//! Secret registry: validation, persistence and read models.
//!
//! The registry never sees a plaintext value: clients send the `st-core` digest, the
//! server stores `HMAC(pepper, digest)`. Neither the digest nor the fingerprint is
//! ever returned, logged or written to the audit log.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use sqlx::{PgConnection, Postgres, QueryBuilder};
use st_core::{Digest, Hints, SecretType, mask, validate_hints};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::audit::{self, AuditEvent};
use crate::crypto::Pepper;
use crate::error::ApiError;
use crate::model::{SecretStatus, SourceType};
use crate::pagination::{self, Cursor, Page};
use crate::policy::Glob;

pub const MAX_ALLOW_RULES: usize = 100;
const MAX_EXPIRY_YEARS: i64 = 10;

// ── API types ─────────────────────────────────────────────────────────────

/// Where a secret is allowed to appear. All set fields must match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AllowRuleIn {
    /// Restrict to one source type; omit for any.
    #[serde(default)]
    pub source_type: Option<SourceType>,
    /// Glob over the source URI (repo URL, `host:<name>`, …). `*` stops at `/`, `**` does not.
    #[schema(example = "git@github.com:acme/infra-secrets.git")]
    pub uri_pattern: String,
    /// Glob over the path inside the source.
    #[serde(default)]
    #[schema(example = "k8s/sealed/**")]
    pub path_pattern: Option<String>,
    #[serde(default)]
    #[schema(example = "prod")]
    pub environment: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct AllowRuleOut {
    pub id: i64,
    pub source_type: Option<SourceType>,
    pub uri_pattern: String,
    pub path_pattern: Option<String>,
    pub environment: Option<String>,
    pub comment: Option<String>,
    #[serde(skip)]
    pub secret_id: Uuid,
}

/// Registration request. `digest` is computed client-side (`secrettrace digest`
/// or the web UI); the plaintext value is never sent.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretCreate {
    #[schema(example = "prod-aws-deploy-key", min_length = 1, max_length = 200)]
    pub name: String,
    #[serde(rename = "type")]
    pub secret_type: SecretType,
    #[schema(example = "platform-team", min_length = 1, max_length = 200)]
    pub owner: String,
    #[serde(default)]
    #[schema(max_length = 2000)]
    pub purpose: Option<String>,
    /// `SHA-256("secrettrace/v1\0" || normalize(value))`, lowercase hex.
    #[schema(value_type = String, pattern = "^[0-9a-f]{64}$")]
    pub digest: Digest,
    #[serde(default)]
    pub hints: Hints,
    #[serde(default)]
    pub allow_rules: Vec<AllowRuleIn>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Partial update. Absent fields are unchanged; `null` clears nullable fields.
/// `allow_rules`, when present, replaces the whole set.
#[allow(clippy::option_option)] // absent vs null vs value
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretUpdate {
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<String>, nullable)]
    pub purpose: Option<Option<String>>,
    #[serde(default)]
    pub status: Option<SecretStatus>,
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<DateTime<Utc>>, nullable)]
    pub expires_at: Option<Option<DateTime<Utc>>>,
    #[serde(default)]
    pub allow_rules: Option<Vec<AllowRuleIn>>,
}

// Tri-state (absent / null / value) is exactly what PATCH semantics need.
#[allow(clippy::option_option)]
fn double_option<'de, T: Deserialize<'de>, D: Deserializer<'de>>(d: D) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(d).map(Some)
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SecretOut {
    pub id: Uuid,
    pub name: String,
    #[serde(rename = "type")]
    pub secret_type: SecretType,
    pub owner: String,
    pub purpose: Option<String>,
    /// Built from stored hints only, e.g. `AKIA…` or `••••••••`.
    #[schema(example = "AKIA…")]
    pub masked: String,
    pub status: SecretStatus,
    /// `true` when `expires_at` has passed (even before the expiry job flips `status`).
    pub is_expired: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub allow_rules: Vec<AllowRuleOut>,
    pub location_count: i64,
    pub violation_count: i64,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SecretFilter {
    pub status: Option<SecretStatus>,
    #[serde(rename = "type")]
    #[param(rename = "type", value_type = Option<SecretType>)]
    pub secret_type: Option<SecretType>,
    pub owner: Option<String>,
    /// Case-insensitive substring of name, owner or purpose.
    pub q: Option<String>,
    pub cursor: Option<String>,
    #[param(minimum = 1, maximum = 200)]
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct LocationOut {
    pub id: Uuid,
    pub secret_id: Uuid,
    pub source_id: Option<Uuid>,
    pub source_type: SourceType,
    pub uri: String,
    /// `{path, line, column, commit, blob, ref, encoding}` — never file contents.
    #[schema(value_type = Object)]
    pub locator: serde_json::Value,
    pub environment: Option<String>,
    pub in_current_state: bool,
    pub is_allowed: bool,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    #[serde(skip)]
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LocationFilter {
    pub is_allowed: Option<bool>,
    pub cursor: Option<String>,
    #[param(minimum = 1, maximum = 200)]
    pub limit: Option<i64>,
}

// ── validation ────────────────────────────────────────────────────────────

fn unprocessable(msg: impl Into<String>) -> ApiError {
    ApiError::Unprocessable(msg.into())
}

fn text(field: &str, value: &str, max_chars: usize) -> Result<String, ApiError> {
    let v = value.trim();
    if v.is_empty() || v.chars().count() > max_chars {
        return Err(unprocessable(format!("{field} must be 1-{max_chars} characters")));
    }
    if v.chars().any(char::is_control) {
        return Err(unprocessable(format!("{field} must not contain control characters")));
    }
    Ok(v.to_owned())
}

fn optional_text(field: &str, value: Option<&str>, max_chars: usize) -> Result<Option<String>, ApiError> {
    value.map(str::trim).filter(|v| !v.is_empty()).map(|v| text(field, v, max_chars)).transpose()
}

fn validate_expiry(expires_at: Option<DateTime<Utc>>) -> Result<(), ApiError> {
    if let Some(t) = expires_at {
        let now = Utc::now();
        if t <= now {
            return Err(unprocessable("expires_at must be in the future"));
        }
        if t > now + Duration::days(366 * MAX_EXPIRY_YEARS) {
            return Err(unprocessable(format!("expires_at must be within {MAX_EXPIRY_YEARS} years")));
        }
    }
    Ok(())
}

fn validate_rules(rules: &[AllowRuleIn]) -> Result<Vec<AllowRuleIn>, ApiError> {
    if rules.len() > MAX_ALLOW_RULES {
        return Err(unprocessable(format!("at most {MAX_ALLOW_RULES} allow rules")));
    }
    let mut out: Vec<AllowRuleIn> = Vec::with_capacity(rules.len());
    for (i, r) in rules.iter().enumerate() {
        let glob = |field: &str, p: &str| {
            Glob::parse(p)
                .map_err(|e| unprocessable(format!("allow_rules[{i}].{field}: {e}")))
                .map(|g| g.as_str().to_owned())
        };
        let env = r.environment.as_deref().map(str::trim).filter(|e| !e.is_empty());
        if let Some(e) = env
            && (e.len() > 64 || !e.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')))
        {
            return Err(unprocessable(format!("allow_rules[{i}].environment must be 1-64 chars of [A-Za-z0-9._-]")));
        }
        let rule = AllowRuleIn {
            source_type: r.source_type,
            uri_pattern: glob("uri_pattern", r.uri_pattern.trim())?,
            path_pattern: r
                .path_pattern
                .as_deref()
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(|p| glob("path_pattern", p))
                .transpose()?,
            environment: env.map(str::to_owned),
            comment: optional_text(&format!("allow_rules[{i}].comment"), r.comment.as_deref(), 500)?,
        };
        let duplicate = out.iter().any(|o| {
            o.source_type == rule.source_type
                && o.uri_pattern == rule.uri_pattern
                && o.path_pattern == rule.path_pattern
                && o.environment == rule.environment
        });
        if duplicate {
            return Err(unprocessable(format!("allow_rules[{i}] duplicates an earlier rule")));
        }
        out.push(rule);
    }
    Ok(out)
}

fn hints_error(e: &st_core::HintsError) -> ApiError {
    unprocessable(format!("hints: {e}"))
}

// ── persistence ───────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct SecretRow {
    id: Uuid,
    name: String,
    #[sqlx(rename = "type")]
    secret_type: SecretType,
    owner: String,
    purpose: Option<String>,
    hint_prefix: Option<String>,
    hint_suffix: Option<String>,
    value_length: Option<i32>,
    expires_at: Option<DateTime<Utc>>,
    status: SecretStatus,
    created_by: Option<Uuid>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    location_count: i64,
    violation_count: i64,
}

const SECRET_SELECT: &str = "SELECT s.id, s.name, s.type, s.owner, s.purpose, s.hint_prefix, s.hint_suffix,
        s.value_length, s.expires_at, s.status, s.created_by, s.created_at, s.updated_at,
        (SELECT count(*) FROM locations l WHERE l.secret_id = s.id) AS location_count,
        (SELECT count(*) FROM locations l WHERE l.secret_id = s.id AND NOT l.is_allowed) AS violation_count
    FROM secrets s";

impl SecretRow {
    fn into_out(self, allow_rules: Vec<AllowRuleOut>) -> SecretOut {
        let hints = Hints {
            prefix: self.hint_prefix,
            suffix: self.hint_suffix,
            length: self.value_length.and_then(|l| u32::try_from(l).ok()),
        };
        SecretOut {
            id: self.id,
            name: self.name,
            secret_type: self.secret_type,
            owner: self.owner,
            purpose: self.purpose,
            masked: mask(&hints),
            status: self.status,
            is_expired: self.expires_at.is_some_and(|t| t <= Utc::now()),
            expires_at: self.expires_at,
            allow_rules,
            location_count: self.location_count,
            violation_count: self.violation_count,
            created_by: self.created_by,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

async fn rules_for(conn: &mut PgConnection, ids: &[Uuid]) -> Result<HashMap<Uuid, Vec<AllowRuleOut>>, sqlx::Error> {
    let rows: Vec<AllowRuleOut> = sqlx::query_as(
        "SELECT id, secret_id, source_type, uri_pattern, path_pattern, environment, comment
         FROM secret_allow_rules WHERE secret_id = ANY($1) ORDER BY id",
    )
    .bind(ids)
    .fetch_all(conn)
    .await?;
    let mut map: HashMap<Uuid, Vec<AllowRuleOut>> = HashMap::new();
    for r in rows {
        map.entry(r.secret_id).or_default().push(r);
    }
    Ok(map)
}

async fn insert_rules(conn: &mut PgConnection, secret_id: Uuid, rules: &[AllowRuleIn]) -> Result<(), sqlx::Error> {
    if rules.is_empty() {
        return Ok(());
    }
    let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(
        "INSERT INTO secret_allow_rules (secret_id, source_type, uri_pattern, path_pattern, environment, comment) ",
    );
    qb.push_values(rules, |mut b, r| {
        b.push_bind(secret_id)
            .push_bind(r.source_type)
            .push_bind(&r.uri_pattern)
            .push_bind(&r.path_pattern)
            .push_bind(&r.environment)
            .push_bind(&r.comment);
    });
    qb.build().execute(conn).await?;
    Ok(())
}

pub async fn get(conn: &mut PgConnection, id: Uuid) -> Result<Option<SecretOut>, sqlx::Error> {
    let row: Option<SecretRow> =
        sqlx::query_as(&format!("{SECRET_SELECT} WHERE s.id = $1")).bind(id).fetch_optional(&mut *conn).await?;
    let Some(row) = row else { return Ok(None) };
    let mut rules = rules_for(conn, &[id]).await?;
    Ok(Some(row.into_out(rules.remove(&id).unwrap_or_default())))
}

pub async fn list(conn: &mut PgConnection, f: &SecretFilter) -> Result<Page<SecretOut>, ApiError> {
    let limit = pagination::limit(f.limit)?;
    let cursor = f.cursor.as_deref().map(Cursor::decode).transpose()?;

    let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(SECRET_SELECT);
    qb.push(" WHERE true");
    if let Some(s) = f.status {
        qb.push(" AND s.status = ").push_bind(s);
    }
    if let Some(t) = f.secret_type {
        qb.push(" AND s.type = ").push_bind(t);
    }
    if let Some(o) = f.owner.as_deref().filter(|o| !o.is_empty()) {
        qb.push(" AND s.owner = ").push_bind(o.to_owned());
    }
    if let Some(q) = f.q.as_deref().map(str::trim).filter(|q| !q.is_empty()) {
        if q.chars().count() > 200 {
            return Err(ApiError::BadRequest("q must be at most 200 characters".into()));
        }
        let like = format!("%{}%", q.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"));
        qb.push(" AND (s.name ILIKE ").push_bind(like.clone());
        qb.push(" OR s.owner ILIKE ").push_bind(like.clone());
        qb.push(" OR s.purpose ILIKE ").push_bind(like).push(")");
    }
    if let Some(c) = cursor {
        qb.push(" AND (s.created_at, s.id) < (").push_bind(c.created_at).push(", ").push_bind(c.id).push(")");
    }
    qb.push(" ORDER BY s.created_at DESC, s.id DESC LIMIT ").push_bind(limit + 1);

    let mut rows: Vec<SecretRow> = qb.build_query_as().fetch_all(&mut *conn).await?;
    let next_cursor = if rows.len() > usize::try_from(limit).unwrap_or(usize::MAX) {
        rows.pop();
        rows.last().map(|r| Cursor { created_at: r.created_at, id: r.id }.encode())
    } else {
        None
    };
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let mut rules = rules_for(conn, &ids).await?;
    let items = rows
        .into_iter()
        .map(|r| {
            let id = r.id;
            r.into_out(rules.remove(&id).unwrap_or_default())
        })
        .collect();
    Ok(Page { items, next_cursor })
}

pub async fn list_locations(
    conn: &mut PgConnection,
    secret_id: Uuid,
    f: &LocationFilter,
) -> Result<Page<LocationOut>, ApiError> {
    let limit = pagination::limit(f.limit)?;
    let cursor = f.cursor.as_deref().map(Cursor::decode).transpose()?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM secrets WHERE id = $1)")
        .bind(secret_id)
        .fetch_one(&mut *conn)
        .await?;
    if !exists {
        return Err(ApiError::NotFound);
    }
    // Locations are ordered by first_seen; the cursor reuses the (timestamp, id) shape.
    let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(
        "SELECT id, secret_id, source_id, source_type, uri, locator, environment, in_current_state, is_allowed,
                first_seen, last_seen, first_seen AS created_at
         FROM locations WHERE secret_id = ",
    );
    qb.push_bind(secret_id);
    if let Some(a) = f.is_allowed {
        qb.push(" AND is_allowed = ").push_bind(a);
    }
    if let Some(c) = cursor {
        qb.push(" AND (first_seen, id) < (").push_bind(c.created_at).push(", ").push_bind(c.id).push(")");
    }
    qb.push(" ORDER BY first_seen DESC, id DESC LIMIT ").push_bind(limit + 1);
    let mut items: Vec<LocationOut> = qb.build_query_as().fetch_all(&mut *conn).await?;
    let next_cursor = if items.len() > usize::try_from(limit).unwrap_or(usize::MAX) {
        items.pop();
        items.last().map(|l| Cursor { created_at: l.created_at, id: l.id }.encode())
    } else {
        None
    };
    Ok(Page { items, next_cursor })
}

/// Register a secret. Runs inside the caller's transaction together with its audit record.
pub async fn create(
    conn: &mut sqlx::Transaction<'_, Postgres>,
    pepper: &Pepper,
    req: &SecretCreate,
    created_by: Uuid,
    audit_event: AuditEvent,
) -> Result<SecretOut, ApiError> {
    let name = text("name", &req.name, 200)?;
    let owner = text("owner", &req.owner, 200)?;
    let purpose = optional_text("purpose", req.purpose.as_deref(), 2000)?;
    validate_hints(req.secret_type, &req.hints).map_err(|e| hints_error(&e))?;
    validate_expiry(req.expires_at)?;
    let rules = validate_rules(&req.allow_rules)?;

    // The same value may already be registered under an older pepper version.
    let (versions, fingerprints): (Vec<i16>, Vec<Vec<u8>>) = pepper
        .fingerprint_all(&req.digest)
        .into_iter()
        .map(|(v, fp)| (i16::try_from(v).unwrap_or(i16::MAX), fp.as_bytes().to_vec()))
        .unzip();
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM secrets
         WHERE (pepper_version, fingerprint) IN (SELECT * FROM UNNEST($1::smallint[], $2::bytea[])) LIMIT 1",
    )
    .bind(&versions)
    .bind(&fingerprints)
    .fetch_optional(&mut **conn)
    .await?;
    if let Some(id) = existing {
        return Err(ApiError::Conflict(format!("this secret value is already registered (secret {id})")));
    }

    let (version, fingerprint) = pepper.fingerprint_current(&req.digest);
    let inserted = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO secrets (name, type, owner, purpose, fingerprint, pepper_version, hint_prefix, hint_suffix,
                              value_length, expires_at, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id",
    )
    .bind(&name)
    .bind(req.secret_type)
    .bind(&owner)
    .bind(&purpose)
    .bind(fingerprint.as_bytes().as_slice())
    .bind(i16::try_from(version).unwrap_or(i16::MAX))
    .bind(&req.hints.prefix)
    .bind(&req.hints.suffix)
    .bind(req.hints.length.and_then(|l| i32::try_from(l).ok()))
    .bind(req.expires_at)
    .bind(created_by)
    .fetch_one(&mut **conn)
    .await;
    let id = match inserted {
        Ok(id) => id,
        Err(e) => return Err(map_unique(e)),
    };
    insert_rules(conn, id, &rules).await?;

    let out = get(conn, id).await?.ok_or_else(|| anyhow::anyhow!("secret vanished after insert"))?;
    let event = audit_event.target("secret", id.to_string()).details(json!({
        "name": out.name,
        "type": out.secret_type,
        "owner": out.owner,
        "masked": out.masked,
        "pepper_version": version,
        "allow_rules": rules.len(),
        "expires_at": out.expires_at,
    }));
    audit::record(conn, &event).await?;
    Ok(out)
}

#[derive(sqlx::FromRow)]
struct CurrentSecret {
    owner: String,
    purpose: Option<String>,
    status: SecretStatus,
    expires_at: Option<DateTime<Utc>>,
}

/// Apply a partial update. Terminal statuses (`revoked`, `rotated`) cannot be left.
pub async fn update(
    conn: &mut sqlx::Transaction<'_, Postgres>,
    id: Uuid,
    req: &SecretUpdate,
    audit_event: AuditEvent,
) -> Result<SecretOut, ApiError> {
    let no_changes = req.owner.is_none()
        && req.purpose.is_none()
        && req.status.is_none()
        && req.expires_at.is_none()
        && req.allow_rules.is_none();
    if no_changes {
        return Err(unprocessable("no fields to update"));
    }

    let cur: CurrentSecret =
        sqlx::query_as("SELECT owner, purpose, status, expires_at FROM secrets WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut **conn)
            .await?
            .ok_or(ApiError::NotFound)?;

    let owner = req.owner.as_deref().map(|o| text("owner", o, 200)).transpose()?.unwrap_or(cur.owner.clone());
    let purpose = match &req.purpose {
        Some(p) => optional_text("purpose", p.as_deref(), 2000)?,
        None => cur.purpose.clone(),
    };
    let expires_at = match req.expires_at {
        Some(e) => {
            validate_expiry(e)?;
            e
        }
        None => cur.expires_at,
    };
    let status = req.status.unwrap_or(cur.status);
    if cur.status.is_terminal() && status != cur.status {
        return Err(ApiError::Conflict(format!(
            "secret is {}; register the new value as a new secret",
            cur.status.as_str()
        )));
    }
    if status == SecretStatus::Active && expires_at.is_some_and(|t| t <= Utc::now()) {
        return Err(unprocessable("cannot set status active while expires_at is in the past"));
    }
    let rules = req.allow_rules.as_deref().map(validate_rules).transpose()?;

    sqlx::query(
        "UPDATE secrets SET owner = $2, purpose = $3, status = $4, expires_at = $5, updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(&owner)
    .bind(&purpose)
    .bind(status)
    .bind(expires_at)
    .execute(&mut **conn)
    .await?;
    if let Some(rules) = &rules {
        sqlx::query("DELETE FROM secret_allow_rules WHERE secret_id = $1").bind(id).execute(&mut **conn).await?;
        insert_rules(conn, id, rules).await?;
        // Deleting the old rules nulled `allow_rule_id` but left `is_allowed` stale.
        crate::policy::reevaluate(conn, id).await?;
    }

    let mut changed = Vec::new();
    if owner != cur.owner {
        changed.push("owner");
    }
    if purpose != cur.purpose {
        changed.push("purpose");
    }
    if expires_at != cur.expires_at {
        changed.push("expires_at");
    }
    if rules.is_some() {
        changed.push("allow_rules");
    }
    let mut details = json!({ "changed": changed });
    if status != cur.status {
        details["status"] = json!({ "from": cur.status, "to": status });
    }
    let action = match status {
        s if s == cur.status => "secret.update",
        SecretStatus::Revoked => "secret.revoke",
        SecretStatus::Rotated => "secret.rotate",
        _ => "secret.status_change",
    };
    let mut event = audit_event.target("secret", id.to_string()).details(details);
    action.clone_into(&mut event.action);
    audit::record(conn, &event).await?;

    get(conn, id).await?.ok_or(ApiError::NotFound)
}

fn map_unique(e: sqlx::Error) -> ApiError {
    let constraint = e.as_database_error().and_then(|d| d.constraint()).map(str::to_owned);
    match constraint.as_deref() {
        Some("secrets_name_key") => ApiError::Conflict("a secret with this name already exists".into()),
        Some("secrets_fingerprint_uniq") => ApiError::Conflict("this secret value is already registered".into()),
        _ => ApiError::Database(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(uri: &str) -> AllowRuleIn {
        AllowRuleIn { source_type: None, uri_pattern: uri.into(), path_pattern: None, environment: None, comment: None }
    }

    #[test]
    fn rules_are_normalized_and_validated() {
        let mut r = rule("  git@github.com:acme/*  ");
        r.path_pattern = Some("   ".into());
        r.environment = Some(" prod ".into());
        let out = validate_rules(&[r]).unwrap_or_default();
        assert_eq!(out[0].uri_pattern, "git@github.com:acme/*");
        assert_eq!(out[0].path_pattern, None);
        assert_eq!(out[0].environment.as_deref(), Some("prod"));

        assert!(validate_rules(&[rule("")]).is_err());
        assert!(validate_rules(&[rule("bad\\")]).is_err());
        assert!(validate_rules(&[rule("a"), rule("a")]).is_err(), "duplicates");
        let mut bad_env = rule("a");
        bad_env.environment = Some("prod env".into());
        assert!(validate_rules(&[bad_env]).is_err());
        assert!(validate_rules(&vec![rule("x"); MAX_ALLOW_RULES + 1]).is_err());
    }

    #[test]
    fn text_fields() {
        assert_eq!(text("name", "  ok  ", 10).ok().as_deref(), Some("ok"));
        assert!(text("name", "   ", 10).is_err());
        assert!(text("name", "a\u{7}b", 10).is_err());
        assert!(text("name", &"x".repeat(11), 10).is_err());
        assert_eq!(optional_text("p", Some("  "), 10).ok(), Some(None));
    }

    #[test]
    fn update_distinguishes_absent_and_null() {
        let absent: SecretUpdate = serde_json::from_str(r#"{"owner":"x"}"#).unwrap_or_default();
        assert_eq!(absent.expires_at, None);
        let null: SecretUpdate = serde_json::from_str(r#"{"expires_at":null}"#).unwrap_or_default();
        assert_eq!(null.expires_at, Some(None));
        assert!(serde_json::from_str::<SecretUpdate>(r#"{"fingerprint":"x"}"#).is_err());
    }
}
