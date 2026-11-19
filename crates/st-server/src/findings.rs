//! Read models across the registry: every location of every secret (the "findings"
//! list of the UI) and the dashboard overview. Only masked data leaves this module.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Postgres, QueryBuilder, Row as _};
use st_core::{Hints, SecretType, mask};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::error::ApiError;
use crate::model::{SecretStatus, SourceType};
use crate::pagination::{self, Cursor, Page};
use crate::sources::{self, ScanFilter, ScanOut};

const MAX_QUERY_CHARS: usize = 200;
const TREND_DAYS: i32 = 30;
const EXPIRY_WARNING_DAYS: i32 = 30;

/// The secret a finding belongs to, as the UI shows it.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SecretRef {
    pub id: Uuid,
    pub name: String,
    #[serde(rename = "type")]
    pub secret_type: SecretType,
    pub status: SecretStatus,
    /// Built from stored hints only.
    pub masked: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct FindingOut {
    pub id: Uuid,
    pub secret: SecretRef,
    pub source_id: Option<Uuid>,
    pub source_name: Option<String>,
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
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct FindingFilter {
    /// `false`: violations only; `true`: allowed locations only.
    pub is_allowed: Option<bool>,
    /// `true`: still present in the last full scan; `false`: only in history.
    pub in_current_state: Option<bool>,
    pub secret_id: Option<Uuid>,
    pub source_id: Option<Uuid>,
    pub environment: Option<String>,
    /// Case-insensitive substring of the URI or the path.
    pub q: Option<String>,
    pub cursor: Option<String>,
    #[param(minimum = 1, maximum = 200)]
    pub limit: Option<i64>,
}

const FINDING_SELECT: &str = "SELECT l.id, l.source_id, src.name AS source_name, l.source_type, l.uri, l.locator,
        l.environment, l.in_current_state, l.is_allowed, l.first_seen, l.last_seen,
        s.id AS secret_id, s.name AS secret_name, s.type AS secret_type, s.status AS secret_status,
        s.hint_prefix, s.hint_suffix, s.value_length
    FROM locations l
    JOIN secrets s ON s.id = l.secret_id
    LEFT JOIN sources src ON src.id = l.source_id";

fn masked_from_row(row: &sqlx::postgres::PgRow) -> Result<String, sqlx::Error> {
    let length: Option<i32> = row.try_get("value_length")?;
    let hints = Hints {
        prefix: row.try_get("hint_prefix")?,
        suffix: row.try_get("hint_suffix")?,
        length: length.and_then(|l| u32::try_from(l).ok()),
    };
    Ok(mask(&hints))
}

fn finding_from_row(row: &sqlx::postgres::PgRow) -> Result<FindingOut, sqlx::Error> {
    Ok(FindingOut {
        id: row.try_get("id")?,
        secret: SecretRef {
            id: row.try_get("secret_id")?,
            name: row.try_get("secret_name")?,
            secret_type: row.try_get("secret_type")?,
            status: row.try_get("secret_status")?,
            masked: masked_from_row(row)?,
        },
        source_id: row.try_get("source_id")?,
        source_name: row.try_get("source_name")?,
        source_type: row.try_get("source_type")?,
        uri: row.try_get("uri")?,
        locator: row.try_get("locator")?,
        environment: row.try_get("environment")?,
        in_current_state: row.try_get("in_current_state")?,
        is_allowed: row.try_get("is_allowed")?,
        first_seen: row.try_get("first_seen")?,
        last_seen: row.try_get("last_seen")?,
    })
}

/// `%q%` for `ILIKE … ESCAPE '\'` with the wildcards of `q` escaped.
pub(crate) fn like_pattern(q: &str) -> Result<Option<String>, ApiError> {
    let q = q.trim();
    if q.is_empty() {
        return Ok(None);
    }
    if q.chars().count() > MAX_QUERY_CHARS || q.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!("q must be at most {MAX_QUERY_CHARS} printable characters")));
    }
    Ok(Some(format!("%{}%", q.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"))))
}

pub async fn list(conn: &mut PgConnection, f: &FindingFilter) -> Result<Page<FindingOut>, ApiError> {
    let limit = pagination::limit(f.limit)?;
    let cursor = f.cursor.as_deref().map(Cursor::decode).transpose()?;
    let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(FINDING_SELECT);
    qb.push(" WHERE true");
    if let Some(a) = f.is_allowed {
        qb.push(" AND l.is_allowed = ").push_bind(a);
    }
    if let Some(c) = f.in_current_state {
        qb.push(" AND l.in_current_state = ").push_bind(c);
    }
    if let Some(id) = f.secret_id {
        qb.push(" AND l.secret_id = ").push_bind(id);
    }
    if let Some(id) = f.source_id {
        qb.push(" AND l.source_id = ").push_bind(id);
    }
    if let Some(env) = f.environment.as_deref().map(str::trim).filter(|e| !e.is_empty()) {
        if env.chars().count() > 64 {
            return Err(ApiError::BadRequest("environment must be at most 64 characters".into()));
        }
        qb.push(" AND l.environment = ").push_bind(env.to_owned());
    }
    if let Some(like) = f.q.as_deref().map(like_pattern).transpose()?.flatten() {
        qb.push(" AND (l.uri ILIKE ").push_bind(like.clone());
        qb.push(" OR l.locator->>'path' ILIKE ").push_bind(like.clone());
        qb.push(" OR s.name ILIKE ").push_bind(like).push(")");
    }
    if let Some(c) = cursor {
        qb.push(" AND (l.first_seen, l.id) < (").push_bind(c.created_at).push(", ").push_bind(c.id).push(")");
    }
    qb.push(" ORDER BY l.first_seen DESC, l.id DESC LIMIT ").push_bind(limit + 1);
    let rows = qb.build().fetch_all(conn).await?;
    let mut items = rows.iter().map(finding_from_row).collect::<Result<Vec<_>, _>>()?;
    let next_cursor = if items.len() > usize::try_from(limit).unwrap_or(usize::MAX) {
        items.pop();
        items.last().map(|l| Cursor { created_at: l.first_seen, id: l.id }.encode())
    } else {
        None
    };
    Ok(Page { items, next_cursor })
}

// ── overview ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SecretCounts {
    pub total: i64,
    pub active: i64,
    pub expired: i64,
    pub revoked: i64,
    pub rotated: i64,
    /// Active secrets whose `expires_at` is within the next 30 days.
    pub expiring_soon: i64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct LocationCounts {
    pub total: i64,
    /// Not allowed and still present in the current state of the source.
    pub open_violations: i64,
    /// Not allowed, seen only in history (still a leak: history is readable).
    pub historical_violations: i64,
    pub allowed: i64,
    /// Secrets with at least one violation.
    pub exposed_secrets: i64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SourceCounts {
    pub total: i64,
    pub enabled: i64,
    pub scheduled: i64,
}

#[derive(Debug, Clone, Default, Serialize, ToSchema)]
pub struct ScanCounts {
    pub queued: i64,
    pub running: i64,
    pub succeeded: i64,
    pub failed: i64,
    pub cancelled: i64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DayCount {
    #[schema(value_type = String, format = Date)]
    pub day: NaiveDate,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ExposedSecret {
    pub secret: SecretRef,
    pub violations: i64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ExpiringSecret {
    pub secret: SecretRef,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Overview {
    pub secrets: SecretCounts,
    pub locations: LocationCounts,
    pub sources: SourceCounts,
    /// Scans created in the last 24 hours, by status.
    pub scans_24h: ScanCounts,
    /// New violations per day (UTC, by first sighting), oldest first, last 30 days.
    pub violations_by_day: Vec<DayCount>,
    /// Secrets with the most violations (up to 5).
    pub top_exposed: Vec<ExposedSecret>,
    /// Active secrets expiring soonest within 30 days (up to 5).
    pub expiring: Vec<ExpiringSecret>,
    /// Newest violations (up to 8).
    pub recent_violations: Vec<FindingOut>,
    /// Newest scans (up to 6).
    pub recent_scans: Vec<ScanOut>,
}

fn secret_ref(row: &sqlx::postgres::PgRow) -> Result<SecretRef, sqlx::Error> {
    Ok(SecretRef {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        secret_type: row.try_get("type")?,
        status: row.try_get("status")?,
        masked: masked_from_row(row)?,
    })
}

async fn counts(conn: &mut PgConnection) -> Result<(SecretCounts, LocationCounts, SourceCounts), sqlx::Error> {
    let r = sqlx::query(
        "SELECT count(*) AS total,
                count(*) FILTER (WHERE status = 'active') AS active,
                count(*) FILTER (WHERE status = 'expired') AS expired,
                count(*) FILTER (WHERE status = 'revoked') AS revoked,
                count(*) FILTER (WHERE status = 'rotated') AS rotated,
                count(*) FILTER (WHERE status = 'active' AND expires_at > now()
                                  AND expires_at <= now() + make_interval(days => $1)) AS expiring_soon
         FROM secrets",
    )
    .bind(EXPIRY_WARNING_DAYS)
    .fetch_one(&mut *conn)
    .await?;
    let secrets = SecretCounts {
        total: r.try_get("total")?,
        active: r.try_get("active")?,
        expired: r.try_get("expired")?,
        revoked: r.try_get("revoked")?,
        rotated: r.try_get("rotated")?,
        expiring_soon: r.try_get("expiring_soon")?,
    };

    let r = sqlx::query(
        "SELECT count(*) AS total,
                count(*) FILTER (WHERE NOT is_allowed AND in_current_state) AS open_violations,
                count(*) FILTER (WHERE NOT is_allowed AND NOT in_current_state) AS historical_violations,
                count(*) FILTER (WHERE is_allowed) AS allowed,
                count(DISTINCT secret_id) FILTER (WHERE NOT is_allowed) AS exposed_secrets
         FROM locations",
    )
    .fetch_one(&mut *conn)
    .await?;
    let locations = LocationCounts {
        total: r.try_get("total")?,
        open_violations: r.try_get("open_violations")?,
        historical_violations: r.try_get("historical_violations")?,
        allowed: r.try_get("allowed")?,
        exposed_secrets: r.try_get("exposed_secrets")?,
    };

    let r = sqlx::query(
        "SELECT count(*) AS total, count(*) FILTER (WHERE enabled) AS enabled,
                count(*) FILTER (WHERE enabled AND schedule_cron IS NOT NULL) AS scheduled
         FROM sources",
    )
    .fetch_one(&mut *conn)
    .await?;
    let sources_counts =
        SourceCounts { total: r.try_get("total")?, enabled: r.try_get("enabled")?, scheduled: r.try_get("scheduled")? };

    Ok((secrets, locations, sources_counts))
}

async fn trend(conn: &mut PgConnection) -> Result<Vec<DayCount>, sqlx::Error> {
    let rows = sqlx::query(
        "WITH days AS (
             SELECT generate_series((now() AT TIME ZONE 'UTC')::date - ($1 - 1),
                                    (now() AT TIME ZONE 'UTC')::date, interval '1 day')::date AS day)
         SELECT d.day, count(l.id) AS n
         FROM days d
         LEFT JOIN locations l ON NOT l.is_allowed AND (l.first_seen AT TIME ZONE 'UTC')::date = d.day
         GROUP BY d.day ORDER BY d.day",
    )
    .bind(TREND_DAYS)
    .fetch_all(&mut *conn)
    .await?;
    rows.iter().map(|r| Ok(DayCount { day: r.try_get("day")?, count: r.try_get("n")? })).collect()
}

pub async fn overview(conn: &mut PgConnection) -> Result<Overview, ApiError> {
    let (secrets, locations, sources_counts) = counts(conn).await?;
    let rows = sqlx::query(
        "SELECT status::text AS status, count(*) AS n FROM scan_jobs
         WHERE created_at > now() - interval '24 hours' GROUP BY status",
    )
    .fetch_all(&mut *conn)
    .await?;
    let mut scans_24h = ScanCounts::default();
    for row in &rows {
        let n: i64 = row.try_get("n")?;
        match row.try_get::<String, _>("status")?.as_str() {
            "queued" => scans_24h.queued = n,
            "running" => scans_24h.running = n,
            "succeeded" => scans_24h.succeeded = n,
            "failed" => scans_24h.failed = n,
            "cancelled" => scans_24h.cancelled = n,
            _ => {}
        }
    }

    let violations_by_day = trend(conn).await?;

    let rows = sqlx::query(
        "SELECT s.id, s.name, s.type, s.status, s.hint_prefix, s.hint_suffix, s.value_length,
                count(*) AS violations
         FROM secrets s JOIN locations l ON l.secret_id = s.id AND NOT l.is_allowed
         GROUP BY s.id ORDER BY violations DESC, s.name LIMIT 5",
    )
    .fetch_all(&mut *conn)
    .await?;
    let top_exposed = rows
        .iter()
        .map(|r| Ok(ExposedSecret { secret: secret_ref(r)?, violations: r.try_get("violations")? }))
        .collect::<Result<Vec<_>, sqlx::Error>>()?;

    let rows = sqlx::query(
        "SELECT id, name, type, status, hint_prefix, hint_suffix, value_length, expires_at
         FROM secrets
         WHERE status = 'active' AND expires_at > now() AND expires_at <= now() + make_interval(days => $1)
         ORDER BY expires_at, name LIMIT 5",
    )
    .bind(EXPIRY_WARNING_DAYS)
    .fetch_all(&mut *conn)
    .await?;
    let expiring = rows
        .iter()
        .map(|r| Ok(ExpiringSecret { secret: secret_ref(r)?, expires_at: r.try_get("expires_at")? }))
        .collect::<Result<Vec<_>, sqlx::Error>>()?;

    let recent_violations =
        list(conn, &FindingFilter { is_allowed: Some(false), limit: Some(8), ..FindingFilter::default() }).await?.items;
    let recent_scans = sources::list_scans(conn, &ScanFilter { limit: Some(6), ..ScanFilter::default() }).await?.items;

    Ok(Overview {
        secrets,
        locations,
        sources: sources_counts,
        scans_24h,
        violations_by_day,
        top_exposed,
        expiring,
        recent_violations,
        recent_scans,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn like_pattern_escapes_wildcards() {
        assert_eq!(like_pattern("  ").ok().flatten(), None);
        assert_eq!(like_pattern("a_b%c\\").ok().flatten().as_deref(), Some("%a\\_b\\%c\\\\%"));
        assert!(like_pattern(&"x".repeat(201)).is_err());
        assert!(like_pattern("a\u{0}b").is_err());
    }
}
