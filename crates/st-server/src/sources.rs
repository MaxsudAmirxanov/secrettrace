//! Sources managed through the API and their scan jobs.
//!
//! A source is something the system scans (a git repository, …). Sources reported by
//! agents and CI are auto-created by ingest; operators create and configure them here:
//! schedule (cron, UTC), credential by reference (`credential_ref` names a file the worker
//! reads; the value never passes through the API or the database) and environment.
//! `type` and `uri` are immutable: a different repository is a different source.
//!
//! Server-side scans (manual or scheduled) are worker jobs: at most one is queued or
//! running per source (unique index `scan_jobs_worker_active_uniq`).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use sqlx::{PgConnection, Postgres, QueryBuilder, Row as _, Transaction};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::audit::{self, AuditEvent};
use crate::error::ApiError;
use crate::ingest::{validate_environment, validate_uri};
use crate::model::SourceType;
use crate::pagination::{self, Cursor, Page};
use crate::schedule::Schedule;

pub const MAX_NAME_CHARS: usize = 200;
pub const MAX_BLOB_BYTES_LIMIT: u64 = 64 * 1024 * 1024;
const MAX_USERNAME_LEN: usize = 64;

/// Triggers of worker jobs (server-side scans); `ci` and `agent` scans come through ingest.
const WORKER_TRIGGERS: &str = "('manual', 'schedule')";

// ── API types ─────────────────────────────────────────────────────────────

/// Per-source scan settings. Never holds credentials.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceConfig {
    /// User name for HTTPS (with the token from `credential_ref`) or for `ssh://` URIs
    /// without one. Default for HTTPS: `x-access-token`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(
        example = "x-access-token",
        min_length = 1,
        max_length = 64,
        pattern = "^[A-Za-z0-9._@][A-Za-z0-9._@-]*$"
    )]
    pub username: Option<String>,
    /// Skip blobs larger than this (default: the worker's limit, 16 MiB).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(minimum = 1, maximum = 67_108_864)]
    pub max_blob_bytes: Option<u64>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceCreate {
    #[schema(example = "infra-app", min_length = 1, max_length = 200)]
    pub name: String,
    #[serde(rename = "type")]
    pub source_type: SourceType,
    /// Repository URL without credentials: `https://host/org/repo.git`, `ssh://host/org/repo.git`
    /// or `git@host:org/repo.git`.
    #[schema(example = "https://git.example/infra/app.git", max_length = 2048)]
    pub uri: String,
    #[serde(default)]
    #[schema(example = "prod")]
    pub environment: Option<String>,
    /// Name of a credential file in the worker's credentials directory (never a value).
    #[serde(default)]
    #[schema(example = "github_infra", pattern = "^[A-Za-z0-9_-]{1,64}$")]
    pub credential_ref: Option<String>,
    /// 5-field cron expression in UTC, at most every 5 minutes; `git_repo` only.
    #[serde(default)]
    #[schema(example = "0 3 * * *")]
    pub schedule: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub config: Option<SourceConfig>,
}

const fn default_true() -> bool {
    true
}

/// Partial update. Absent fields are unchanged; `null` clears nullable fields;
/// `config`, when present, replaces the whole object. `type` and `uri` cannot change.
#[allow(clippy::option_option)] // absent vs null vs value
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceUpdate {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<String>, nullable)]
    pub environment: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<String>, nullable)]
    pub credential_ref: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<String>, nullable)]
    pub schedule: Option<Option<String>>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub config: Option<SourceConfig>,
    /// Accepted only to answer with a clear error: immutable.
    #[serde(default, rename = "type")]
    #[schema(ignore)]
    pub source_type: Option<Value>,
    #[serde(default)]
    #[schema(ignore)]
    pub uri: Option<Value>,
}

#[allow(clippy::option_option)]
fn double_option<'de, T: Deserialize<'de>, D: Deserializer<'de>>(d: D) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(d).map(Some)
}

/// The queued or running server-side scan of a source.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ActiveScan {
    pub id: Uuid,
    pub status: JobStatus,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SourceOut {
    pub id: Uuid,
    pub name: String,
    #[serde(rename = "type")]
    pub source_type: SourceType,
    pub uri: String,
    pub environment: Option<String>,
    pub credential_ref: Option<String>,
    /// Normalized cron expression (UTC).
    pub schedule: Option<String>,
    pub enabled: bool,
    #[schema(value_type = SourceConfig)]
    pub config: Value,
    pub created_at: DateTime<Utc>,
    pub last_scan_at: Option<DateTime<Utc>>,
    pub next_scan_at: Option<DateTime<Utc>>,
    /// The queued or running server-side (manual/scheduled) scan, if any.
    pub active_scan: Option<ActiveScan>,
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SourceFilter {
    #[serde(rename = "type")]
    #[param(rename = "type", value_type = Option<SourceType>)]
    pub source_type: Option<SourceType>,
    pub enabled: Option<bool>,
    pub cursor: Option<String>,
    #[param(minimum = 1, maximum = 200)]
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, ToSchema)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "job_status", rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

/// What started a scan: a user (`manual`), the scheduler, or an API token (`ci`, `agent`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScanTrigger {
    Manual,
    Schedule,
    Ci,
    Agent,
}

impl ScanTrigger {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Schedule => "schedule",
            Self::Ci => "ci",
            Self::Agent => "agent",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "manual" => Self::Manual,
            "schedule" => Self::Schedule,
            "ci" => Self::Ci,
            "agent" => Self::Agent,
            _ => return None,
        })
    }

    const fn is_worker(self) -> bool {
        matches!(self, Self::Manual | Self::Schedule)
    }
}

/// Body of `POST /sources/{id}/scans` (optional).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanRequest {
    /// Scan the whole history, ignoring what earlier scans covered.
    #[serde(default)]
    pub full: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ScanOut {
    pub id: Uuid,
    pub source_id: Option<Uuid>,
    pub trigger: ScanTrigger,
    pub status: JobStatus,
    /// Whole history (`true`) or only what is new since the last scan.
    pub full_scan: bool,
    pub attempts: i32,
    pub requested_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    /// Not claimed before this time (retry backoff).
    pub run_after: DateTime<Utc>,
    /// Counters only (documents, candidates, matched, violations, …).
    #[schema(value_type = Object)]
    pub stats: Value,
    /// Failure or cancellation reason; never file contents.
    pub error: Option<String>,
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ScanFilter {
    pub source_id: Option<Uuid>,
    #[param(value_type = Option<JobStatus>)]
    pub status: Option<JobStatus>,
    #[param(value_type = Option<ScanTrigger>)]
    pub trigger: Option<ScanTrigger>,
    pub cursor: Option<String>,
    #[param(minimum = 1, maximum = 200)]
    pub limit: Option<i64>,
}

// ── validation ────────────────────────────────────────────────────────────

fn unprocessable(msg: impl Into<String>) -> ApiError {
    ApiError::Unprocessable(msg.into())
}

fn validate_name(name: &str) -> Result<String, ApiError> {
    let v = name.trim();
    if v.is_empty() || v.chars().count() > MAX_NAME_CHARS {
        return Err(unprocessable(format!("name must be 1-{MAX_NAME_CHARS} characters")));
    }
    if v.chars().any(char::is_control) {
        return Err(unprocessable("name must not contain control characters"));
    }
    Ok(v.to_owned())
}

fn validate_credential_ref(r: Option<&str>) -> Result<Option<String>, ApiError> {
    match r {
        None => Ok(None),
        Some(r)
            if (1..=64).contains(&r.len())
                && r.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')) =>
        {
            Ok(Some(r.to_owned()))
        }
        Some(_) => Err(unprocessable("credential_ref must be 1-64 chars of [A-Za-z0-9_-]")),
    }
}

fn validate_config(c: &SourceConfig) -> Result<Value, ApiError> {
    if let Some(u) = &c.username {
        let ok = (1..=MAX_USERNAME_LEN).contains(&u.len())
            && !u.starts_with('-')
            && u.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'@' | b'-'));
        if !ok {
            return Err(unprocessable("config.username must be 1-64 chars of [A-Za-z0-9._@-], not starting with '-'"));
        }
    }
    if c.max_blob_bytes.is_some_and(|n| n == 0 || n > MAX_BLOB_BYTES_LIMIT) {
        return Err(unprocessable(format!("config.max_blob_bytes must be 1-{MAX_BLOB_BYTES_LIMIT}")));
    }
    serde_json::to_value(c).map_err(|e| ApiError::Internal(e.into()))
}

/// Parse a schedule; only git repositories are scanned by the server.
fn validate_schedule(s: Option<&str>, source_type: SourceType) -> Result<Option<Schedule>, ApiError> {
    let Some(s) = s else { return Ok(None) };
    let schedule = Schedule::parse(s).map_err(|e| unprocessable(format!("schedule: {e}")))?;
    if source_type != SourceType::GitRepo {
        return Err(unprocessable("only git_repo sources can be scheduled"));
    }
    Ok(Some(schedule))
}

/// When the scheduler should next enqueue a scan.
fn next_scan_at(schedule: Option<&Schedule>, enabled: bool) -> Option<DateTime<Utc>> {
    schedule.filter(|_| enabled).and_then(|s| s.next_after(Utc::now()))
}

// ── persistence ───────────────────────────────────────────────────────────

const SOURCE_SELECT: &str = "SELECT s.id, s.name, s.type, s.uri, s.environment, s.credential_ref, s.schedule_cron,
        s.enabled, s.config, s.created_at, s.last_scan_at, s.next_scan_at,
        a.id AS active_id, a.status AS active_status
    FROM sources s
    LEFT JOIN LATERAL (
        SELECT j.id, j.status FROM scan_jobs j
        WHERE j.source_id = s.id AND j.status IN ('queued', 'running') AND j.trigger IN ('manual', 'schedule')
        ORDER BY j.created_at DESC LIMIT 1
    ) a ON true";

fn source_from_row(row: &sqlx::postgres::PgRow) -> Result<SourceOut, sqlx::Error> {
    let active_id: Option<Uuid> = row.try_get("active_id")?;
    let active_status: Option<JobStatus> = row.try_get("active_status")?;
    Ok(SourceOut {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        source_type: row.try_get("type")?,
        uri: row.try_get("uri")?,
        environment: row.try_get("environment")?,
        credential_ref: row.try_get("credential_ref")?,
        schedule: row.try_get("schedule_cron")?,
        enabled: row.try_get("enabled")?,
        config: row.try_get("config")?,
        created_at: row.try_get("created_at")?,
        last_scan_at: row.try_get("last_scan_at")?,
        next_scan_at: row.try_get("next_scan_at")?,
        active_scan: active_id.zip(active_status).map(|(id, status)| ActiveScan { id, status }),
    })
}

pub async fn get(conn: &mut PgConnection, id: Uuid) -> Result<Option<SourceOut>, sqlx::Error> {
    let row = sqlx::query(&format!("{SOURCE_SELECT} WHERE s.id = $1")).bind(id).fetch_optional(conn).await?;
    row.as_ref().map(source_from_row).transpose()
}

fn next_cursor<T>(items: &mut Vec<T>, limit: i64, key: impl Fn(&T) -> Cursor) -> Option<String> {
    if items.len() > usize::try_from(limit).unwrap_or(usize::MAX) {
        items.pop();
        items.last().map(|i| key(i).encode())
    } else {
        None
    }
}

pub async fn list(conn: &mut PgConnection, f: &SourceFilter) -> Result<Page<SourceOut>, ApiError> {
    let limit = pagination::limit(f.limit)?;
    let cursor = f.cursor.as_deref().map(Cursor::decode).transpose()?;
    let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(SOURCE_SELECT);
    qb.push(" WHERE true");
    if let Some(t) = f.source_type {
        qb.push(" AND s.type = ").push_bind(t);
    }
    if let Some(e) = f.enabled {
        qb.push(" AND s.enabled = ").push_bind(e);
    }
    if let Some(c) = cursor {
        qb.push(" AND (s.created_at, s.id) < (").push_bind(c.created_at).push(", ").push_bind(c.id).push(")");
    }
    qb.push(" ORDER BY s.created_at DESC, s.id DESC LIMIT ").push_bind(limit + 1);
    let rows = qb.build().fetch_all(conn).await?;
    let mut items = rows.iter().map(source_from_row).collect::<Result<Vec<_>, _>>()?;
    let next_cursor = next_cursor(&mut items, limit, |s| Cursor { created_at: s.created_at, id: s.id });
    Ok(Page { items, next_cursor })
}

fn map_source_unique(e: sqlx::Error) -> ApiError {
    match e.as_database_error().and_then(|d| d.constraint()) {
        Some("sources_name_key") => ApiError::Conflict("source name already exists".into()),
        Some("sources_type_uri_uniq") => ApiError::Conflict("source already exists".into()),
        _ => ApiError::Database(e),
    }
}

pub async fn create(
    tx: &mut Transaction<'_, Postgres>,
    req: &SourceCreate,
    audit_event: AuditEvent,
) -> Result<SourceOut, ApiError> {
    let name = validate_name(&req.name)?;
    validate_uri(&req.uri).map_err(|e| match e {
        ApiError::Unprocessable(m) => unprocessable(m.replacen("source.uri", "uri", 1)),
        other => other,
    })?;
    let environment = validate_environment(req.environment.as_deref())?;
    let credential_ref = validate_credential_ref(req.credential_ref.as_deref())?;
    let schedule = validate_schedule(req.schedule.as_deref(), req.source_type)?;
    let config = validate_config(&req.config.clone().unwrap_or_default())?;

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO sources (name, type, uri, environment, credential_ref, schedule_cron, enabled, config, next_scan_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",
    )
    .bind(&name)
    .bind(req.source_type)
    .bind(&req.uri)
    .bind(&environment)
    .bind(&credential_ref)
    .bind(schedule.as_ref().map(ToString::to_string))
    .bind(req.enabled)
    .bind(&config)
    .bind(next_scan_at(schedule.as_ref(), req.enabled))
    .fetch_one(&mut **tx)
    .await
    .map_err(map_source_unique)?;

    let details = json!({
        "name": name,
        "type": req.source_type,
        "scheduled": schedule.is_some(),
        // The reference names a file on the worker; it is not a credential value.
        "credential_ref": credential_ref,
    });
    audit::record(tx, &audit_event.target("source", id.to_string()).details(details)).await?;
    get(tx, id).await?.ok_or(ApiError::NotFound)
}

#[derive(sqlx::FromRow)]
struct CurrentSource {
    name: String,
    #[sqlx(rename = "type")]
    source_type: SourceType,
    environment: Option<String>,
    credential_ref: Option<String>,
    schedule_cron: Option<String>,
    enabled: bool,
    config: Value,
    next_scan_at: Option<DateTime<Utc>>,
}

/// Cancel the source's queued or running worker job; a running one stops at the
/// worker's next heartbeat.
async fn cancel_active(conn: &mut PgConnection, source_id: Uuid, reason: &str) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query(&format!(
        "UPDATE scan_jobs SET status = 'cancelled', finished_at = now(), error = $2
         WHERE source_id = $1 AND status IN ('queued', 'running') AND trigger IN {WORKER_TRIGGERS}"
    ))
    .bind(source_id)
    .bind(reason)
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn update(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    req: &SourceUpdate,
    audit_event: AuditEvent,
) -> Result<SourceOut, ApiError> {
    if req.source_type.is_some() || req.uri.is_some() {
        return Err(unprocessable("type and uri cannot be changed"));
    }
    let no_changes = req.name.is_none()
        && req.environment.is_none()
        && req.credential_ref.is_none()
        && req.schedule.is_none()
        && req.enabled.is_none()
        && req.config.is_none();
    if no_changes {
        return Err(unprocessable("no fields to update"));
    }
    let cur: CurrentSource = sqlx::query_as(
        "SELECT name, type, environment, credential_ref, schedule_cron, enabled, config, next_scan_at
         FROM sources WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(ApiError::NotFound)?;

    let name = req.name.as_deref().map(validate_name).transpose()?.unwrap_or_else(|| cur.name.clone());
    let environment = match &req.environment {
        Some(e) => validate_environment(e.as_deref())?,
        None => cur.environment.clone(),
    };
    let credential_ref = match &req.credential_ref {
        Some(r) => validate_credential_ref(r.as_deref())?,
        None => cur.credential_ref.clone(),
    };
    let schedule = match &req.schedule {
        Some(s) => validate_schedule(s.as_deref(), cur.source_type)?,
        // A stored schedule that no longer parses is treated as none.
        None => cur.schedule_cron.as_deref().and_then(|s| Schedule::parse(s).ok()),
    };
    let schedule_text = match &req.schedule {
        Some(_) => schedule.as_ref().map(ToString::to_string),
        None => cur.schedule_cron.clone(),
    };
    let enabled = req.enabled.unwrap_or(cur.enabled);
    let config = req.config.as_ref().map(validate_config).transpose()?.unwrap_or_else(|| cur.config.clone());

    let schedule_changed = schedule_text != cur.schedule_cron;
    let enabled_changed = enabled != cur.enabled;
    let next =
        if schedule_changed || enabled_changed { next_scan_at(schedule.as_ref(), enabled) } else { cur.next_scan_at };

    sqlx::query(
        "UPDATE sources SET name = $2, environment = $3, credential_ref = $4, schedule_cron = $5, enabled = $6,
                            config = $7, next_scan_at = $8
         WHERE id = $1",
    )
    .bind(id)
    .bind(&name)
    .bind(&environment)
    .bind(&credential_ref)
    .bind(&schedule_text)
    .bind(enabled)
    .bind(&config)
    .bind(next)
    .execute(&mut **tx)
    .await
    .map_err(map_source_unique)?;

    let mut cancelled = 0;
    if enabled_changed && !enabled {
        cancelled = cancel_active(tx, id, "source disabled").await?;
    }

    let mut changed = Vec::new();
    for (field, differs) in [
        ("name", name != cur.name),
        ("environment", environment != cur.environment),
        ("credential_ref", credential_ref != cur.credential_ref),
        ("schedule", schedule_changed),
        ("enabled", enabled_changed),
        ("config", config != cur.config),
    ] {
        if differs {
            changed.push(field);
        }
    }
    let mut details = json!({ "changed": changed, "cancelled_scans": cancelled });
    if credential_ref != cur.credential_ref {
        // A name (or null when removed), never a value: who pointed the source at which credential.
        details["credential_ref"] = json!(credential_ref);
    }
    audit::record(tx, &audit_event.target("source", id.to_string()).details(details)).await?;
    get(tx, id).await?.ok_or(ApiError::NotFound)
}

pub async fn delete(tx: &mut Transaction<'_, Postgres>, id: Uuid, audit_event: AuditEvent) -> Result<(), ApiError> {
    let row = sqlx::query("SELECT name, type FROM sources WHERE id = $1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    let name: String = row.try_get("name")?;
    let source_type: SourceType = row.try_get("type")?;
    let cancelled = cancel_active(tx, id, "source deleted").await?;
    // Locations and past jobs stay, with `source_id = NULL` (FK ON DELETE SET NULL).
    sqlx::query("DELETE FROM sources WHERE id = $1").bind(id).execute(&mut **tx).await?;
    let details = json!({ "name": name, "type": source_type, "cancelled_scans": cancelled });
    audit::record(tx, &audit_event.target("source", id.to_string()).details(details)).await?;
    Ok(())
}

// ── scan jobs ─────────────────────────────────────────────────────────────

const SCAN_SELECT: &str =
    "SELECT id, source_id, trigger, status, full_scan, attempts, requested_by, created_at, started_at,
        finished_at, run_after, stats, error
    FROM scan_jobs";

fn scan_from_row(row: &sqlx::postgres::PgRow) -> Result<ScanOut, sqlx::Error> {
    let trigger: String = row.try_get("trigger")?;
    let trigger = ScanTrigger::parse(&trigger)
        .ok_or_else(|| sqlx::Error::Decode(format!("unknown scan trigger {trigger:?}").into()))?;
    Ok(ScanOut {
        id: row.try_get("id")?,
        source_id: row.try_get("source_id")?,
        trigger,
        status: row.try_get("status")?,
        full_scan: row.try_get("full_scan")?,
        attempts: row.try_get("attempts")?,
        requested_by: row.try_get("requested_by")?,
        created_at: row.try_get("created_at")?,
        started_at: row.try_get("started_at")?,
        finished_at: row.try_get("finished_at")?,
        run_after: row.try_get("run_after")?,
        stats: row.try_get("stats")?,
        error: row.try_get("error")?,
    })
}

pub async fn get_scan(conn: &mut PgConnection, id: Uuid) -> Result<Option<ScanOut>, sqlx::Error> {
    let row = sqlx::query(&format!("{SCAN_SELECT} WHERE id = $1")).bind(id).fetch_optional(conn).await?;
    row.as_ref().map(scan_from_row).transpose()
}

pub async fn list_scans(conn: &mut PgConnection, f: &ScanFilter) -> Result<Page<ScanOut>, ApiError> {
    let limit = pagination::limit(f.limit)?;
    let cursor = f.cursor.as_deref().map(Cursor::decode).transpose()?;
    let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(SCAN_SELECT);
    qb.push(" WHERE true");
    if let Some(s) = f.source_id {
        qb.push(" AND source_id = ").push_bind(s);
    }
    if let Some(s) = f.status {
        qb.push(" AND status = ").push_bind(s);
    }
    if let Some(t) = f.trigger {
        qb.push(" AND trigger = ").push_bind(t.as_str());
    }
    if let Some(c) = cursor {
        qb.push(" AND (created_at, id) < (").push_bind(c.created_at).push(", ").push_bind(c.id).push(")");
    }
    qb.push(" ORDER BY created_at DESC, id DESC LIMIT ").push_bind(limit + 1);
    let rows = qb.build().fetch_all(conn).await?;
    let mut items = rows.iter().map(scan_from_row).collect::<Result<Vec<_>, _>>()?;
    let next_cursor = next_cursor(&mut items, limit, |s| Cursor { created_at: s.created_at, id: s.id });
    Ok(Page { items, next_cursor })
}

/// Queue a manual server-side scan of a source.
pub async fn enqueue(
    tx: &mut Transaction<'_, Postgres>,
    source_id: Uuid,
    requested_by: Uuid,
    req: &ScanRequest,
    audit_event: AuditEvent,
) -> Result<ScanOut, ApiError> {
    let row = sqlx::query("SELECT type, enabled, environment FROM sources WHERE id = $1 FOR SHARE")
        .bind(source_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    if row.try_get::<SourceType, _>("type")? != SourceType::GitRepo {
        return Err(unprocessable("only git_repo sources can be scanned by the server"));
    }
    if !row.try_get::<bool, _>("enabled")? {
        return Err(ApiError::Conflict("source is disabled".into()));
    }
    let environment: Option<String> = row.try_get("environment")?;
    // The unique index decides, not a check-then-insert race.
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO scan_jobs (source_id, trigger, status, requested_by, full_scan, environment)
         VALUES ($1, 'manual', 'queued', $2, $3, $4) RETURNING id",
    )
    .bind(source_id)
    .bind(requested_by)
    .bind(req.full)
    .bind(&environment)
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| {
        if e.as_database_error().and_then(|d| d.constraint()) == Some("scan_jobs_worker_active_uniq") {
            ApiError::Conflict("a scan of this source is already queued or running".into())
        } else {
            e.into()
        }
    })?;
    let details = json!({ "source_id": source_id, "trigger": "manual", "full": req.full });
    audit::record(tx, &audit_event.target("scan_job", id.to_string()).details(details)).await?;
    get_scan(tx, id).await?.ok_or(ApiError::NotFound)
}

/// Cancel a queued or running server-side scan. API-token scans are closed by their token.
pub async fn cancel(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    audit_event: AuditEvent,
) -> Result<ScanOut, ApiError> {
    let row = sqlx::query("SELECT trigger, status, source_id FROM scan_jobs WHERE id = $1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    let trigger = ScanTrigger::parse(&row.try_get::<String, _>("trigger")?);
    let status: JobStatus = row.try_get("status")?;
    let source_id: Option<Uuid> = row.try_get("source_id")?;
    let active = matches!(status, JobStatus::Queued | JobStatus::Running);
    if !(active && trigger.is_some_and(ScanTrigger::is_worker)) {
        return Err(ApiError::Conflict("scan cannot be cancelled".into()));
    }
    sqlx::query(
        "UPDATE scan_jobs SET status = 'cancelled', finished_at = now(), error = 'cancelled by user' WHERE id = $1",
    )
    .bind(id)
    .execute(&mut **tx)
    .await?;
    let details = json!({ "source_id": source_id, "from": status });
    audit::record(tx, &audit_event.target("scan_job", id.to_string()).details(details)).await?;
    get_scan(tx, id).await?.ok_or(ApiError::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_unprocessable<T>(r: &Result<T, ApiError>) -> bool {
        matches!(r, Err(ApiError::Unprocessable(_)))
    }

    #[test]
    fn names() {
        assert_eq!(validate_name("  infra  ").ok().as_deref(), Some("infra"));
        assert!(is_unprocessable(&validate_name("  ")));
        assert!(is_unprocessable(&validate_name("a\nb")));
        assert!(is_unprocessable(&validate_name(&"x".repeat(201))));
    }

    #[test]
    fn credential_refs() {
        assert_eq!(validate_credential_ref(Some("github_infra-1")).ok().flatten().as_deref(), Some("github_infra-1"));
        assert_eq!(validate_credential_ref(None).ok(), Some(None));
        for bad in ["", "../pepper_keys", "a/b", "a.b", "a b", &"x".repeat(65)] {
            assert!(is_unprocessable(&validate_credential_ref(Some(bad))), "{bad:?}");
        }
    }

    #[test]
    fn configs() {
        let ok = SourceConfig { username: Some("x-access-token".into()), max_blob_bytes: Some(1024) };
        assert_eq!(validate_config(&ok).ok(), Some(json!({"username": "x-access-token", "max_blob_bytes": 1024})));
        assert_eq!(validate_config(&SourceConfig::default()).ok(), Some(json!({})));
        for u in ["", "-oProxyCommand", "a b", "a:b", &"u".repeat(65)] {
            let c = SourceConfig { username: Some(u.into()), max_blob_bytes: None };
            assert!(is_unprocessable(&validate_config(&c)), "{u:?}");
        }
        for n in [0, MAX_BLOB_BYTES_LIMIT + 1] {
            let c = SourceConfig { username: None, max_blob_bytes: Some(n) };
            assert!(is_unprocessable(&validate_config(&c)), "{n}");
        }
        assert!(serde_json::from_str::<SourceConfig>(r#"{"password":"x"}"#).is_err(), "unknown fields");
    }

    #[test]
    fn schedules() {
        let s = validate_schedule(Some(" 0  3 * * * "), SourceType::GitRepo).ok().flatten();
        assert_eq!(s.map(|s| s.to_string()).as_deref(), Some("0 3 * * *"));
        assert!(is_unprocessable(&validate_schedule(Some("* * * * *"), SourceType::GitRepo)));
        assert!(is_unprocessable(&validate_schedule(Some("0 3 * * *"), SourceType::Filesystem)));
        assert!(matches!(validate_schedule(None, SourceType::Filesystem), Ok(None)));
        let s = Schedule::parse("0 3 * * *").ok();
        assert!(next_scan_at(s.as_ref(), true).is_some_and(|t| t > Utc::now()));
        assert_eq!(next_scan_at(s.as_ref(), false), None);
        assert_eq!(next_scan_at(None, true), None);
    }

    #[test]
    fn update_parsing() {
        let null: SourceUpdate = serde_json::from_str(r#"{"schedule":null}"#).unwrap_or_default();
        assert_eq!(null.schedule, Some(None));
        let absent: SourceUpdate = serde_json::from_str(r#"{"enabled":false}"#).unwrap_or_default();
        assert_eq!(absent.schedule, None);
        assert_eq!(serde_json::from_str::<ScanRequest>("{}").ok(), Some(ScanRequest { full: false }));
        assert_eq!(serde_json::from_str::<ScanRequest>(r#"{"full":true}"#).ok(), Some(ScanRequest { full: true }));
        assert!(serde_json::from_str::<ScanRequest>(r#"{"fast":true}"#).is_err());
        let immutable: SourceUpdate = serde_json::from_str(r#"{"uri":"https://x/y"}"#).unwrap_or_default();
        assert!(immutable.uri.is_some());
        assert!(serde_json::from_str::<SourceUpdate>(r#"{"scan_state":{}}"#).is_err());
    }

    #[test]
    fn triggers() {
        for t in [ScanTrigger::Manual, ScanTrigger::Schedule, ScanTrigger::Ci, ScanTrigger::Agent] {
            assert_eq!(ScanTrigger::parse(t.as_str()), Some(t));
        }
        assert!(ScanTrigger::Manual.is_worker() && !ScanTrigger::Ci.is_worker());
    }
}
