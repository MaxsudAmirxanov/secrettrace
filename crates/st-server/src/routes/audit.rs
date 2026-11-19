//! `/api/v1/audit` — the audit log (admin only): browse and verify the hash chain.

use axum::Json;
use axum::extract::State;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Postgres, QueryBuilder};
use utoipa::{IntoParams, ToSchema};

use crate::app::AppState;
use crate::audit::{self, VerifyError};
use crate::auth::{CurrentUser, Role};
use crate::error::{ApiError, ApiResult, Problem};
use crate::extract::ApiQuery;
use crate::pagination::{self, Page};

#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct AuditOut {
    pub id: i64,
    pub ts: DateTime<Utc>,
    /// `user`, `token` or `system`.
    pub actor_type: String,
    pub actor_id: String,
    /// Username or token name of the actor, when it still exists.
    pub actor_name: Option<String>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub ip: Option<String>,
    pub request_id: Option<String>,
    /// Never contains secret values.
    #[schema(value_type = Object)]
    pub details: Value,
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AuditFilter {
    /// Exact action, or a prefix ending in `.` (e.g. `auth.`).
    pub action: Option<String>,
    pub actor_type: Option<String>,
    pub actor_id: Option<String>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub cursor: Option<String>,
    #[param(minimum = 1, maximum = 200)]
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct VerifyOut {
    pub ok: bool,
    pub rows: u64,
    /// Hash of the newest row (hex); keep a copy out of band to detect tail truncation.
    pub head: Option<String>,
    pub broken_at: Option<i64>,
    pub reason: Option<String>,
}

fn bounded<'a>(field: &str, v: Option<&'a str>, max: usize) -> Result<Option<&'a str>, ApiError> {
    match v.map(str::trim).filter(|v| !v.is_empty()) {
        Some(v) if v.chars().count() > max || v.chars().any(char::is_control) => {
            Err(ApiError::BadRequest(format!("{field} must be at most {max} printable characters")))
        }
        other => Ok(other),
    }
}

/// Browse the audit log, newest first.
#[utoipa::path(get, path = "/api/v1/audit", tag = "audit", params(AuditFilter),
    responses((status = 200, body = Page<AuditOut>), (status = 400, body = Problem, content_type = "application/problem+json"),
              (status = 403, body = Problem, content_type = "application/problem+json")),
    security(("session" = [])))]
pub async fn list(
    State(state): State<AppState>,
    user: CurrentUser,
    ApiQuery(f): ApiQuery<AuditFilter>,
) -> ApiResult<Json<Page<AuditOut>>> {
    user.require(Role::Admin)?;
    let limit = pagination::limit(f.limit)?;
    let cursor = match f.cursor.as_deref() {
        None | Some("") => None,
        Some(c) => {
            Some(c.parse::<i64>().ok().filter(|id| *id > 0).ok_or(ApiError::BadRequest("invalid cursor".into()))?)
        }
    };
    let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(
        "SELECT a.id, a.ts, a.actor_type, a.actor_id,
                COALESCE(u.username::text, t.name) AS actor_name,
                a.action, a.target_type, a.target_id, host(a.ip) AS ip, a.request_id, a.details
         FROM audit_log a
         LEFT JOIN users u ON a.actor_type = 'user' AND u.id::text = a.actor_id
         LEFT JOIN api_tokens t ON a.actor_type = 'token' AND t.id::text = a.actor_id
         WHERE true",
    );
    if let Some(action) = bounded("action", f.action.as_deref(), 100)? {
        if let Some(prefix) = action.strip_suffix('.') {
            let like = format!("{}.%", prefix.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"));
            qb.push(" AND a.action LIKE ").push_bind(like);
        } else {
            qb.push(" AND a.action = ").push_bind(action.to_owned());
        }
    }
    for (column, field, value) in [
        ("a.actor_type", "actor_type", f.actor_type.as_deref()),
        ("a.actor_id", "actor_id", f.actor_id.as_deref()),
        ("a.target_type", "target_type", f.target_type.as_deref()),
        ("a.target_id", "target_id", f.target_id.as_deref()),
    ] {
        if let Some(v) = bounded(field, value, 200)? {
            qb.push(format!(" AND {column} = ")).push_bind(v.to_owned());
        }
    }
    if let Some(t) = f.since {
        qb.push(" AND a.ts >= ").push_bind(t);
    }
    if let Some(t) = f.until {
        qb.push(" AND a.ts < ").push_bind(t);
    }
    if let Some(id) = cursor {
        qb.push(" AND a.id < ").push_bind(id);
    }
    qb.push(" ORDER BY a.id DESC LIMIT ").push_bind(limit + 1);
    let mut items: Vec<AuditOut> = qb.build_query_as().fetch_all(&state.db).await?;
    let next_cursor = if items.len() > usize::try_from(limit).unwrap_or(usize::MAX) {
        items.pop();
        items.last().map(|a| a.id.to_string())
    } else {
        None
    };
    Ok(Json(Page { items, next_cursor }))
}

/// Recompute the hash chain of the whole log.
#[utoipa::path(get, path = "/api/v1/audit/verify", tag = "audit",
    responses((status = 200, body = VerifyOut), (status = 403, body = Problem, content_type = "application/problem+json")),
    security(("session" = [])))]
pub async fn verify(State(state): State<AppState>, user: CurrentUser) -> ApiResult<Json<VerifyOut>> {
    user.require(Role::Admin)?;
    match audit::verify_chain(&state.db).await {
        Ok(r) => Ok(Json(VerifyOut { ok: true, rows: r.rows, head: r.head, broken_at: None, reason: None })),
        Err(VerifyError::Broken { id, reason }) => {
            tracing::error!(row_id = id, reason, "audit chain verification failed");
            Ok(Json(VerifyOut { ok: false, rows: 0, head: None, broken_at: Some(id), reason: Some(reason.into()) }))
        }
        Err(VerifyError::Db(e)) => Err(ApiError::Database(e)),
    }
}
