//! `/api/v1/api-tokens` — machine credentials for agents and CI (admin only).

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::app::AppState;
use crate::audit;
use crate::auth::tokens::{self, API_SCOPES};
use crate::auth::{CurrentUser, RequestMeta, Role};
use crate::error::{ApiError, ApiResult, Problem};
use crate::extract::{ApiJson, ApiPath};

const MAX_TTL_DAYS: i64 = 365;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum TokenKind {
    Agent,
    Ci,
    Automation,
}

impl TokenKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Ci => "ci",
            Self::Automation => "automation",
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateTokenRequest {
    name: String,
    kind: TokenKind,
    #[schema(example = json!(["ingest:profile", "ingest:match", "ingest:findings"]))]
    scopes: Vec<String>,
    /// Days until expiry (1..=365). Tokens always expire.
    #[schema(minimum = 1, maximum = 365)]
    expires_in_days: i64,
}

#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct TokenInfo {
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    pub token_prefix: String,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreatedToken {
    /// Shown exactly once; only its hash is stored.
    pub token: String,
    #[serde(flatten)]
    pub info: TokenInfo,
}

const TOKEN_COLUMNS: &str = "id, name, kind, token_prefix, scopes, created_at, expires_at, revoked_at, last_used_at";

/// List API tokens (never includes token values).
#[utoipa::path(get, path = "/api/v1/api-tokens", tag = "api-tokens",
    responses((status = 200, body = Vec<TokenInfo>), (status = 403, body = Problem, content_type = "application/problem+json")), security(("session" = [])))]
pub async fn list(State(state): State<AppState>, user: CurrentUser) -> ApiResult<Json<Vec<TokenInfo>>> {
    user.require(Role::Admin)?;
    let rows = sqlx::query_as(&format!("SELECT {TOKEN_COLUMNS} FROM api_tokens ORDER BY created_at DESC"))
        .fetch_all(&state.db)
        .await?;
    Ok(Json(rows))
}

/// Issue a token for an agent or CI. The value is returned once.
#[utoipa::path(post, path = "/api/v1/api-tokens", tag = "api-tokens", request_body = CreateTokenRequest,
    responses((status = 201, body = CreatedToken), (status = 403, body = Problem, content_type = "application/problem+json"), (status = 422, body = Problem, content_type = "application/problem+json")),
    security(("session" = [], "csrf" = [])))]
pub async fn create(
    State(state): State<AppState>,
    meta: RequestMeta,
    user: CurrentUser,
    ApiJson(req): ApiJson<CreateTokenRequest>,
) -> ApiResult<(StatusCode, Json<CreatedToken>)> {
    user.require(Role::Admin)?;
    let name = req.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(ApiError::Unprocessable("name must be 1-100 characters".into()));
    }
    if req.scopes.is_empty() {
        return Err(ApiError::Unprocessable("at least one scope is required".into()));
    }
    if let Some(bad) = req.scopes.iter().find(|s| !API_SCOPES.contains(&s.as_str())) {
        return Err(ApiError::Unprocessable(format!("unknown scope {bad:?}; allowed: {}", API_SCOPES.join(", "))));
    }
    if !(1..=MAX_TTL_DAYS).contains(&req.expires_in_days) {
        return Err(ApiError::Unprocessable(format!("expires_in_days must be 1..={MAX_TTL_DAYS}")));
    }
    let mut scopes = req.scopes.clone();
    scopes.sort();
    scopes.dedup();

    let new = tokens::new_api_token();
    let expires_at = Utc::now() + Duration::days(req.expires_in_days);

    let mut tx = state.db.begin().await?;
    let info: TokenInfo = sqlx::query_as(&format!(
        "INSERT INTO api_tokens (name, kind, token_hash, token_prefix, scopes, created_by, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING {TOKEN_COLUMNS}"
    ))
    .bind(name)
    .bind(req.kind.as_str())
    .bind(new.hash.as_slice())
    .bind(&new.prefix)
    .bind(&scopes)
    .bind(user.id)
    .bind(expires_at)
    .fetch_one(&mut *tx)
    .await?;
    let ev = meta.user_event(user.id, "api_token.create").target("api_token", info.id.to_string()).details(json!({
        "name": name, "prefix": new.prefix, "kind": req.kind.as_str(), "scopes": scopes,
    }));
    audit::record(&mut tx, &ev).await?;
    tx.commit().await?;

    Ok((StatusCode::CREATED, Json(CreatedToken { token: new.token.as_str().to_owned(), info })))
}

/// Revoke a token immediately.
#[utoipa::path(delete, path = "/api/v1/api-tokens/{id}", tag = "api-tokens", params(("id" = Uuid, Path)),
    responses((status = 204, description = "Revoked"), (status = 403, body = Problem, content_type = "application/problem+json"), (status = 404, body = Problem, content_type = "application/problem+json")),
    security(("session" = [], "csrf" = [])))]
pub async fn revoke(
    State(state): State<AppState>,
    meta: RequestMeta,
    user: CurrentUser,
    ApiPath(id): ApiPath<Uuid>,
) -> ApiResult<StatusCode> {
    user.require(Role::Admin)?;
    let mut tx = state.db.begin().await?;
    let prefix: String = sqlx::query_scalar(
        "UPDATE api_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL RETURNING token_prefix",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    let ev = meta.user_event(user.id, "api_token.revoke").target("api_token", id.to_string());
    audit::record(&mut tx, &ev.details(json!({ "prefix": prefix }))).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
