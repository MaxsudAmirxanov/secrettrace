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
use crate::ingest::validate_environment;
use crate::model::SourceType;
use crate::policy::Glob;

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
    /// CN of the client certificate the token must arrive with (through the mTLS
    /// endpoint), 1-64 of `[A-Za-z0-9._-]`. Required when the server enforces client
    /// certificates.
    #[serde(default)]
    #[schema(example = "ci-infra")]
    cert_cn: Option<String>,
    /// Only sources of this type may be reported.
    #[serde(default)]
    source_type: Option<SourceType>,
    /// Only source URIs matching this glob may be reported (`*` stops at `/`, `**` does not).
    #[serde(default)]
    #[schema(example = "https://git.example.com/acme/**")]
    source_uri_pattern: Option<String>,
    /// Scans are recorded under this environment; the token cannot claim another.
    #[serde(default)]
    #[schema(example = "ci")]
    environment: Option<String>,
}

#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct TokenInfo {
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    pub token_prefix: String,
    pub scopes: Vec<String>,
    pub cert_cn: Option<String>,
    pub source_type: Option<SourceType>,
    pub source_uri_pattern: Option<String>,
    pub environment: Option<String>,
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

const TOKEN_COLUMNS: &str = "id, name, kind, token_prefix, scopes, cert_cn, source_type, source_uri_pattern, environment, \
                             created_at, expires_at, revoked_at, last_used_at";

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
    let cert_cn = req.cert_cn.as_deref().map(str::trim).filter(|c| !c.is_empty());
    if let Some(cn) = cert_cn
        && !tokens::valid_cert_cn(cn)
    {
        return Err(ApiError::Unprocessable("cert_cn must be 1-64 chars of [A-Za-z0-9._-]".into()));
    }
    if cert_cn.is_none() && state.auth.require_client_cert {
        return Err(ApiError::Unprocessable(
            "this server requires API tokens bound to a client certificate: set cert_cn".into(),
        ));
    }
    let uri_pattern = req.source_uri_pattern.as_deref().map(str::trim).filter(|p| !p.is_empty());
    if let Some(p) = uri_pattern {
        if p.len() > 2048 {
            return Err(ApiError::Unprocessable("source_uri_pattern must be at most 2048 bytes".into()));
        }
        Glob::parse(p).map_err(|e| ApiError::Unprocessable(format!("source_uri_pattern: {e}")))?;
    }
    let environment = validate_environment(req.environment.as_deref().map(str::trim).filter(|e| !e.is_empty()))?;
    let mut scopes = req.scopes.clone();
    scopes.sort();
    scopes.dedup();

    let new = tokens::new_api_token();
    let expires_at = Utc::now() + Duration::days(req.expires_in_days);

    let mut tx = state.db.begin().await?;
    let info: TokenInfo = sqlx::query_as(&format!(
        "INSERT INTO api_tokens (name, kind, token_hash, token_prefix, scopes, created_by, expires_at,
                                 cert_cn, source_type, source_uri_pattern, environment)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING {TOKEN_COLUMNS}"
    ))
    .bind(name)
    .bind(req.kind.as_str())
    .bind(new.hash.as_slice())
    .bind(&new.prefix)
    .bind(&scopes)
    .bind(user.id)
    .bind(expires_at)
    .bind(cert_cn)
    .bind(req.source_type)
    .bind(uri_pattern)
    .bind(&environment)
    .fetch_one(&mut *tx)
    .await?;
    let ev = meta.user_event(user.id, "api_token.create").target("api_token", info.id.to_string()).details(json!({
        "name": name, "prefix": new.prefix, "kind": req.kind.as_str(), "scopes": scopes,
        "cert_cn": cert_cn, "source_type": req.source_type, "source_uri_pattern": uri_pattern,
        "environment": environment,
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
