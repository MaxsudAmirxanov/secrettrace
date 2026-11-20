//! `/api/v1/canaries` — canary tokens (viewers read, operators create and change), and
//! `ANY /_canary`, where the edge's canary listener forwards every request it receives.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use st_core::{SecretType, prepare};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::app::AppState;
use crate::audit;
use crate::auth::{CurrentUser, FromTrustedProxy, RequestMeta, Role};
use crate::canary::{self, CANARY_HEADER};
use crate::error::{ApiError, ApiResult, Problem};
use crate::extract::{ApiJson, ApiPath};
use crate::registry::{self, Registered, SecretCreate};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, ToSchema)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "canary_kind", rename_all = "snake_case")]
pub enum CanaryKind {
    /// A link that fires when opened.
    Url,
    /// A fake API key with an endpoint, for `.env` files and configs.
    ApiKey,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow, ToSchema)]
pub struct CanaryOut {
    pub id: Uuid,
    pub name: String,
    pub kind: CanaryKind,
    pub planted_at: Option<String>,
    pub memo: Option<String>,
    /// The registered secret of an `api_key` canary: scans that find it report a leak.
    pub secret_id: Option<Uuid>,
    pub enabled: bool,
    pub hit_count: i64,
    pub last_hit_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct HitOut {
    pub id: i64,
    pub at: DateTime<Utc>,
    pub ip: Option<String>,
    pub method: String,
    pub host: Option<String>,
    /// Request target with the token replaced by `{token}`.
    pub path: String,
    pub user_agent: Option<String>,
    /// Where the token was: `path`, `query`, `bearer`, `basic` or `header`.
    pub via: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CanaryDetail {
    #[serde(flatten)]
    pub canary: CanaryOut,
    /// The latest 100 stored hits, newest first.
    pub hits: Vec<HitOut>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CanaryCreate {
    #[schema(example = "laptop-alice-aws", min_length = 1, max_length = 190)]
    pub name: String,
    pub kind: CanaryKind,
    /// Where it will be planted (free text, for whoever reads the alert).
    #[serde(default)]
    #[schema(example = "alice's laptop, ~/.config/deploy/.env", max_length = 500)]
    pub planted_at: Option<String>,
    #[serde(default)]
    #[schema(max_length = 2000)]
    pub memo: Option<String>,
}

/// Returned once: only an HMAC of the token is stored.
#[derive(Debug, Serialize, ToSchema)]
pub struct CreatedCanary {
    pub canary: CanaryOut,
    /// The link (`url`) or the fake key (`api_key`).
    pub value: String,
    /// The fake service endpoint of an `api_key` canary.
    pub endpoint: Option<String>,
    /// Ready to plant: the link, or `.env` lines with endpoint and key.
    pub snippet: String,
}

#[allow(clippy::option_option)] // absent vs null vs value
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CanaryUpdate {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<String>, nullable)]
    pub planted_at: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<String>, nullable)]
    pub memo: Option<Option<String>>,
}

#[allow(clippy::option_option)] // absent / null / value
fn double_option<'de, T: Deserialize<'de>, D: Deserializer<'de>>(d: D) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(d).map(Some)
}

const COLUMNS: &str =
    "id, name, kind, planted_at, memo, secret_id, enabled, hit_count, last_hit_at, created_at, updated_at";
const MAX_NAME: usize = 190; // the registered secret is named "canary: <name>" (≤ 200)

fn text(field: &str, value: Option<&str>, max: usize) -> Result<Option<String>, ApiError> {
    let Some(v) = value.map(str::trim).filter(|v| !v.is_empty()) else { return Ok(None) };
    if v.chars().count() > max || v.chars().any(|c| c.is_control() && c != '\n') {
        return Err(ApiError::Unprocessable(format!(
            "{field} must be at most {max} characters, no control characters"
        )));
    }
    Ok(Some(v.to_owned()))
}

/// List canaries, newest first.
#[utoipa::path(get, path = "/api/v1/canaries", tag = "canaries",
    responses((status = 200, body = Vec<CanaryOut>), (status = 401, body = Problem, content_type = "application/problem+json")),
    security(("session" = [])))]
pub async fn list(State(state): State<AppState>, user: CurrentUser) -> ApiResult<Json<Vec<CanaryOut>>> {
    user.require(Role::Viewer)?;
    let rows = sqlx::query_as(&format!("SELECT {COLUMNS} FROM canaries ORDER BY created_at DESC, id LIMIT 1000"))
        .fetch_all(&state.db)
        .await?;
    Ok(Json(rows))
}

/// Create a canary. The value is returned once; `api_key` canaries are also registered
/// as secrets (named `canary: <name>`, owner `canary`).
#[utoipa::path(post, path = "/api/v1/canaries", tag = "canaries", request_body = CanaryCreate,
    responses(
        (status = 201, body = CreatedCanary),
        (status = 403, body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Name taken, or canaries are not configured", body = Problem, content_type = "application/problem+json"),
        (status = 422, body = Problem, content_type = "application/problem+json"),
    ),
    security(("session" = [], "csrf" = [])))]
pub async fn create(
    State(state): State<AppState>,
    meta: RequestMeta,
    user: CurrentUser,
    ApiJson(req): ApiJson<CanaryCreate>,
) -> ApiResult<(StatusCode, Json<CreatedCanary>)> {
    user.require(Role::Operator)?;
    let settings = state.canary.clone().ok_or_else(|| {
        ApiError::Conflict("canary tokens are not configured: set ST_CANARY_KEY and ST_CANARY_BASE_URL".into())
    })?;
    let name =
        text("name", Some(&req.name), MAX_NAME)?.ok_or_else(|| ApiError::Unprocessable("name is required".into()))?;
    let planted_at = text("planted_at", req.planted_at.as_deref(), 500)?;
    let memo = text("memo", req.memo.as_deref(), 2000)?;

    let token = match req.kind {
        CanaryKind::Url => canary::new_url_token(),
        CanaryKind::ApiKey => canary::new_api_key(),
    };
    let mut tx = state.db.begin().await?;
    let secret_id = if req.kind == CanaryKind::ApiKey {
        let (digest, hints) = prepare(SecretType::ApiKey, &token).map_err(anyhow::Error::from)?;
        let secret = SecretCreate {
            name: format!("canary: {name}"),
            secret_type: SecretType::ApiKey,
            owner: "canary".into(),
            purpose: Some("Canary token: it is never used legitimately, any location is a leak".into()),
            digest,
            hints,
            allow_rules: Vec::new(),
            expires_at: None,
        };
        match registry::create(&mut tx, &state.pepper, &secret, user.id, meta.user_event(user.id, "secret.create"))
            .await?
        {
            Registered::Created(s) => Some(s.id),
            Registered::Duplicate(_) => return Err(anyhow::anyhow!("a fresh canary key is already registered").into()),
        }
    } else {
        None
    };
    let row: CanaryOut = sqlx::query_as(&format!(
        "INSERT INTO canaries (name, kind, lookup, planted_at, memo, secret_id, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING {COLUMNS}"
    ))
    .bind(&name)
    .bind(req.kind)
    .bind(settings.lookup(&token).as_slice())
    .bind(&planted_at)
    .bind(&memo)
    .bind(secret_id)
    .bind(user.id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        if e.as_database_error().and_then(|d| d.constraint()) == Some("canaries_name_key") {
            ApiError::Conflict("a canary with this name already exists".into())
        } else {
            e.into()
        }
    })?;
    let ev = meta.user_event(user.id, "canary.create").target("canary", row.id.to_string());
    audit::record(&mut tx, &ev.details(json!({ "name": name, "kind": req.kind, "secret_id": secret_id }))).await?;
    tx.commit().await?;

    let (value, endpoint, snippet) = match req.kind {
        CanaryKind::Url => {
            let url = canary::url_for(&settings, &token);
            (url.clone(), None, url)
        }
        CanaryKind::ApiKey => {
            let endpoint = settings.endpoint();
            let snippet = format!("SERVICE_API_URL={endpoint}\nSERVICE_API_KEY={}\n", token.as_str());
            (token.as_str().to_owned(), Some(endpoint), snippet)
        }
    };
    Ok((StatusCode::CREATED, Json(CreatedCanary { canary: row, value, endpoint, snippet })))
}

/// One canary with its latest hits.
#[utoipa::path(get, path = "/api/v1/canaries/{id}", tag = "canaries", params(("id" = Uuid, Path)),
    responses((status = 200, body = CanaryDetail), (status = 404, body = Problem, content_type = "application/problem+json")),
    security(("session" = [])))]
pub async fn get(
    State(state): State<AppState>,
    user: CurrentUser,
    ApiPath(id): ApiPath<Uuid>,
) -> ApiResult<Json<CanaryDetail>> {
    user.require(Role::Viewer)?;
    let canary: CanaryOut = sqlx::query_as(&format!("SELECT {COLUMNS} FROM canaries WHERE id = $1"))
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    let hits = sqlx::query_as(
        "SELECT id, at, host(ip) AS ip, method, host, path, user_agent, via FROM canary_hits
         WHERE canary_id = $1 ORDER BY at DESC, id DESC LIMIT 100",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(CanaryDetail { canary, hits }))
}

/// Enable or disable a canary (a disabled one ignores hits), or edit its notes.
#[utoipa::path(patch, path = "/api/v1/canaries/{id}", tag = "canaries", params(("id" = Uuid, Path)), request_body = CanaryUpdate,
    responses((status = 200, body = CanaryOut), (status = 403, body = Problem, content_type = "application/problem+json"),
              (status = 404, body = Problem, content_type = "application/problem+json"), (status = 422, body = Problem, content_type = "application/problem+json")),
    security(("session" = [], "csrf" = [])))]
pub async fn update(
    State(state): State<AppState>,
    meta: RequestMeta,
    user: CurrentUser,
    ApiPath(id): ApiPath<Uuid>,
    ApiJson(req): ApiJson<CanaryUpdate>,
) -> ApiResult<Json<CanaryOut>> {
    user.require(Role::Operator)?;
    let planted_at = req.planted_at.as_ref().map(|v| text("planted_at", v.as_deref(), 500)).transpose()?;
    let memo = req.memo.as_ref().map(|v| text("memo", v.as_deref(), 2000)).transpose()?;
    let mut changed = Vec::new();
    if req.enabled.is_some() {
        changed.push("enabled");
    }
    if planted_at.is_some() {
        changed.push("planted_at");
    }
    if memo.is_some() {
        changed.push("memo");
    }
    let mut tx = state.db.begin().await?;
    let row: CanaryOut = sqlx::query_as(&format!(
        "UPDATE canaries SET enabled = COALESCE($2, enabled),
                planted_at = CASE WHEN $3 THEN $4 ELSE planted_at END,
                memo = CASE WHEN $5 THEN $6 ELSE memo END, updated_at = now()
         WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(req.enabled)
    .bind(planted_at.is_some())
    .bind(planted_at.flatten())
    .bind(memo.is_some())
    .bind(memo.flatten())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    let ev = meta.user_event(user.id, "canary.update").target("canary", id.to_string());
    audit::record(&mut tx, &ev.details(json!({ "name": row.name, "changed": changed, "enabled": row.enabled })))
        .await?;
    tx.commit().await?;
    Ok(Json(row))
}

/// `ANY /_canary`: a request that reached the canary listener. Only the edge may send
/// these (trusted proxy and the canary header); every answer is the same plain 404, so
/// whoever holds the bait learns nothing from it.
pub async fn hit(
    State(state): State<AppState>,
    FromTrustedProxy(trusted): FromTrustedProxy,
    meta: RequestMeta,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let from_edge = trusted && headers.get(CANARY_HEADER).is_some_and(|v| v == "1");
    if let (true, Some(settings)) = (from_edge, state.canary.as_deref()) {
        let target = canary::original_target(&headers, &uri);
        let req = canary::Request { method: &method, target: &target, headers: &headers, ip: meta.ip };
        if let Err(e) = canary::record(&state.db, settings, &req).await {
            tracing::error!(error = %e, "cannot record a canary hit");
        }
    }
    let mut resp = (StatusCode::NOT_FOUND, "Not Found\n").into_response();
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}
