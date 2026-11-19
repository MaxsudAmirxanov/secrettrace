//! `/api/v1/secrets` — the registry. Viewers read, operators write.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::{CurrentUser, RequestMeta, Role};
use crate::error::{ApiError, ApiResult, Problem};
use crate::extract::{ApiJson, ApiPath, ApiQuery};
use crate::pagination::Page;
use crate::registry::{self, LocationFilter, LocationOut, SecretCreate, SecretFilter, SecretOut, SecretUpdate};

/// List registered secrets.
#[utoipa::path(
    get, path = "/api/v1/secrets", tag = "secrets",
    params(SecretFilter),
    responses(
        (status = 200, body = Page<SecretOut>),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
    ),
    security(("session" = []))
)]
pub async fn list(
    State(state): State<AppState>,
    user: CurrentUser,
    ApiQuery(filter): ApiQuery<SecretFilter>,
) -> ApiResult<Json<Page<SecretOut>>> {
    user.require(Role::Viewer)?;
    let mut conn = state.db.acquire().await?;
    Ok(Json(registry::list(&mut conn, &filter).await?))
}

/// Register a secret by its client-side digest.
#[utoipa::path(
    post, path = "/api/v1/secrets", tag = "secrets",
    request_body = SecretCreate,
    responses(
        (status = 201, body = SecretOut),
        (status = 403, body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Name taken or value already registered", body = Problem, content_type = "application/problem+json"),
        (status = 422, body = Problem, content_type = "application/problem+json"),
    ),
    security(("session" = [], "csrf" = []))
)]
pub async fn create(
    State(state): State<AppState>,
    meta: RequestMeta,
    user: CurrentUser,
    ApiJson(req): ApiJson<SecretCreate>,
) -> ApiResult<(StatusCode, Json<SecretOut>)> {
    user.require(Role::Operator)?;
    let mut tx = state.db.begin().await?;
    let out =
        registry::create(&mut tx, &state.pepper, &req, user.id, meta.user_event(user.id, "secret.create")).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(out)))
}

/// Get one secret.
#[utoipa::path(
    get, path = "/api/v1/secrets/{id}", tag = "secrets",
    params(("id" = Uuid, Path)),
    responses((status = 200, body = SecretOut), (status = 404, body = Problem, content_type = "application/problem+json")),
    security(("session" = []))
)]
pub async fn get(
    State(state): State<AppState>,
    user: CurrentUser,
    ApiPath(id): ApiPath<Uuid>,
) -> ApiResult<Json<SecretOut>> {
    user.require(Role::Viewer)?;
    let mut conn = state.db.acquire().await?;
    registry::get(&mut conn, id).await?.map(Json).ok_or(ApiError::NotFound)
}

/// Update metadata, status, expiry or allow-rules. Revoked/rotated secrets cannot be reactivated.
#[utoipa::path(
    patch, path = "/api/v1/secrets/{id}", tag = "secrets",
    params(("id" = Uuid, Path)),
    request_body = SecretUpdate,
    responses(
        (status = 200, body = SecretOut),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Status transition not allowed", body = Problem, content_type = "application/problem+json"),
        (status = 422, body = Problem, content_type = "application/problem+json"),
    ),
    security(("session" = [], "csrf" = []))
)]
pub async fn update(
    State(state): State<AppState>,
    meta: RequestMeta,
    user: CurrentUser,
    ApiPath(id): ApiPath<Uuid>,
    ApiJson(req): ApiJson<SecretUpdate>,
) -> ApiResult<Json<SecretOut>> {
    user.require(Role::Operator)?;
    let mut tx = state.db.begin().await?;
    let out = registry::update(&mut tx, id, &req, meta.user_event(user.id, "secret.update")).await?;
    tx.commit().await?;
    Ok(Json(out))
}

/// Where the secret has been found.
#[utoipa::path(
    get, path = "/api/v1/secrets/{id}/locations", tag = "secrets",
    params(("id" = Uuid, Path), LocationFilter),
    responses((status = 200, body = Page<LocationOut>), (status = 404, body = Problem, content_type = "application/problem+json")),
    security(("session" = []))
)]
pub async fn locations(
    State(state): State<AppState>,
    user: CurrentUser,
    ApiPath(id): ApiPath<Uuid>,
    ApiQuery(filter): ApiQuery<LocationFilter>,
) -> ApiResult<Json<Page<LocationOut>>> {
    user.require(Role::Viewer)?;
    let mut conn = state.db.acquire().await?;
    Ok(Json(registry::list_locations(&mut conn, id, &filter).await?))
}
