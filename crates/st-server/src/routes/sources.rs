//! `/api/v1/sources` — what the system scans. Viewers read, operators write.

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::extract::rejection::BytesRejection;
use axum::http::{HeaderMap, StatusCode, header};
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::{CurrentUser, RequestMeta, Role};
use crate::error::{ApiError, ApiResult, Problem};
use crate::extract::{ApiJson, ApiPath, ApiQuery};
use crate::pagination::Page;
use crate::sources::{self, ScanOut, ScanRequest, SourceCreate, SourceFilter, SourceOut, SourceUpdate};

/// List sources, newest first.
#[utoipa::path(
    get, path = "/api/v1/sources", tag = "sources",
    params(SourceFilter),
    responses(
        (status = 200, body = Page<SourceOut>),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
    ),
    security(("session" = []))
)]
pub async fn list(
    State(state): State<AppState>,
    user: CurrentUser,
    ApiQuery(filter): ApiQuery<SourceFilter>,
) -> ApiResult<Json<Page<SourceOut>>> {
    user.require(Role::Viewer)?;
    let mut conn = state.db.acquire().await?;
    Ok(Json(sources::list(&mut conn, &filter).await?))
}

/// Create a source. Credentials are referenced by name (`credential_ref`), never sent.
#[utoipa::path(
    post, path = "/api/v1/sources", tag = "sources",
    request_body = SourceCreate,
    responses(
        (status = 201, body = SourceOut),
        (status = 403, body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Name or (type, uri) already exists", body = Problem, content_type = "application/problem+json"),
        (status = 422, body = Problem, content_type = "application/problem+json"),
    ),
    security(("session" = [], "csrf" = []))
)]
pub async fn create(
    State(state): State<AppState>,
    meta: RequestMeta,
    user: CurrentUser,
    ApiJson(req): ApiJson<SourceCreate>,
) -> ApiResult<(StatusCode, Json<SourceOut>)> {
    user.require(Role::Operator)?;
    let mut tx = state.db.begin().await?;
    let out = sources::create(&mut tx, &req, meta.user_event(user.id, "source.create")).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(out)))
}

/// Get one source.
#[utoipa::path(
    get, path = "/api/v1/sources/{id}", tag = "sources",
    params(("id" = Uuid, Path)),
    responses((status = 200, body = SourceOut), (status = 404, body = Problem, content_type = "application/problem+json")),
    security(("session" = []))
)]
pub async fn get(
    State(state): State<AppState>,
    user: CurrentUser,
    ApiPath(id): ApiPath<Uuid>,
) -> ApiResult<Json<SourceOut>> {
    user.require(Role::Viewer)?;
    let mut conn = state.db.acquire().await?;
    sources::get(&mut conn, id).await?.map(Json).ok_or(ApiError::NotFound)
}

/// Update a source. `type` and `uri` are immutable; disabling cancels its active scan.
#[utoipa::path(
    patch, path = "/api/v1/sources/{id}", tag = "sources",
    params(("id" = Uuid, Path)),
    request_body = SourceUpdate,
    responses(
        (status = 200, body = SourceOut),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Name already exists", body = Problem, content_type = "application/problem+json"),
        (status = 422, body = Problem, content_type = "application/problem+json"),
    ),
    security(("session" = [], "csrf" = []))
)]
pub async fn update(
    State(state): State<AppState>,
    meta: RequestMeta,
    user: CurrentUser,
    ApiPath(id): ApiPath<Uuid>,
    ApiJson(req): ApiJson<SourceUpdate>,
) -> ApiResult<Json<SourceOut>> {
    user.require(Role::Operator)?;
    let mut tx = state.db.begin().await?;
    let out = sources::update(&mut tx, id, &req, meta.user_event(user.id, "source.update")).await?;
    tx.commit().await?;
    Ok(Json(out))
}

/// Delete a source; its active scan is cancelled, found locations are kept.
#[utoipa::path(
    delete, path = "/api/v1/sources/{id}", tag = "sources",
    params(("id" = Uuid, Path)),
    responses(
        (status = 204, description = "Deleted"),
        (status = 403, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    ),
    security(("session" = [], "csrf" = []))
)]
pub async fn delete(
    State(state): State<AppState>,
    meta: RequestMeta,
    user: CurrentUser,
    ApiPath(id): ApiPath<Uuid>,
) -> ApiResult<StatusCode> {
    user.require(Role::Operator)?;
    let mut tx = state.db.begin().await?;
    sources::delete(&mut tx, id, meta.user_event(user.id, "source.delete")).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// An optional JSON body: empty (with or without `Content-Type`) means `T::default()`.
/// A non-empty body must be a JSON object and is parsed like `ApiJson` (415 / 400 / 422,
/// input redacted).
fn optional_json<T: serde::de::DeserializeOwned + Default>(
    headers: &HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<T, ApiError> {
    let body = body.map_err(|e| {
        if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::PayloadTooLarge
        } else {
            ApiError::BadRequest("cannot read request body".into())
        }
    })?;
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(T::default());
    }
    let is_json =
        headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).and_then(|v| v.split(';').next()).is_some_and(
            |m| {
                let m = m.trim().to_ascii_lowercase();
                m == "application/json" || (m.starts_with("application/") && m.ends_with("+json"))
            },
        );
    if !is_json {
        return Err(ApiError::UnsupportedMediaType);
    }
    // serde also accepts a struct as a sequence (`[]`, `[true]`); only objects are meant.
    if !Json::<serde_json::Value>::from_bytes(&body)?.0.is_object() {
        return Err(ApiError::Unprocessable("request body must be a JSON object".into()));
    }
    Ok(Json::<T>::from_bytes(&body)?.0)
}

/// Queue a server-side scan of a git repository source. Optional body `{"full": true}`
/// rescans the whole history instead of only what is new since the last scan.
#[utoipa::path(
    post, path = "/api/v1/sources/{id}/scans", tag = "sources",
    params(("id" = Uuid, Path)),
    request_body(content = Option<ScanRequest>, description = "Optional; empty body means `{\"full\": false}`"),
    responses(
        (status = 202, body = ScanOut),
        (status = 403, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Source disabled, or a scan is already queued or running", body = Problem, content_type = "application/problem+json"),
        (status = 415, description = "Non-empty body that is not JSON", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Not a git_repo source, or invalid body", body = Problem, content_type = "application/problem+json"),
    ),
    security(("session" = [], "csrf" = []))
)]
pub async fn enqueue_scan(
    State(state): State<AppState>,
    meta: RequestMeta,
    user: CurrentUser,
    ApiPath(id): ApiPath<Uuid>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> ApiResult<(StatusCode, Json<ScanOut>)> {
    user.require(Role::Operator)?;
    let req: ScanRequest = optional_json(&headers, body)?;
    let mut tx = state.db.begin().await?;
    let out = sources::enqueue(&mut tx, id, user.id, &req, meta.user_event(user.id, "scan.enqueue")).await?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(out)))
}
