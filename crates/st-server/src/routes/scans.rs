//! `/api/v1/scans` — scan jobs: server-side (manual, scheduled) and reported by tokens.

use axum::Json;
use axum::extract::State;
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::{CurrentUser, RequestMeta, Role};
use crate::error::{ApiError, ApiResult, Problem};
use crate::extract::{ApiPath, ApiQuery};
use crate::pagination::Page;
use crate::sources::{self, ScanFilter, ScanOut};

/// List scans, newest first.
#[utoipa::path(
    get, path = "/api/v1/scans", tag = "scans",
    params(ScanFilter),
    responses(
        (status = 200, body = Page<ScanOut>),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
    ),
    security(("session" = []))
)]
pub async fn list(
    State(state): State<AppState>,
    user: CurrentUser,
    ApiQuery(filter): ApiQuery<ScanFilter>,
) -> ApiResult<Json<Page<ScanOut>>> {
    user.require(Role::Viewer)?;
    let mut conn = state.db.acquire().await?;
    Ok(Json(sources::list_scans(&mut conn, &filter).await?))
}

/// Get one scan.
#[utoipa::path(
    get, path = "/api/v1/scans/{id}", tag = "scans",
    params(("id" = Uuid, Path)),
    responses((status = 200, body = ScanOut), (status = 404, body = Problem, content_type = "application/problem+json")),
    security(("session" = []))
)]
pub async fn get(
    State(state): State<AppState>,
    user: CurrentUser,
    ApiPath(id): ApiPath<Uuid>,
) -> ApiResult<Json<ScanOut>> {
    user.require(Role::Viewer)?;
    let mut conn = state.db.acquire().await?;
    sources::get_scan(&mut conn, id).await?.map(Json).ok_or(ApiError::NotFound)
}

/// Cancel a queued or running server-side scan.
#[utoipa::path(
    post, path = "/api/v1/scans/{id}/cancel", tag = "scans",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, body = ScanOut),
        (status = 403, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Finished, or reported by an API token", body = Problem, content_type = "application/problem+json"),
    ),
    security(("session" = [], "csrf" = []))
)]
pub async fn cancel(
    State(state): State<AppState>,
    meta: RequestMeta,
    user: CurrentUser,
    ApiPath(id): ApiPath<Uuid>,
) -> ApiResult<Json<ScanOut>> {
    user.require(Role::Operator)?;
    let mut tx = state.db.begin().await?;
    let out = sources::cancel(&mut tx, id, meta.user_event(user.id, "scan.cancel")).await?;
    tx.commit().await?;
    Ok(Json(out))
}
