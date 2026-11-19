//! `/api/v1/overview` and `/api/v1/locations` — dashboard numbers and the findings list.

use axum::Json;
use axum::extract::State;

use crate::app::AppState;
use crate::auth::{CurrentUser, Role};
use crate::error::{ApiResult, Problem};
use crate::extract::ApiQuery;
use crate::findings::{self, FindingFilter, FindingOut, Overview};
use crate::pagination::Page;

/// Dashboard: counters, the 30-day violation trend, top exposed and expiring secrets.
#[utoipa::path(get, path = "/api/v1/overview", tag = "overview",
    responses((status = 200, body = Overview), (status = 401, body = Problem, content_type = "application/problem+json")),
    security(("session" = [])))]
pub async fn overview(State(state): State<AppState>, user: CurrentUser) -> ApiResult<Json<Overview>> {
    user.require(Role::Viewer)?;
    let mut conn = state.db.acquire().await?;
    Ok(Json(findings::overview(&mut conn).await?))
}

/// Every location of every secret, newest first sighting first.
#[utoipa::path(get, path = "/api/v1/locations", tag = "overview", params(FindingFilter),
    responses((status = 200, body = Page<FindingOut>), (status = 400, body = Problem, content_type = "application/problem+json"),
              (status = 401, body = Problem, content_type = "application/problem+json")),
    security(("session" = [])))]
pub async fn locations(
    State(state): State<AppState>,
    user: CurrentUser,
    ApiQuery(filter): ApiQuery<FindingFilter>,
) -> ApiResult<Json<Page<FindingOut>>> {
    user.require(Role::Viewer)?;
    let mut conn = state.db.acquire().await?;
    Ok(Json(findings::list(&mut conn, &filter).await?))
}
