use std::time::Duration;

use axum::Json;
use axum::extract::State;
use serde_json::{Value, json};

use crate::app::AppState;
use crate::error::{ApiError, ApiResult, Problem};

/// Liveness: the process is up and serving.
#[utoipa::path(get, path = "/healthz", tag = "health", responses((status = 200, description = "Alive")))]
pub async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

/// Readiness: dependencies (database) are reachable.
#[utoipa::path(get, path = "/readyz", tag = "health", responses((status = 200, description = "Ready"), (status = 503, body = Problem, content_type = "application/problem+json")))]
pub async fn readyz(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let ping = sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&state.db);
    match tokio::time::timeout(Duration::from_secs(2), ping).await {
        Ok(Ok(_)) => Ok(Json(json!({ "status": "ready" }))),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "readiness check: database unavailable");
            Err(ApiError::Unavailable)
        }
        Err(_) => {
            tracing::warn!("readiness check: database timeout");
            Err(ApiError::Unavailable)
        }
    }
}
