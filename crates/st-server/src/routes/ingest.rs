//! `/api/v1/ingest/scans` — scan results from agents and CI, API tokens only.
//!
//! Request bodies are never logged (the HTTP trace records method and path only).

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use uuid::Uuid;

use crate::app::AppState;
use crate::audit::ActorType;
use crate::auth::{RequestMeta, TokenPrincipal};
use crate::error::{ApiResult, Problem};
use crate::extract::{ApiJson, ApiPath};
use crate::ingest::{
    self, FindingsRequest, FindingsResponse, MatchRequest, MatchResponse, ScanComplete, ScanCompleted, ScanStart,
    ScanStarted,
};

fn event(meta: &RequestMeta, principal: &TokenPrincipal, action: &str) -> crate::audit::AuditEvent {
    meta.event(ActorType::Token, principal.id.to_string(), action)
}

/// Start a scan of a source (found or created by type and URI). Scope `ingest:profile`.
#[utoipa::path(
    post, path = "/api/v1/ingest/scans", tag = "ingest",
    request_body = ScanStart,
    responses(
        (status = 201, body = ScanStarted),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Token lacks ingest:profile", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Source is disabled", body = Problem, content_type = "application/problem+json"),
        (status = 422, body = Problem, content_type = "application/problem+json"),
    ),
    security(("token" = []))
)]
pub async fn start(
    State(state): State<AppState>,
    meta: RequestMeta,
    principal: TokenPrincipal,
    ApiJson(req): ApiJson<ScanStart>,
) -> ApiResult<(StatusCode, Json<ScanStarted>)> {
    principal.require_scope("ingest:profile")?;
    let mut tx = state.db.begin().await?;
    let out =
        ingest::start(&mut tx, &principal, &state.ingest, &req, event(&meta, &principal, "ingest.scan_start")).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(out)))
}

/// Which of the submitted digests are registered. Rate-limited per token by unique
/// digests; only counts are audited. Scope `ingest:match`.
#[utoipa::path(
    post, path = "/api/v1/ingest/scans/{id}/match", tag = "ingest",
    params(("id" = Uuid, Path, description = "Scan id")),
    request_body = MatchRequest,
    responses(
        (status = 200, body = MatchResponse),
        (status = 403, body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "No such scan for this token", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Scan is not running", body = Problem, content_type = "application/problem+json"),
        (status = 422, body = Problem, content_type = "application/problem+json"),
        (status = 429, body = Problem, content_type = "application/problem+json"),
    ),
    security(("token" = []))
)]
pub async fn match_digests(
    State(state): State<AppState>,
    meta: RequestMeta,
    principal: TokenPrincipal,
    ApiPath(id): ApiPath<Uuid>,
    ApiJson(req): ApiJson<MatchRequest>,
) -> ApiResult<Json<MatchResponse>> {
    principal.require_scope("ingest:match")?;
    let mut tx = state.db.begin().await?;
    let out = ingest::match_digests(
        &mut tx,
        &state.pepper,
        &state.ingest,
        &principal,
        id,
        &req,
        event(&meta, &principal, "ingest.match"),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(out))
}

/// Report locations of matched candidates. Digests are matched again; unregistered ones
/// are counted and dropped. Scope `ingest:findings`.
#[utoipa::path(
    post, path = "/api/v1/ingest/scans/{id}/findings", tag = "ingest",
    params(("id" = Uuid, Path, description = "Scan id")),
    request_body = FindingsRequest,
    responses(
        (status = 200, body = FindingsResponse),
        (status = 403, body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "No such scan for this token", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Scan is not running", body = Problem, content_type = "application/problem+json"),
        (status = 422, body = Problem, content_type = "application/problem+json"),
    ),
    security(("token" = []))
)]
pub async fn findings(
    State(state): State<AppState>,
    meta: RequestMeta,
    principal: TokenPrincipal,
    ApiPath(id): ApiPath<Uuid>,
    ApiJson(req): ApiJson<FindingsRequest>,
) -> ApiResult<Json<FindingsResponse>> {
    principal.require_scope("ingest:findings")?;
    let mut tx = state.db.begin().await?;
    let out = ingest::findings(
        &mut tx,
        &state.pepper,
        &state.ingest,
        &principal,
        id,
        &req,
        event(&meta, &principal, "ingest.findings"),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(out))
}

/// Finish a scan. A successful full scan marks the source's unreported locations as no
/// longer present. Scope `ingest:profile`.
#[utoipa::path(
    post, path = "/api/v1/ingest/scans/{id}/complete", tag = "ingest",
    params(("id" = Uuid, Path, description = "Scan id")),
    request_body = ScanComplete,
    responses(
        (status = 200, body = ScanCompleted),
        (status = 403, body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "No such scan for this token", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Scan is not running", body = Problem, content_type = "application/problem+json"),
        (status = 422, body = Problem, content_type = "application/problem+json"),
    ),
    security(("token" = []))
)]
pub async fn complete(
    State(state): State<AppState>,
    meta: RequestMeta,
    principal: TokenPrincipal,
    ApiPath(id): ApiPath<Uuid>,
    ApiJson(req): ApiJson<ScanComplete>,
) -> ApiResult<Json<ScanCompleted>> {
    principal.require_scope("ingest:profile")?;
    let mut tx = state.db.begin().await?;
    let out = ingest::complete(&mut tx, &principal, id, &req, event(&meta, &principal, "ingest.scan_complete")).await?;
    tx.commit().await?;
    Ok(Json(out))
}
