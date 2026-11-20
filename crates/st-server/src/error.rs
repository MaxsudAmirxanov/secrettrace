//! API errors rendered as RFC 7807 `application/problem+json`.
//!
//! Client-facing messages never include internal details; internal errors are logged
//! server-side and correlated via the `x-request-id` response header.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    /// 403 with an explanation the caller may see (e.g. a token binding that does not allow
    /// this request). Never put secrets or other users' data in it.
    #[error("forbidden: {0}")]
    Denied(String),
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("unprocessable: {0}")]
    Unprocessable(String),
    #[error("too many requests")]
    TooManyRequests,
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("unsupported media type")]
    UnsupportedMediaType,
    #[error("service unavailable")]
    Unavailable,
    #[error("database error")]
    Database(#[from] sqlx::Error),
    #[error("audit log error")]
    Audit(#[from] crate::audit::AuditError),
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

/// RFC 7807 problem details.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct Problem {
    #[serde(rename = "type")]
    #[schema(example = "urn:secrettrace:problem:not-found")]
    pub kind: &'static str,
    pub title: &'static str,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ApiError {
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden | Self::Denied(_) => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Database(_) | Self::Audit(_) | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    const fn type_and_title(&self) -> (&'static str, &'static str) {
        match self {
            Self::BadRequest(_) => ("urn:secrettrace:problem:bad-request", "Bad request"),
            Self::Unauthorized => ("urn:secrettrace:problem:unauthorized", "Authentication required"),
            Self::Forbidden | Self::Denied(_) => ("urn:secrettrace:problem:forbidden", "Forbidden"),
            Self::NotFound => ("urn:secrettrace:problem:not-found", "Not found"),
            Self::Conflict(_) => ("urn:secrettrace:problem:conflict", "Conflict"),
            Self::Unprocessable(_) => ("urn:secrettrace:problem:validation", "Validation failed"),
            Self::TooManyRequests => ("urn:secrettrace:problem:rate-limited", "Too many requests"),
            Self::PayloadTooLarge => ("urn:secrettrace:problem:payload-too-large", "Payload too large"),
            Self::UnsupportedMediaType => {
                ("urn:secrettrace:problem:unsupported-media-type", "Expected application/json")
            }
            Self::Unavailable => ("urn:secrettrace:problem:unavailable", "Service unavailable"),
            Self::Database(_) | Self::Audit(_) | Self::Internal(_) => {
                ("urn:secrettrace:problem:internal", "Internal server error")
            }
        }
    }

    fn detail(&self) -> Option<String> {
        match self {
            Self::BadRequest(d) | Self::Conflict(d) | Self::Unprocessable(d) | Self::Denied(d) => Some(d.clone()),
            _ => None,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match &self {
            Self::Database(e) => tracing::error!(error = %e, "database error"),
            Self::Audit(e) => tracing::error!(error = %e, "audit log error"),
            Self::Internal(e) => tracing::error!(error = format!("{e:#}"), "internal error"),
            _ => {}
        }
        let status = self.status();
        let (kind, title) = self.type_and_title();
        let problem = Problem { kind, title, status: status.as_u16(), detail: self.detail() };
        problem_response(status, &problem)
    }
}

#[must_use]
pub fn problem_response(status: StatusCode, problem: &Problem) -> Response {
    let mut resp = (status, Json(problem)).into_response();
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/problem+json"));
    resp
}

pub type ApiResult<T> = Result<T, ApiError>;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use http_body_util::BodyExt as _;

    use super::*;

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn renders_problem_json() {
        let resp = ApiError::Conflict("secret already registered".into()).into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert_eq!(resp.headers()[header::CONTENT_TYPE], "application/problem+json");
        let v = body_json(resp).await;
        assert_eq!(v["type"], "urn:secrettrace:problem:conflict");
        assert_eq!(v["status"], 409);
        assert_eq!(v["detail"], "secret already registered");
    }

    #[tokio::test]
    async fn internal_errors_do_not_leak_details() {
        let resp = ApiError::Internal(anyhow::anyhow!("connection to 10.0.0.5 failed: password=x")).into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let v = body_json(resp).await;
        assert!(v.get("detail").is_none());
        assert!(!v.to_string().contains("10.0.0.5"));
    }
}
