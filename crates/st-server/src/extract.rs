//! Extractors whose rejections are RFC 7807 problems instead of axum's plain text.

use axum::extract::FromRequest;
use axum::extract::FromRequestParts;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};

use crate::error::ApiError;

/// JSON body. Malformed JSON → 400, schema violations → 422, oversized → 413.
#[derive(Debug, FromRequest)]
#[from_request(via(axum::Json), rejection(ApiError))]
pub struct ApiJson<T>(pub T);

#[derive(Debug, FromRequestParts)]
#[from_request(via(axum::extract::Query), rejection(ApiError))]
pub struct ApiQuery<T>(pub T);

#[derive(Debug, FromRequestParts)]
#[from_request(via(axum::extract::Path), rejection(ApiError))]
pub struct ApiPath<T>(pub T);

impl From<JsonRejection> for ApiError {
    fn from(r: JsonRejection) -> Self {
        match r {
            // serde messages name fields and expected types; they never echo our secrets
            // (digests fail with a fixed message, SecretString fields are opaque).
            JsonRejection::JsonDataError(e) => Self::Unprocessable(e.body_text()),
            JsonRejection::JsonSyntaxError(_) => Self::BadRequest("request body is not valid JSON".into()),
            JsonRejection::MissingJsonContentType(_) => Self::UnsupportedMediaType,
            JsonRejection::BytesRejection(e) if e.status() == axum::http::StatusCode::PAYLOAD_TOO_LARGE => {
                Self::PayloadTooLarge
            }
            other => Self::BadRequest(other.body_text()),
        }
    }
}

impl From<QueryRejection> for ApiError {
    fn from(r: QueryRejection) -> Self {
        Self::BadRequest(r.body_text())
    }
}

impl From<PathRejection> for ApiError {
    fn from(_: PathRejection) -> Self {
        Self::NotFound
    }
}
