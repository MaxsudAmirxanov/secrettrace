//! Router and middleware stack.

use std::any::Any;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{DefaultBodyLimit, Request};
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::Response;
use axum::routing::{delete, get, post};
use sqlx::PgPool;
use tower::ServiceBuilder;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tracing::Level;

use crate::auth::AuthSettings;
use crate::auth::ratelimit::AuthLimiters;
use crate::crypto::{DataKey, Pepper};
use crate::error::{ApiError, Problem, problem_response};
use crate::routes;

static REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

#[derive(Clone, Debug)]
pub struct AppState {
    pub db: PgPool,
    pub pepper: Arc<Pepper>,
    pub data_key: Arc<DataKey>,
    pub auth: Arc<AuthSettings>,
    pub limiters: Arc<AuthLimiters>,
}

impl AppState {
    #[must_use]
    pub fn new(db: PgPool, pepper: Pepper, data_key: DataKey, auth: AuthSettings) -> Self {
        Self {
            db,
            pepper: Arc::new(pepper),
            data_key: Arc::new(data_key),
            auth: Arc::new(auth),
            limiters: Arc::new(AuthLimiters::default()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HttpLimits {
    pub request_timeout: Duration,
    pub max_body_bytes: usize,
}

pub fn router(state: AppState, limits: HttpLimits) -> Router {
    let api_v1 = Router::new()
        .route("/auth/login", post(routes::auth::login))
        .route("/auth/mfa/enroll", post(routes::auth::mfa_enroll))
        .route("/auth/mfa/verify", post(routes::auth::mfa_verify))
        .route("/auth/logout", post(routes::auth::logout))
        .route("/auth/me", get(routes::auth::me))
        .route("/api-tokens", get(routes::api_tokens::list).post(routes::api_tokens::create))
        .route("/api-tokens/{id}", delete(routes::api_tokens::revoke))
        .route("/secrets", get(routes::secrets::list).post(routes::secrets::create))
        .route("/secrets/{id}", get(routes::secrets::get).patch(routes::secrets::update))
        .route("/secrets/{id}/locations", get(routes::secrets::locations))
        .route("/openapi.json", get(openapi_json));

    Router::new()
        .route("/healthz", get(routes::health::healthz))
        .route("/readyz", get(routes::health::readyz))
        .nest("/api/v1", api_v1)
        .fallback(|| async { ApiError::NotFound })
        .with_state(state)
        .layer(
            // Listed outermost → innermost.
            ServiceBuilder::new()
                .layer(SetRequestIdLayer::new(REQUEST_ID.clone(), MakeRequestUuid))
                .layer(
                    TraceLayer::new_for_http()
                        // Path only: query strings and headers are never logged.
                        .make_span_with(|req: &Request| {
                            let request_id =
                                req.headers().get(&REQUEST_ID).and_then(|v| v.to_str().ok()).unwrap_or_default();
                            tracing::info_span!(
                                "http",
                                method = %req.method(),
                                path = %req.uri().path(),
                                request_id = %request_id,
                            )
                        })
                        .on_request(())
                        .on_response(DefaultOnResponse::new().level(Level::INFO)),
                )
                .layer(PropagateRequestIdLayer::new(REQUEST_ID.clone()))
                .layer(SetResponseHeaderLayer::overriding(
                    header::X_CONTENT_TYPE_OPTIONS,
                    HeaderValue::from_static("nosniff"),
                ))
                .layer(SetResponseHeaderLayer::if_not_present(
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("no-store"),
                ))
                .layer(CatchPanicLayer::custom(panic_response))
                .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, limits.request_timeout)),
        )
        // Enforced by body extractors (Json, Bytes…) before any parsing.
        .layer(DefaultBodyLimit::max(limits.max_body_bytes))
}

async fn openapi_json() -> impl axum::response::IntoResponse {
    ([(header::CONTENT_TYPE, "application/json")], crate::openapi::json())
}

fn panic_response(_payload: Box<dyn Any + Send + 'static>) -> Response {
    // The payload may contain arbitrary data; do not log or echo it.
    tracing::error!("handler panicked");
    problem_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        &Problem {
            kind: "urn:secrettrace:problem:internal",
            title: "Internal server error",
            status: 500,
            detail: None,
        },
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use axum::body::Body;
    use secrecy::SecretString;
    use tower::ServiceExt as _;

    use super::*;

    fn test_app() -> Router {
        // Lazy pool to an unroutable address: no DB needed, readyz must report 503.
        let db = crate::db::connect_lazy(&SecretString::from("postgres://x:y@127.0.0.1:1/none"), 1).unwrap();
        let pepper = Pepper::parse(&SecretString::from(format!("1:{}", "A".repeat(44))), None).unwrap();
        let data_key = DataKey::parse(&SecretString::from("A".repeat(43) + "=")).unwrap();
        let auth = AuthSettings {
            session_ttl: Duration::from_secs(3600),
            session_idle: Duration::from_secs(600),
            cookie_secure: false,
            totp_issuer: "SecretTrace".into(),
            trusted_proxies: vec![],
        };
        router(
            AppState::new(db, pepper, data_key, auth),
            HttpLimits { request_timeout: Duration::from_secs(10), max_body_bytes: 1024 },
        )
    }

    #[tokio::test]
    async fn healthz_ok_with_security_headers_and_request_id() {
        let resp = test_app().oneshot(Request::get("/healthz").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["x-content-type-options"], "nosniff");
        assert_eq!(resp.headers()["cache-control"], "no-store");
        assert!(resp.headers().contains_key("x-request-id"));
    }

    #[tokio::test]
    async fn readyz_reports_unavailable_without_db() {
        let resp = test_app().oneshot(Request::get("/readyz").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(resp.headers()["content-type"], "application/problem+json");
    }

    #[tokio::test]
    async fn unknown_route_is_problem_404() {
        let resp = test_app().oneshot(Request::get("/nope").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(resp.headers()["content-type"], "application/problem+json");
    }

    #[tokio::test]
    async fn incoming_request_id_is_propagated() {
        let resp = test_app()
            .oneshot(Request::get("/healthz").header("x-request-id", "abc-123").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.headers()["x-request-id"], "abc-123");
    }
}
