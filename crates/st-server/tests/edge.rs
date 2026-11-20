//! Token bindings behind the TLS edge: client-certificate CN from the trusted mTLS proxy,
//! source and environment restrictions. Run with `make test` (needs `DATABASE_URL`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use common::*;
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use sqlx::PgPool;
use st_server::app::{self, AppState, HttpLimits};
use st_server::auth::{AuthSettings, CLIENT_CN_HEADER, Role};
use tower::ServiceExt as _;

const PROXY: [u8; 4] = [172, 30, 0, 10];
const SCOPES: &[&str] = &["ingest:profile", "ingest:match", "ingest:findings"];

/// The app as seen from `peer`, with the mTLS proxy trusted.
fn app_from(state: &AppState, peer: [u8; 4]) -> Router {
    let limits = HttpLimits { request_timeout: std::time::Duration::from_secs(30), max_body_bytes: 64 * 1024 };
    app::router(state.clone(), limits).layer(MockConnectInfo(SocketAddr::from((peer, 40000))))
}

fn edge_state(pool: PgPool, require_client_cert: bool) -> AppState {
    let base = state(pool);
    let auth = AuthSettings { trusted_proxies: vec![IpAddr::from(PROXY)], require_client_cert, ..(*base.auth).clone() };
    AppState { auth: Arc::new(auth), ..base }
}

async fn admin(pool: &PgPool, state: &AppState) -> Client {
    logged_in(pool, &app_from(state, [10, 0, 0, 7]), "admin", Role::Admin).await
}

async fn issue(admin: &mut Client, extra: Value) -> (StatusCode, Value) {
    let mut req = json!({ "name": "ci", "kind": "ci", "scopes": SCOPES, "expires_in_days": 30 });
    req.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    let r = admin.call(Method::POST, "/api/v1/api-tokens", Some(req)).await;
    (r.status, r.body)
}

/// `POST /ingest/scans` with a token and optionally a client-CN header.
async fn start(app: &Router, token: &str, cn: &[&str], body: Value) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/ingest/scans")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json");
    for v in cn {
        req = req.header(CLIENT_CN_HEADER, *v);
    }
    let resp = app.clone().oneshot(req.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn scan(uri: &str) -> Value {
    json!({ "source": { "type": "git_repo", "uri": uri } })
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn cert_bound_token_needs_its_cn_from_the_trusted_proxy(pool: PgPool) {
    let state = edge_state(pool.clone(), false);
    let mut admin = admin(&pool, &state).await;
    let (status, body) = issue(&mut admin, json!({ "cert_cn": "ci-infra" })).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["cert_cn"], "ci-infra");
    let token = body["token"].as_str().unwrap().to_owned();

    let proxy = app_from(&state, PROXY);
    let direct = app_from(&state, [10, 0, 0, 99]);
    let uri = "https://git.example.com/acme/app.git";

    assert_eq!(start(&proxy, &token, &["ci-infra"], scan(uri)).await.0, StatusCode::CREATED);
    // Wrong CN, no CN, a repeated header, a malformed value.
    for cn in [&["ci-other"][..], &[], &["ci-infra", "ci-infra"], &["ci infra"]] {
        assert_eq!(start(&proxy, &token, cn, scan(uri)).await.0, StatusCode::UNAUTHORIZED, "{cn:?}");
    }
    // The header from anyone but the proxy is ignored: a direct client cannot claim a CN.
    assert_eq!(start(&direct, &token, &["ci-infra"], scan(uri)).await.0, StatusCode::UNAUTHORIZED);

    // An unbound token works directly while client certificates are optional.
    let (_, unbound) = issue(&mut admin, json!({})).await;
    assert_eq!(unbound["cert_cn"], Value::Null);
    let unbound = unbound["token"].as_str().unwrap();
    assert_eq!(start(&direct, unbound, &[], scan(uri)).await.0, StatusCode::CREATED);

    let (status, body) = issue(&mut admin, json!({ "cert_cn": "bad cn" })).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn required_client_certs_refuse_unbound_tokens(pool: PgPool) {
    let state = edge_state(pool.clone(), true);
    let mut admin = admin(&pool, &state).await;
    let (status, body) = issue(&mut admin, json!({})).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(body["detail"].as_str().unwrap().contains("cert_cn"));

    // A token issued before enforcement was switched on (no binding) stops working.
    let state_off = edge_state(pool.clone(), false);
    let mut admin_off = Client { app: app_from(&state_off, [10, 0, 0, 7]), ..admin };
    let (_, old) = issue(&mut admin_off, json!({})).await;
    let old = old["token"].as_str().unwrap().to_owned();
    let proxy = app_from(&state, PROXY);
    let uri = "https://git.example.com/acme/app.git";
    assert_eq!(start(&proxy, &old, &["anything"], scan(uri)).await.0, StatusCode::UNAUTHORIZED);
    let used: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT last_used_at FROM api_tokens").fetch_one(&pool).await.unwrap();
    assert!(used.is_none(), "a refused request is not a use of the token");

    let (_, bound) = issue(&mut admin_off, json!({ "cert_cn": "agent-01" })).await;
    let bound = bound["token"].as_str().unwrap();
    assert_eq!(start(&proxy, bound, &["agent-01"], scan(uri)).await.0, StatusCode::CREATED);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn source_and_environment_bindings(pool: PgPool) {
    let state = edge_state(pool.clone(), false);
    let mut admin = admin(&pool, &state).await;
    let (status, body) = issue(
        &mut admin,
        json!({ "source_type": "git_repo", "source_uri_pattern": "https://git.example.com/acme/**", "environment": "ci" }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let token = body["token"].as_str().unwrap().to_owned();
    let app = app_from(&state, [10, 0, 0, 7]);

    let (status, body) = start(&app, &token, &[], scan("https://git.example.com/acme/app.git")).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let env: Option<String> = sqlx::query_scalar("SELECT environment FROM scan_jobs WHERE id = $1::uuid")
        .bind(body["scan_id"].as_str().unwrap())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(env.as_deref(), Some("ci"), "the bound environment is the default");

    let same_env =
        json!({ "source": { "type": "git_repo", "uri": "https://git.example.com/acme/x.git" }, "environment": "ci" });
    assert_eq!(start(&app, &token, &[], same_env).await.0, StatusCode::CREATED);

    let cases = [
        (
            json!({ "source": { "type": "git_repo", "uri": "https://git.example.com/acme/x.git" }, "environment": "prod" }),
            "environment",
        ),
        (scan("https://git.example.com/other/x.git"), "matching"),
        (json!({ "source": { "type": "filesystem", "uri": "https://git.example.com/acme/x" } }), "git_repo"),
    ];
    for (body, why) in cases {
        let (status, problem) = start(&app, &token, &[], body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{problem}");
        assert!(problem["detail"].as_str().unwrap().contains(why), "{problem}");
    }

    let (status, _) = issue(&mut admin, json!({ "environment": "not valid" })).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, _) = issue(&mut admin, json!({ "source_uri_pattern": "a\\" })).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let list = admin.call(Method::GET, "/api/v1/api-tokens", None).await;
    assert_eq!(list.body[0]["environment"], "ci");
    assert_eq!(list.body[0]["source_uri_pattern"], "https://git.example.com/acme/**");
}
