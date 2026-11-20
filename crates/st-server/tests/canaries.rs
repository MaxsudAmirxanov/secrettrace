//! Canary tokens: creation, hits through the edge's canary listener, alerts, bounds.
//! Run with `make test` (needs `DATABASE_URL`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Method, Request, StatusCode};
use base64::Engine as _;
use common::*;
use http_body_util::BodyExt as _;
use secrecy::SecretString;
use serde_json::{Value, json};
use sqlx::PgPool;
use st_core::{SecretType, prepare};
use st_server::app::{self, AppState, HttpLimits};
use st_server::auth::{AuthSettings, Role};
use st_server::canary::CanarySettings;
use tower::ServiceExt as _;

const EDGE: [u8; 4] = [172, 30, 0, 10];
const ADMIN_NET: [u8; 4] = [10, 0, 0, 7];

fn canary_state(pool: PgPool, enabled: bool) -> AppState {
    let base = state(pool);
    let auth = AuthSettings { trusted_proxies: vec![IpAddr::from(EDGE)], ..(*base.auth).clone() };
    let key = SecretString::from(base64::engine::general_purpose::STANDARD.encode([7u8; 32]));
    let settings = enabled.then(|| CanarySettings::new(&key, "https://assets.example.com").unwrap());
    AppState { auth: Arc::new(auth), ..base }.with_canaries(settings)
}

fn app_from(state: &AppState, peer: [u8; 4]) -> Router {
    let limits = HttpLimits { request_timeout: std::time::Duration::from_secs(30), max_body_bytes: 64 * 1024 };
    app::router(state.clone(), limits).layer(MockConnectInfo(SocketAddr::from((peer, 40000))))
}

/// A request as the edge forwards it: `ANY /_canary` with the original target.
async fn knock(app: &Router, target: &str, headers: &[(&str, &str)], canary_header: bool) -> (StatusCode, String) {
    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/_canary")
        .header("x-secrettrace-original-uri", target)
        .header("x-forwarded-for", "203.0.113.9")
        .header("x-forwarded-host", "assets.example.com")
        .header("user-agent", "curl/8.10");
    if canary_header {
        req = req.header("x-secrettrace-canary", "1");
    }
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = app.clone().oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

async fn hits(pool: &PgPool, id: &str) -> (i64, i64) {
    sqlx::query_as("SELECT c.hit_count, (SELECT count(*) FROM canary_hits h WHERE h.canary_id = c.id) FROM canaries c WHERE c.id = $1::uuid")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn create(op: &mut Client, name: &str, kind: &str) -> Value {
    let r = op
        .call(
            Method::POST,
            "/api/v1/canaries",
            Some(json!({ "name": name, "kind": kind, "planted_at": "alice laptop" })),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    r.body
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn url_canary_fires_through_the_edge_only(pool: PgPool) {
    let state = canary_state(pool.clone(), true);
    let mut op = logged_in(&pool, &app_from(&state, ADMIN_NET), "op", Role::Operator).await;
    let created = create(&mut op, "wiki-link", "url").await;
    let url = created["value"].as_str().unwrap();
    assert!(url.starts_with("https://assets.example.com/"), "{url}");
    assert_eq!(created["snippet"], created["value"]);
    assert_eq!(created["canary"]["secret_id"], Value::Null);
    let id = created["canary"]["id"].as_str().unwrap().to_owned();
    let path = url.trim_start_matches("https://assets.example.com");
    let edge = app_from(&state, EDGE);

    // Same answer for a hit and for anything else.
    let miss = knock(&edge, "/images/nothing-here.png", &[], true).await;
    let hit = knock(&edge, &format!("{path}.png?utm=1"), &[], true).await;
    assert_eq!(hit, miss);
    assert_eq!(hit.0, StatusCode::NOT_FOUND);
    assert_eq!(hits(&pool, &id).await, (1, 1));

    let row: (Option<String>, String, String, Option<String>, Option<String>) =
        sqlx::query_as("SELECT host(ip), path, via, host, user_agent FROM canary_hits WHERE canary_id = $1::uuid")
            .bind(&id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row.0.as_deref(), Some("203.0.113.9"), "client address from the edge");
    assert!(row.1.ends_with("{token}.png?utm=1") && !row.1.contains(&id), "token masked: {}", row.1);
    assert_eq!(
        (row.2.as_str(), row.3.as_deref(), row.4.as_deref()),
        ("path", Some("assets.example.com"), Some("curl/8.10"))
    );

    // Not from the edge, or without the canary header: ignored.
    knock(&app_from(&state, [10, 0, 0, 99]), path, &[], true).await;
    knock(&edge, path, &[], false).await;
    assert_eq!(hits(&pool, &id).await, (1, 1));

    // One open alert per canary, bumped on every hit.
    knock(&edge, path, &[], true).await;
    let alert: (String, String, i32, Value) =
        sqlx::query_as("SELECT rule, severity::text, occurrences, context FROM alerts WHERE dedup_key = $1")
            .bind(format!("canary:{id}"))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!((alert.0.as_str(), alert.1.as_str(), alert.2), ("canary.triggered", "critical", 2));
    assert_eq!(alert.3["name"], "wiki-link");
    assert!(!alert.3.to_string().contains(path.rsplit('/').next().unwrap()), "no token in the alert");

    // Disabled canaries ignore hits.
    let r = op.call(Method::PATCH, &format!("/api/v1/canaries/{id}"), Some(json!({ "enabled": false }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    knock(&edge, path, &[], true).await;
    assert_eq!(hits(&pool, &id).await.0, 2);

    let detail = op.call(Method::GET, &format!("/api/v1/canaries/{id}"), None).await;
    assert_eq!(detail.body["hits"].as_array().unwrap().len(), 2);
    assert_eq!(detail.body["planted_at"], "alice laptop");
    let actions = audit_actions(&pool).await;
    assert!(actions.contains(&"canary.create".to_owned()) && actions.contains(&"canary.update".to_owned()));
    let audit: Vec<Value> = sqlx::query_scalar("SELECT details FROM audit_log").fetch_all(&pool).await.unwrap();
    let token = path.rsplit('/').next().unwrap();
    assert!(audit.iter().all(|d| !d.to_string().contains(token)), "the token never reaches the audit log");
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn api_key_canary_fires_on_use_and_is_a_registered_secret(pool: PgPool) {
    let state = canary_state(pool.clone(), true);
    let mut op = logged_in(&pool, &app_from(&state, ADMIN_NET), "op", Role::Operator).await;
    let created = create(&mut op, "deploy-env", "api_key").await;
    let key = created["value"].as_str().unwrap().to_owned();
    assert!(key.starts_with("ak_") && key.len() == 43, "{key}");
    assert_eq!(created["endpoint"], "https://assets.example.com/v1");
    assert!(created["snippet"].as_str().unwrap().contains(&format!("SERVICE_API_KEY={key}")));
    let id = created["canary"]["id"].as_str().unwrap().to_owned();
    let edge = app_from(&state, EDGE);

    let basic = base64::engine::general_purpose::STANDARD.encode(format!("x:{key}"));
    for headers in [
        vec![("authorization", format!("Bearer {key}"))],
        vec![("x-api-key", key.clone())],
        vec![("authorization", format!("Basic {basic}"))],
    ] {
        let h: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        knock(&edge, "/v1/charges", &h, true).await;
    }
    knock(&edge, &format!("/v1/users?api_key={key}"), &[], true).await;
    assert_eq!(hits(&pool, &id).await, (4, 4));
    let vias: Vec<String> =
        sqlx::query_scalar("SELECT via FROM canary_hits ORDER BY id").fetch_all(&pool).await.unwrap();
    assert_eq!(vias, ["bearer", "header", "basic", "query"]);

    // Registered: a scan that finds the key anywhere matches it.
    let secret: (String, String) = sqlx::query_as("SELECT name, owner FROM secrets WHERE id = $1::uuid")
        .bind(created["canary"]["secret_id"].as_str().unwrap())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(secret, ("canary: deploy-env".to_owned(), "canary".to_owned()));
    let (digest, _) = prepare(SecretType::ApiKey, &key).unwrap();
    let (_, fingerprint) = state.pepper.fingerprint_current(&digest);
    let matched: i64 = sqlx::query_scalar("SELECT count(*) FROM secrets WHERE fingerprint = $1")
        .bind(fingerprint.as_bytes().as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(matched, 1, "the key's fingerprint is in the registry");
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn stored_hits_are_bounded_and_roles_apply(pool: PgPool) {
    let state = canary_state(pool.clone(), true);
    let app = app_from(&state, ADMIN_NET);
    let mut op = logged_in(&pool, &app, "op", Role::Operator).await;
    let created = create(&mut op, "flood", "url").await;
    let id = created["canary"]["id"].as_str().unwrap().to_owned();
    let path = created["value"].as_str().unwrap().trim_start_matches("https://assets.example.com").to_owned();
    let edge = app_from(&state, EDGE);
    for _ in 0..15 {
        knock(&edge, &path, &[], true).await;
    }
    assert_eq!(hits(&pool, &id).await, (15, 10), "the counter counts, storage stops at 10 a minute");

    let mut viewer = logged_in(&pool, &app, "viewer", Role::Viewer).await;
    assert_eq!(viewer.call(Method::GET, "/api/v1/canaries", None).await.status, StatusCode::OK);
    let r = viewer.call(Method::POST, "/api/v1/canaries", Some(json!({ "name": "x", "kind": "url" }))).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let dup = op.call(Method::POST, "/api/v1/canaries", Some(json!({ "name": "flood", "kind": "url" }))).await;
    assert_eq!(dup.status, StatusCode::CONFLICT);
    let bad = op.call(Method::POST, "/api/v1/canaries", Some(json!({ "name": " ", "kind": "url" }))).await;
    assert_eq!(bad.status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn without_configuration_canaries_are_off(pool: PgPool) {
    let state = canary_state(pool.clone(), false);
    let mut op = logged_in(&pool, &app_from(&state, ADMIN_NET), "op", Role::Operator).await;
    let r = op.call(Method::POST, "/api/v1/canaries", Some(json!({ "name": "x", "kind": "url" }))).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert!(r.body["detail"].as_str().unwrap().contains("ST_CANARY_KEY"));
    let (status, _) = knock(&app_from(&state, EDGE), "/s/abcdefghijklmnopqrstuvwxyz", &[], true).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
