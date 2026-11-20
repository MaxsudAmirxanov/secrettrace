//! Shared helpers for integration tests: app wiring, a cookie-keeping client, TOTP login.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]

use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use base64::Engine as _;
use http_body_util::BodyExt as _;
use secrecy::SecretString;
use serde_json::{Value, json};
use sqlx::PgPool;
use st_server::app::{self, AppState, HttpLimits};
use st_server::audit::AuditEvent;
use st_server::auth::{AuthSettings, Role, totp};
use st_server::crypto::{DataKey, Pepper};
use st_server::users;
use tower::ServiceExt as _;
use zeroize::Zeroizing;

pub const PASSWORD: &str = "correct horse battery staple";

pub fn state(pool: PgPool) -> AppState {
    let b64 = base64::engine::general_purpose::STANDARD;
    let pepper = Pepper::parse(&SecretString::from(format!("1:{}", b64.encode([1u8; 32]))), None).unwrap();
    let data_key = DataKey::parse(&SecretString::from(b64.encode([2u8; 32]))).unwrap();
    let auth = AuthSettings {
        session_ttl: Duration::from_secs(3600),
        session_idle: Duration::from_secs(600),
        cookie_secure: false,
        totp_issuer: "SecretTrace".into(),
        trusted_proxies: vec![],
        require_client_cert: false,
    };
    AppState::new(pool, pepper, data_key, auth)
}

pub fn router(state: AppState) -> Router {
    let limits = HttpLimits { request_timeout: Duration::from_secs(30), max_body_bytes: 64 * 1024 };
    app::router(state, limits).layer(MockConnectInfo(SocketAddr::from(([10, 0, 0, 7], 40000))))
}

pub async fn create_user(pool: &PgPool, username: &str, role: Role) {
    let mut tx = pool.begin().await.unwrap();
    users::create(&mut tx, username, Zeroizing::new(PASSWORD.into()), role, AuditEvent::system("user.create"))
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

/// Minimal browser: keeps the session cookie and CSRF token between requests.
pub struct Client {
    pub app: Router,
    pub cookie: Option<String>,
    pub csrf: Option<String>,
}

pub struct Resp {
    pub status: StatusCode,
    pub body: Value,
    pub headers: HeaderMap,
}

impl Client {
    pub fn new(app: &Router) -> Self {
        Self { app: app.clone(), cookie: None, csrf: None }
    }

    pub async fn call(&mut self, method: Method, path: &str, body: Option<Value>) -> Resp {
        let mut req = Request::builder().method(method).uri(path);
        if let Some(c) = &self.cookie {
            req = req.header(header::COOKIE, format!("st_session={c}"));
        }
        if let Some(t) = &self.csrf {
            req = req.header("x-csrf-token", t);
        }
        let req = match body {
            Some(b) => req.header(header::CONTENT_TYPE, "application/json").body(Body::from(b.to_string())),
            None => req.body(Body::empty()),
        }
        .unwrap();

        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        if let Some(set) = headers.get(header::SET_COOKIE).and_then(|v| v.to_str().ok()) {
            let value = set.split(';').next().and_then(|kv| kv.split_once('=')).map(|(_, v)| v.to_owned());
            self.cookie = value.filter(|v| !v.is_empty());
        }
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        if let Some(t) = body.get("csrf_token").and_then(Value::as_str) {
            self.csrf = Some(t.to_owned());
        }
        Resp { status, body, headers }
    }

    pub async fn login(&mut self, username: &str, password: &str) -> Resp {
        self.call(Method::POST, "/api/v1/auth/login", Some(json!({ "username": username, "password": password }))).await
    }

    pub async fn verify(&mut self, code: &str) -> Resp {
        self.call(Method::POST, "/api/v1/auth/mfa/verify", Some(json!({ "code": code }))).await
    }
}

pub fn b32decode(s: &str) -> Vec<u8> {
    let (mut buf, mut bits, mut out) = (0u64, 0u32, Vec::new());
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => panic!("bad base32"),
        };
        buf = (buf << 5) | u64::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buf >> bits) & 0xff).unwrap());
        }
    }
    out
}

pub fn code_now(seed: &[u8], offset_steps: i64) -> String {
    totp::code_at_step(seed, totp::step_at(chrono::Utc::now().timestamp()) + offset_steps)
}

/// Log in and finish enrollment; returns the TOTP seed.
pub async fn login_and_enroll(c: &mut Client, username: &str) -> Vec<u8> {
    assert_eq!(c.login(username, PASSWORD).await.status, StatusCode::OK);
    let enroll = c.call(Method::POST, "/api/v1/auth/mfa/enroll", None).await;
    assert_eq!(enroll.status, StatusCode::OK, "{}", enroll.body);
    let seed = b32decode(enroll.body["secret"].as_str().unwrap());
    let r = c.verify(&code_now(&seed, 0)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    seed
}

pub async fn audit_actions(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar("SELECT action FROM audit_log ORDER BY id").fetch_all(pool).await.unwrap()
}

/// App state with a custom pepper spec (e.g. to simulate pepper rotation).
pub fn state_with_pepper(pool: PgPool, pepper_spec: &str) -> AppState {
    let base = state(pool);
    let pepper = Pepper::parse(&SecretString::from(pepper_spec.to_owned()), None).unwrap();
    AppState { pepper: std::sync::Arc::new(pepper), ..base }
}

/// Create a user with `role` and return a fully logged-in client.
pub async fn logged_in(pool: &PgPool, app: &Router, username: &str, role: Role) -> Client {
    create_user(pool, username, role).await;
    let mut c = Client::new(app);
    login_and_enroll(&mut c, username).await;
    c
}

/// Router with a custom body limit (the default test router allows 64 KiB).
pub fn router_with_body_limit(state: AppState, max_body_bytes: usize) -> Router {
    let limits = HttpLimits { request_timeout: Duration::from_secs(30), max_body_bytes };
    app::router(state, limits).layer(MockConnectInfo(SocketAddr::from(([10, 0, 0, 7], 40000))))
}

/// Issue an API token through the admin API; returns `(token, id)`.
pub async fn issue_token(admin: &mut Client, name: &str, kind: &str, scopes: &[&str]) -> (String, String) {
    let req = json!({ "name": name, "kind": kind, "scopes": scopes, "expires_in_days": 30 });
    let r = admin.call(Method::POST, "/api/v1/api-tokens", Some(req)).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    (r.body["token"].as_str().unwrap().to_owned(), r.body["id"].as_str().unwrap().to_owned())
}

/// A machine request: `Authorization: Bearer <token>`, no cookies, no CSRF.
pub async fn bearer(app: &Router, method: Method, path: &str, token: Option<&str>, body: Option<Value>) -> Resp {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let req = match body {
        Some(b) => req.header(header::CONTENT_TYPE, "application/json").body(Body::from(b.to_string())),
        None => req.body(Body::empty()),
    }
    .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Resp { status, body, headers }
}
