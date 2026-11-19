//! End-to-end tests of the authentication flow through the real router and Postgres.
//! Run with `make test` (needs `DATABASE_URL` of a superuser; see `tests/db.rs`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]

mod common;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use axum::routing::get;
use common::*;
use serde_json::json;
use sqlx::PgPool;
use st_server::audit;
use st_server::auth::{Role, TokenPrincipal};
use st_server::users;
use tower::ServiceExt as _;

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn full_login_flow_with_enrollment(pool: PgPool) {
    create_user(&pool, "alice", Role::Operator).await;
    let app = router(state(pool.clone()));
    let mut c = Client::new(&app);

    let r = c.login("alice", PASSWORD).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body["mfa_required"], true);
    assert_eq!(r.body["mfa_enrolled"], false);
    let set_cookie = r.headers[header::SET_COOKIE].to_str().unwrap();
    assert!(set_cookie.contains("HttpOnly") && set_cookie.contains("SameSite=Strict"), "{set_cookie}");
    let pre_mfa_cookie = c.cookie.clone().unwrap();

    // Pre-MFA session is not enough for protected endpoints.
    assert_eq!(c.call(Method::GET, "/api/v1/auth/me", None).await.status, StatusCode::UNAUTHORIZED);

    let enroll = c.call(Method::POST, "/api/v1/auth/mfa/enroll", None).await;
    assert_eq!(enroll.status, StatusCode::OK);
    let uri = enroll.body["otpauth_uri"].as_str().unwrap();
    assert!(uri.starts_with("otpauth://totp/SecretTrace:alice?secret="), "{uri}");
    let seed = b32decode(enroll.body["secret"].as_str().unwrap());

    // The seed is stored encrypted, never in clear.
    let stored: Vec<u8> = sqlx::query_scalar("SELECT totp_secret_enc FROM users WHERE username = 'alice'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!stored.windows(seed.len()).any(|w| w == seed.as_slice()));

    assert_eq!(c.verify("000000").await.status, StatusCode::UNAUTHORIZED);
    let r = c.verify(&code_now(&seed, 0)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["role"], "operator");

    // Session token rotated after MFA; the pre-MFA token is dead.
    let full_cookie = c.cookie.clone().unwrap();
    assert_ne!(full_cookie, pre_mfa_cookie);
    let mut stale = Client { app: app.clone(), cookie: Some(pre_mfa_cookie), csrf: None };
    assert_eq!(stale.call(Method::GET, "/api/v1/auth/me", None).await.status, StatusCode::UNAUTHORIZED);

    let me = c.call(Method::GET, "/api/v1/auth/me", None).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.body["username"], "alice");
    assert_eq!(me.body["csrf_token"].as_str(), c.csrf.as_deref(), "/me returns the session's CSRF token");

    // Logout kills the session and clears the cookie.
    assert_eq!(c.call(Method::POST, "/api/v1/auth/logout", None).await.status, StatusCode::NO_CONTENT);
    assert!(c.cookie.is_none());
    let mut after = Client { app, cookie: Some(full_cookie), csrf: None };
    assert_eq!(after.call(Method::GET, "/api/v1/auth/me", None).await.status, StatusCode::UNAUTHORIZED);

    assert_eq!(
        audit_actions(&pool).await,
        [
            "user.create",
            "auth.login.password_ok",
            "auth.mfa.enroll_started",
            "auth.mfa.failed",
            "auth.login.success",
            "auth.logout"
        ]
    );
    assert!(audit::verify_chain(&pool).await.is_ok());
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn totp_codes_cannot_be_replayed_and_enrollment_is_once(pool: PgPool) {
    create_user(&pool, "bob", Role::Viewer).await;
    let app = router(state(pool));
    let mut c = Client::new(&app);
    let seed = login_and_enroll(&mut c, "bob").await;
    let used = code_now(&seed, 0);

    let mut c2 = Client::new(&app);
    let r = c2.login("bob", PASSWORD).await;
    assert_eq!(r.body["mfa_enrolled"], true);
    // Re-enrollment is refused once MFA is active.
    assert_eq!(c2.call(Method::POST, "/api/v1/auth/mfa/enroll", None).await.status, StatusCode::CONFLICT);
    // The code already used for the first login is rejected...
    assert_eq!(c2.verify(&used).await.status, StatusCode::UNAUTHORIZED);
    // ...but the next time step (within the drift window) works.
    assert_eq!(c2.verify(&code_now(&seed, 1)).await.status, StatusCode::OK);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn csrf_is_required_for_state_changes(pool: PgPool) {
    create_user(&pool, "carol", Role::Admin).await;
    let app = router(state(pool));
    let mut c = Client::new(&app);
    login_and_enroll(&mut c, "carol").await;
    let good = c.csrf.clone();

    c.csrf = None;
    assert_eq!(c.call(Method::POST, "/api/v1/auth/logout", None).await.status, StatusCode::FORBIDDEN);
    c.csrf = Some("forged".into());
    assert_eq!(c.call(Method::POST, "/api/v1/auth/logout", None).await.status, StatusCode::FORBIDDEN);
    // Safe methods do not need it.
    c.csrf = None;
    assert_eq!(c.call(Method::GET, "/api/v1/auth/me", None).await.status, StatusCode::OK);
    c.csrf = good;
    assert_eq!(c.call(Method::POST, "/api/v1/auth/logout", None).await.status, StatusCode::NO_CONTENT);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn failures_are_indistinguishable_and_lock_the_account(pool: PgPool) {
    create_user(&pool, "dave", Role::Viewer).await;
    let app = router(state(pool.clone()));
    let mut c = Client::new(&app);

    let unknown = c.login("nobody", PASSWORD).await;
    let wrong = c.login("dave", "wrong password 123").await;
    assert_eq!(unknown.status, StatusCode::UNAUTHORIZED);
    assert_eq!(unknown.body, wrong.body, "no account enumeration via response body");
    assert!(c.cookie.is_none());

    for _ in 0..4 {
        assert_eq!(c.login("dave", "wrong password 123").await.status, StatusCode::UNAUTHORIZED);
    }
    // Five failures: locked, even with the right password.
    let r = c.login("dave", PASSWORD).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.body, wrong.body);

    let locked: bool = sqlx::query_scalar("SELECT locked_until > now() FROM users WHERE username = 'dave'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(locked);

    let mut conn = pool.acquire().await.unwrap();
    let id = users::find_by_username(&mut conn, "dave").await.unwrap().unwrap().id;
    users::reset_failures(&mut conn, id).await.unwrap();
    assert_eq!(c.login("dave", PASSWORD).await.status, StatusCode::OK);

    // The attempted username of unknown accounts is not written to the audit log.
    let leaked: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE details::text LIKE '%nobody%'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(leaked, 0);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn login_is_rate_limited(pool: PgPool) {
    let app = router(state(pool));
    let mut c = Client::new(&app);
    let mut statuses = Vec::new();
    for _ in 0..11 {
        statuses.push(c.login("eve", "some wrong password").await.status);
    }
    assert_eq!(statuses[..10], [StatusCode::UNAUTHORIZED; 10]);
    assert_eq!(statuses[10], StatusCode::TOO_MANY_REQUESTS);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn api_tokens_rbac_and_bearer_auth(pool: PgPool) {
    create_user(&pool, "root", Role::Admin).await;
    create_user(&pool, "viewer1", Role::Viewer).await;
    let st = state(pool.clone());
    let app = router(st.clone());

    let mut viewer = Client::new(&app);
    login_and_enroll(&mut viewer, "viewer1").await;
    assert_eq!(viewer.call(Method::GET, "/api/v1/api-tokens", None).await.status, StatusCode::FORBIDDEN);

    let mut admin = Client::new(&app);
    login_and_enroll(&mut admin, "root").await;

    let bad_scope = json!({ "name": "ci", "kind": "ci", "scopes": ["admin:*"], "expires_in_days": 30 });
    let r = admin.call(Method::POST, "/api/v1/api-tokens", Some(bad_scope)).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);

    let req = json!({ "name": "github-ci", "kind": "ci", "scopes": ["ingest:match", "ingest:profile"], "expires_in_days": 30 });
    let r = admin.call(Method::POST, "/api/v1/api-tokens", Some(req)).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    let token = r.body["token"].as_str().unwrap().to_owned();
    let id = r.body["id"].as_str().unwrap().to_owned();
    assert!(token.starts_with(r.body["token_prefix"].as_str().unwrap()));

    // The listing never contains the token or its hash.
    let list = admin.call(Method::GET, "/api/v1/api-tokens", None).await;
    assert_eq!(list.status, StatusCode::OK);
    assert!(!list.body.to_string().contains(&token));
    assert!(list.body[0].get("token_hash").is_none());

    // Bearer authentication + scope check on a probe route.
    let probe = Router::new()
        .route(
            "/probe/{scope}",
            get(|p: TokenPrincipal, axum::extract::Path(scope): axum::extract::Path<String>| async move {
                p.require_scope(&scope).map(|()| p.token_prefix)
            }),
        )
        .with_state(st);
    let call = |auth: Option<String>, scope: &'static str| {
        let probe = probe.clone();
        async move {
            let mut req = Request::get(format!("/probe/{scope}"));
            if let Some(a) = auth {
                req = req.header(header::AUTHORIZATION, a);
            }
            probe.oneshot(req.body(Body::empty()).unwrap()).await.unwrap().status()
        }
    };
    assert_eq!(call(Some(format!("Bearer {token}")), "ingest:match").await, StatusCode::OK);
    assert_eq!(call(Some(format!("Bearer {token}")), "ingest:findings").await, StatusCode::FORBIDDEN);
    assert_eq!(call(None, "ingest:match").await, StatusCode::UNAUTHORIZED);
    let mut forged = token.clone();
    forged.pop();
    forged.push(if token.ends_with('A') { 'B' } else { 'A' });
    assert_eq!(call(Some(format!("Bearer {forged}")), "ingest:match").await, StatusCode::UNAUTHORIZED);

    // Revocation is immediate.
    let r = admin.call(Method::DELETE, &format!("/api/v1/api-tokens/{id}"), None).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(call(Some(format!("Bearer {token}")), "ingest:match").await, StatusCode::UNAUTHORIZED);
    let again = admin.call(Method::DELETE, &format!("/api/v1/api-tokens/{id}"), None).await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);

    let actions = audit_actions(&pool).await;
    assert!(actions.contains(&"api_token.create".to_owned()));
    assert!(actions.contains(&"api_token.revoke".to_owned()));
    // Token value never reaches the audit log.
    let leaked: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE details::text LIKE '%' || $1 || '%'")
        .bind(&token)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(leaked, 0);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn reset_mfa_revokes_sessions(pool: PgPool) {
    create_user(&pool, "frank", Role::Viewer).await;
    let app = router(state(pool.clone()));
    let mut c = Client::new(&app);
    login_and_enroll(&mut c, "frank").await;

    let mut conn = pool.acquire().await.unwrap();
    let id = users::find_by_username(&mut conn, "frank").await.unwrap().unwrap().id;
    users::reset_mfa(&mut conn, id).await.unwrap();

    assert_eq!(c.call(Method::GET, "/api/v1/auth/me", None).await.status, StatusCode::UNAUTHORIZED);
    let r = c.login("frank", PASSWORD).await;
    assert_eq!(r.body["mfa_enrolled"], false, "must enroll again");
}
