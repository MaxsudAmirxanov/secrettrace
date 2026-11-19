//! API added for the web UI (stage 12): overview, findings list, user administration,
//! own password change, audit log browsing/verification, and serving the UI itself.
//! Run with `make test`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc, clippy::too_many_lines)]

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use common::*;
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use sqlx::PgPool;
use st_core::{SecretType, prepare};
use st_server::auth::Role;
use st_server::web::WebAssets;
use tower::ServiceExt as _;
use uuid::Uuid;

async fn register(c: &mut Client, name: &str, ty: SecretType, value: &str) -> String {
    let (digest, hints) = prepare(ty, value).unwrap();
    let body = json!({ "name": name, "type": ty, "owner": "platform", "digest": digest, "hints": hints });
    let r = c.call(Method::POST, "/api/v1/secrets", Some(body)).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    r.body["id"].as_str().unwrap().to_owned()
}

async fn add_location(pool: &PgPool, secret_id: &str, path: &str, allowed: bool, current: bool) {
    sqlx::query(
        "INSERT INTO locations (secret_id, source_type, uri, locator, locator_key, environment,
                                in_current_state, is_allowed)
         VALUES ($1::uuid, 'git_repo', 'https://git.example/infra/app.git', $2, $3, 'prod', $4, $5)",
    )
    .bind(secret_id)
    .bind(json!({ "path": path, "line": 3, "commit": "a".repeat(40) }))
    .bind(Uuid::new_v4().as_bytes().repeat(2))
    .bind(current)
    .bind(allowed)
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn overview_counts_and_findings_list(pool: PgPool) {
    let app = router(state(pool.clone()));
    let mut op = logged_in(&pool, &app, "op", Role::Operator).await;
    let gh = register(&mut op, "gh", SecretType::Token, "ghp_0123456789abcdefghijABCDEFGHIJ0123").await;
    let pw = register(&mut op, "db-pass", SecretType::Password, "correct horse battery staple").await;
    add_location(&pool, &gh, "config/app.env", false, true).await;
    add_location(&pool, &gh, "old/app.env", false, false).await;
    add_location(&pool, &gh, "k8s/sealed.yaml", true, true).await;
    add_location(&pool, &pw, "README_secret%.md", false, true).await;

    let mut viewer = logged_in(&pool, &app, "viewer", Role::Viewer).await;
    let r = viewer.call(Method::GET, "/api/v1/overview", None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let o = &r.body;
    assert_eq!(o["secrets"]["total"], 2);
    assert_eq!(o["secrets"]["active"], 2);
    assert_eq!(o["locations"]["total"], 4);
    assert_eq!(o["locations"]["open_violations"], 2);
    assert_eq!(o["locations"]["historical_violations"], 1);
    assert_eq!(o["locations"]["allowed"], 1);
    assert_eq!(o["locations"]["exposed_secrets"], 2);
    let days = o["violations_by_day"].as_array().unwrap();
    assert_eq!(days.len(), 30);
    assert_eq!(days.last().unwrap()["count"], 3, "today: three violations first seen");
    assert_eq!(o["top_exposed"][0]["secret"]["name"], "gh");
    assert_eq!(o["top_exposed"][0]["violations"], 2);
    assert_eq!(o["top_exposed"][0]["secret"]["masked"], "ghp_…0123");
    assert_eq!(o["recent_violations"].as_array().unwrap().len(), 3);
    // No digests, fingerprints or hints leave the API.
    let text = o.to_string();
    for forbidden in ["digest", "fingerprint", "hint_prefix", "pepper"] {
        assert!(!text.contains(forbidden), "{forbidden} in overview");
    }

    let r = viewer.call(Method::GET, "/api/v1/locations?is_allowed=false&in_current_state=true", None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let items = r.body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(|i| i["is_allowed"] == false && i["in_current_state"] == true));
    assert_eq!(items[0]["secret"]["type"], "password");
    assert_eq!(items[0]["secret"]["masked"], "••••••••", "passwords have no hints");

    // `q` matches path, URI or secret name; LIKE wildcards in it are literal.
    let r = viewer.call(Method::GET, "/api/v1/locations?q=secret%25", None).await;
    assert_eq!(r.body["items"].as_array().unwrap().len(), 1, "{}", r.body);
    let r = viewer.call(Method::GET, "/api/v1/locations?q=%25", None).await;
    assert_eq!(r.body["items"].as_array().unwrap().len(), 1, "% is literal: {}", r.body);
    let r = viewer.call(Method::GET, &format!("/api/v1/locations?secret_id={gh}&limit=2"), None).await;
    assert_eq!(r.body["items"].as_array().unwrap().len(), 2);
    let cursor = r.body["next_cursor"].as_str().unwrap().to_owned();
    let r = viewer.call(Method::GET, &format!("/api/v1/locations?secret_id={gh}&limit=2&cursor={cursor}"), None).await;
    assert_eq!(r.body["items"].as_array().unwrap().len(), 1);
    assert!(r.body.get("next_cursor").is_none());

    let r = viewer.call(Method::GET, "/api/v1/locations?limit=0", None).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = viewer.call(Method::GET, &format!("/api/v1/locations?q={}", "x".repeat(201)), None).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    let mut anon = Client::new(&app);
    assert_eq!(anon.call(Method::GET, "/api/v1/overview", None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(anon.call(Method::GET, "/api/v1/locations", None).await.status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn scans_carry_source_name(pool: PgPool) {
    let app = router(state(pool.clone()));
    let mut op = logged_in(&pool, &app, "op", Role::Operator).await;
    let body = json!({ "name": "infra-app", "type": "git_repo", "uri": "https://git.example/infra/app.git" });
    let src = op.call(Method::POST, "/api/v1/sources", Some(body)).await;
    assert_eq!(src.status, StatusCode::CREATED, "{}", src.body);
    let id = src.body["id"].as_str().unwrap();
    let r = op.call(Method::POST, &format!("/api/v1/sources/{id}/scans"), None).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{}", r.body);
    assert_eq!(r.body["source_name"], "infra-app");
    let r = op.call(Method::GET, "/api/v1/scans", None).await;
    assert_eq!(r.body["items"][0]["source_name"], "infra-app");
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn admin_manages_users_with_guard_rails(pool: PgPool) {
    let app = router(state(pool.clone()));
    let mut admin = logged_in(&pool, &app, "root", Role::Admin).await;
    let admin_id = admin.call(Method::GET, "/api/v1/auth/me", None).await.body["id"].as_str().unwrap().to_owned();

    // Create: weak password and bad username are 422, duplicates 409.
    let mk = |u: &str, p: &str| json!({ "username": u, "role": "viewer", "password": p });
    let r = admin.call(Method::POST, "/api/v1/users", Some(mk("alice", "short"))).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.body);
    let r = admin.call(Method::POST, "/api/v1/users", Some(mk("bad name", PASSWORD))).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    let r = admin.call(Method::POST, "/api/v1/users", Some(mk("alice", PASSWORD))).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    assert_eq!(r.body["role"], "viewer");
    assert_eq!(r.body["mfa_enabled"], false);
    assert!(r.body.get("password").is_none() && r.body.get("password_hash").is_none());
    let alice = r.body["id"].as_str().unwrap().to_owned();
    let r = admin.call(Method::POST, "/api/v1/users", Some(mk("ALICE", PASSWORD))).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "usernames are case-insensitive");

    // The new user logs in and enrolls TOTP.
    let mut a = Client::new(&app);
    let seed = login_and_enroll(&mut a, "alice").await;
    assert_eq!(a.call(Method::GET, "/api/v1/users", None).await.status, StatusCode::FORBIDDEN);

    // Promote; the role applies to the live session at once.
    let r = admin.call(Method::PATCH, &format!("/api/v1/users/{alice}"), Some(json!({ "role": "operator" }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(a.call(Method::GET, "/api/v1/auth/me", None).await.body["role"], "operator");

    // Disable ends sessions; enable again.
    let r = admin.call(Method::PATCH, &format!("/api/v1/users/{alice}"), Some(json!({ "is_active": false }))).await;
    assert_eq!(r.body["is_active"], false);
    assert_eq!(a.call(Method::GET, "/api/v1/auth/me", None).await.status, StatusCode::UNAUTHORIZED);
    admin.call(Method::PATCH, &format!("/api/v1/users/{alice}"), Some(json!({ "is_active": true }))).await;

    // Own account and the last admin are protected.
    let own = format!("/api/v1/users/{admin_id}");
    let r = admin.call(Method::PATCH, &own, Some(json!({ "role": "viewer" }))).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    let r = admin.call(Method::POST, &format!("{own}/reset-mfa"), None).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    let r = admin
        .call(Method::POST, &format!("{own}/password"), Some(json!({ "password": "another long passphrase" })))
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    let r = admin.call(Method::PATCH, &own, Some(json!({ "role": "admin" }))).await;
    assert_eq!(r.status, StatusCode::OK, "a no-op change is fine");

    // Second admin can be demoted while root stays; root cannot then be demoted by them.
    admin.call(Method::PATCH, &format!("/api/v1/users/{alice}"), Some(json!({ "role": "admin" }))).await;
    let mut a = Client::new(&app);
    a.login("alice", PASSWORD).await;
    a.verify(&code_now(&seed, 1)).await;
    let r = a.call(Method::PATCH, &own, Some(json!({ "is_active": false }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let r = a.call(Method::PATCH, &format!("/api/v1/users/{alice}"), Some(json!({ "role": "viewer" }))).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "own account");
    let r = a.call(Method::PATCH, &own, Some(json!({ "is_active": true }))).await;
    assert_eq!(r.status, StatusCode::OK);

    // Reset MFA, unlock, reset password of another user (by a third admin).
    let mut admin = logged_in(&pool, &app, "ops-admin", Role::Admin).await;
    let r = admin.call(Method::POST, &format!("/api/v1/users/{alice}/reset-mfa"), None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["mfa_enabled"], false);
    sqlx::query("UPDATE users SET failed_logins = 5, locked_until = now() + interval '1 hour' WHERE id = $1::uuid")
        .bind(&alice)
        .execute(&pool)
        .await
        .unwrap();
    let list = admin.call(Method::GET, "/api/v1/users", None).await;
    let row = list.body.as_array().unwrap().iter().find(|u| u["username"] == "alice").unwrap().clone();
    assert_eq!(row["is_locked"], true);
    let r = admin.call(Method::POST, &format!("/api/v1/users/{alice}/unlock"), None).await;
    assert_eq!(r.body["is_locked"], false);
    assert_eq!(r.body["failed_logins"], 0);
    let r = admin
        .call(Method::POST, &format!("/api/v1/users/{alice}/password"), Some(json!({ "password": "alice" })))
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    let r = admin
        .call(
            Method::POST,
            &format!("/api/v1/users/{alice}/password"),
            Some(json!({ "password": "a brand new passphrase" })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let mut a = Client::new(&app);
    assert_eq!(a.login("alice", PASSWORD).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(a.login("alice", "a brand new passphrase").await.status, StatusCode::OK);

    // CSRF is required; viewers and operators are forbidden.
    let csrf = admin.csrf.take();
    let r = admin.call(Method::POST, &format!("/api/v1/users/{alice}/unlock"), None).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    admin.csrf = csrf;
    let mut op = logged_in(&pool, &app, "op", Role::Operator).await;
    assert_eq!(op.call(Method::GET, "/api/v1/users", None).await.status, StatusCode::FORBIDDEN);
    let r = op.call(Method::POST, "/api/v1/users", Some(mk("eve", PASSWORD))).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    let actions = audit_actions(&pool).await;
    for a in ["user.create", "user.update", "user.mfa_reset", "user.unlock", "user.password_reset"] {
        assert!(actions.iter().any(|x| x == a), "{a} not audited: {actions:?}");
    }
    let details: Vec<String> =
        sqlx::query_scalar("SELECT details::text FROM audit_log").fetch_all(&pool).await.unwrap();
    assert!(details.iter().all(|d| !d.contains("passphrase") && !d.contains(PASSWORD)), "no passwords in audit");
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn two_admins_disabling_each_other_leave_one(pool: PgPool) {
    // With the self-check, "last admin" can only be hit by a race: A disables B while B
    // disables A. The admin rows are locked, so one request sees the other's result.
    let app = router(state(pool.clone()));
    let mut a = logged_in(&pool, &app, "admin-a", Role::Admin).await;
    let mut b = logged_in(&pool, &app, "admin-b", Role::Admin).await;
    let id = |name: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, String>("SELECT id::text FROM users WHERE username = $1")
                .bind(name)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    let (ida, idb) = (id("admin-a").await, id("admin-b").await);
    let off = json!({ "is_active": false });
    let pa = format!("/api/v1/users/{idb}");
    let pb = format!("/api/v1/users/{ida}");
    let (ra, rb) = tokio::join!(a.call(Method::PATCH, &pa, Some(off.clone())), b.call(Method::PATCH, &pb, Some(off)));
    let ok = [ra.status, rb.status].iter().filter(|s| **s == StatusCode::OK).count();
    assert!(ok <= 1, "{} / {}", ra.status, rb.status);
    let active: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE role = 'admin' AND is_active")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(active, 1 + i64::from(ok == 0));

    let r =
        a.call(Method::PATCH, &format!("/api/v1/users/{}", Uuid::new_v4()), Some(json!({ "role": "viewer" }))).await;
    assert!(matches!(r.status, StatusCode::NOT_FOUND | StatusCode::UNAUTHORIZED));
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn change_own_password(pool: PgPool) {
    let app = router(state(pool.clone()));
    let mut c = logged_in(&pool, &app, "alice", Role::Viewer).await;
    // A second (pre-MFA) session of the same user.
    let mut other = Client::new(&app);
    assert_eq!(other.login("alice", PASSWORD).await.status, StatusCode::OK);

    let path = "/api/v1/auth/password";
    let body = |cur: &str, new: &str| json!({ "current_password": cur, "new_password": new });
    let r = c.call(Method::POST, path, Some(body("wrong password!!", "a brand new passphrase"))).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    let r = c.call(Method::POST, path, Some(body(PASSWORD, "short"))).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    let r = c.call(Method::POST, path, Some(body(PASSWORD, PASSWORD))).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    let r = c.call(Method::POST, path, Some(body(PASSWORD, "a brand new passphrase"))).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);

    // This session survives, the other one is gone.
    assert_eq!(c.call(Method::GET, "/api/v1/auth/me", None).await.status, StatusCode::OK);
    assert_eq!(
        other.call(Method::POST, "/api/v1/auth/mfa/verify", Some(json!({ "code": "000000" }))).await.status,
        StatusCode::UNAUTHORIZED
    );
    let mut fresh = Client::new(&app);
    assert_eq!(fresh.login("alice", PASSWORD).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(fresh.login("alice", "a brand new passphrase").await.status, StatusCode::OK);

    let actions = audit_actions(&pool).await;
    assert!(actions.contains(&"auth.password_change.failed".to_owned()));
    assert!(actions.contains(&"auth.password_changed".to_owned()));
    let csrf = c.csrf.take();
    let r = c.call(Method::POST, path, Some(body("a brand new passphrase", "yet another passphrase"))).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "CSRF required");
    c.csrf = csrf;
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn audit_log_browse_filter_and_verify(pool: PgPool) {
    let app = router(state(pool.clone()));
    let mut admin = logged_in(&pool, &app, "root", Role::Admin).await;
    let mut op = logged_in(&pool, &app, "op", Role::Operator).await;
    register(&mut op, "gh", SecretType::Token, "ghp_0123456789abcdefghijABCDEFGHIJ0123").await;

    let r = admin.call(Method::GET, "/api/v1/audit?limit=200", None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let items = r.body["items"].as_array().unwrap();
    assert!(items.len() >= 5);
    let ids: Vec<i64> = items.iter().map(|i| i["id"].as_i64().unwrap()).collect();
    assert!(ids.windows(2).all(|w| w[0] > w[1]), "newest first");
    let create = items.iter().find(|i| i["action"] == "secret.create").unwrap();
    assert_eq!(create["actor_name"], "op");
    assert_eq!(create["actor_type"], "user");

    let r = admin.call(Method::GET, "/api/v1/audit?action=auth.", None).await;
    let items = r.body["items"].as_array().unwrap();
    assert!(!items.is_empty() && items.iter().all(|i| i["action"].as_str().unwrap().starts_with("auth.")));
    let r = admin.call(Method::GET, "/api/v1/audit?action=secret.create", None).await;
    assert_eq!(r.body["items"].as_array().unwrap().len(), 1);
    let r = admin.call(Method::GET, "/api/v1/audit?action=auth_", None).await;
    assert_eq!(r.body["items"].as_array().unwrap().len(), 0);

    let r = admin.call(Method::GET, "/api/v1/audit?limit=2", None).await;
    let cursor = r.body["next_cursor"].as_str().unwrap().to_owned();
    let r2 = admin.call(Method::GET, &format!("/api/v1/audit?limit=2&cursor={cursor}"), None).await;
    assert!(r2.body["items"][0]["id"].as_i64().unwrap() < r.body["items"][1]["id"].as_i64().unwrap());
    assert_eq!(admin.call(Method::GET, "/api/v1/audit?cursor=abc", None).await.status, StatusCode::BAD_REQUEST);

    let r = admin.call(Method::GET, "/api/v1/audit/verify", None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body["ok"], true);
    assert!(r.body["rows"].as_u64().unwrap() >= 5);
    assert_eq!(r.body["head"].as_str().unwrap().len(), 64);

    // Tampering (with owner privileges) is reported, not hidden.
    sqlx::query("UPDATE audit_log SET action = 'secret.tampered' WHERE action = 'secret.create'")
        .execute(&pool)
        .await
        .unwrap();
    let r = admin.call(Method::GET, "/api/v1/audit/verify", None).await;
    assert_eq!(r.body["ok"], false);
    assert!(r.body["broken_at"].as_i64().is_some());

    assert_eq!(op.call(Method::GET, "/api/v1/audit", None).await.status, StatusCode::FORBIDDEN);
    assert_eq!(op.call(Method::GET, "/api/v1/audit/verify", None).await.status, StatusCode::FORBIDDEN);
}

async fn raw(app: &axum::Router, method: Method, path: &str) -> (StatusCode, axum::http::HeaderMap, String) {
    let resp =
        app.clone().oneshot(Request::builder().method(method).uri(path).body(Body::empty()).unwrap()).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).into_owned();
    (status, headers, body)
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn serves_ui_with_security_headers(pool: PgPool) {
    let web = WebAssets::from_files([
        ("index.html", b"<!doctype html><div id=root></div>".as_slice()),
        ("assets/index-abc123.js", b"export{}".as_slice()),
    ]);
    let limits =
        st_server::app::HttpLimits { request_timeout: std::time::Duration::from_secs(5), max_body_bytes: 65536 };
    let app = st_server::app::router_with_web(state(pool), limits, Some(Arc::new(web)))
        .layer(axum::extract::connect_info::MockConnectInfo(std::net::SocketAddr::from(([10, 0, 0, 7], 40000))));

    let (status, h, body) = raw(&app, Method::GET, "/secrets/123").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("id=root"));
    let csp = h[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
    assert!(csp.contains("script-src 'self'") && csp.contains("frame-ancestors 'none'"));
    assert!(!csp.contains("unsafe-inline") && !csp.contains("unsafe-eval"));
    assert_eq!(h[header::X_FRAME_OPTIONS], "DENY");
    assert_eq!(h[header::REFERRER_POLICY], "no-referrer");
    assert_eq!(h[header::CACHE_CONTROL], "no-cache");

    let (status, h, _) = raw(&app, Method::GET, "/assets/index-abc123.js").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h[header::CACHE_CONTROL], "public, max-age=31536000, immutable");

    // API paths keep problem+json 404s and their own CSP.
    let (status, h, body) = raw(&app, Method::GET, "/api/v1/nope").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(h[header::CONTENT_TYPE], "application/problem+json");
    assert_eq!(h[header::CONTENT_SECURITY_POLICY], "default-src 'none'; frame-ancestors 'none'");
    assert!(serde_json::from_str::<Value>(&body).is_ok());
    let (status, _, _) = raw(&app, Method::GET, "/assets/missing.js").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = raw(&app, Method::POST, "/secrets").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = raw(&app, Method::GET, "/healthz").await;
    assert_eq!(status, StatusCode::OK);
}
