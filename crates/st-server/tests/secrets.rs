//! Registry API tests: registration by digest, duplicates, RBAC, validation, updates,
//! pagination and locations. Run with `make test`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use base64::Engine as _;
use common::*;
use serde_json::{Value, json};
use sqlx::PgPool;
use st_core::{SecretType, prepare};
use st_server::auth::Role;
use tower::ServiceExt as _;

const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

fn register_body(name: &str, ty: SecretType, value: &str) -> Value {
    let (digest, hints) = prepare(ty, value).unwrap();
    json!({ "name": name, "type": ty, "owner": "platform-team", "digest": digest.to_hex(), "hints": hints })
}

async fn register(c: &mut Client, body: Value) -> Resp {
    c.call(Method::POST, "/api/v1/secrets", Some(body)).await
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn register_and_read_without_exposing_digest(pool: PgPool) {
    let app = router(state(pool.clone()));
    let mut op = logged_in(&pool, &app, "op", Role::Operator).await;

    let mut body = register_body("prod-aws-deploy", SecretType::ApiKey, AWS_KEY);
    body["purpose"] = json!("terraform deploys");
    body["allow_rules"] = json!([
        { "source_type": "git_repo", "uri_pattern": "git@github.com:acme/infra-secrets.git", "path_pattern": "sealed/**" },
        { "uri_pattern": "host:vault-*", "environment": "prod", "comment": "runtime" }
    ]);
    body["expires_at"] = json!((chrono::Utc::now() + chrono::Duration::days(90)).to_rfc3339());
    let digest_hex = body["digest"].as_str().unwrap().to_owned();

    let r = register(&mut op, body).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    let s = &r.body;
    assert_eq!(s["masked"], "AKIA…");
    assert_eq!(s["type"], "api_key");
    assert_eq!(s["status"], "active");
    assert_eq!(s["is_expired"], false);
    assert_eq!(s["allow_rules"].as_array().unwrap().len(), 2);
    assert_eq!(s["location_count"], 0);
    for forbidden in ["digest", "fingerprint", "pepper_version", "hint_prefix"] {
        assert!(s.get(forbidden).is_none(), "response leaks {forbidden}");
    }
    assert!(!r.body.to_string().contains(&digest_hex));
    let id = s["id"].as_str().unwrap().to_owned();

    // Stored fingerprint is keyed: it is not the digest.
    let fp: Vec<u8> = sqlx::query_scalar("SELECT fingerprint FROM secrets").fetch_one(&pool).await.unwrap();
    assert_ne!(hex::encode(&fp), digest_hex);

    let got = op.call(Method::GET, &format!("/api/v1/secrets/{id}"), None).await;
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(got.body["name"], "prod-aws-deploy");
    assert_eq!(got.body["allow_rules"][0]["path_pattern"], "sealed/**");

    let audit: Value = sqlx::query_scalar("SELECT details FROM audit_log WHERE action = 'secret.create'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(audit["masked"], "AKIA…");
    assert!(!audit.to_string().contains(&digest_hex), "digest must not reach the audit log");
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn duplicates_are_rejected_including_older_pepper_versions(pool: PgPool) {
    let b64 = base64::engine::general_purpose::STANDARD;
    let k1 = b64.encode([1u8; 32]); // same key as common::state() uses for version 1
    let app = router(state(pool.clone()));
    let mut op = logged_in(&pool, &app, "op", Role::Operator).await;

    assert_eq!(register(&mut op, register_body("a", SecretType::ApiKey, AWS_KEY)).await.status, StatusCode::CREATED);
    let same_value = register(&mut op, register_body("b", SecretType::ApiKey, AWS_KEY)).await;
    assert_eq!(same_value.status, StatusCode::CONFLICT);
    assert!(same_value.body["detail"].as_str().unwrap().contains("already registered"));
    let same_name = register(&mut op, register_body("a", SecretType::Token, "another-token-value-123")).await;
    assert_eq!(same_name.status, StatusCode::CONFLICT);
    assert!(same_name.body["detail"].as_str().unwrap().contains("name"));

    // After pepper rotation (current = v2) the value registered under v1 is still detected.
    let rotated = router(state_with_pepper(pool.clone(), &format!("1:{k1},2:{}", b64.encode([9u8; 32]))));
    op.app = rotated;
    let r = register(&mut op, register_body("c", SecretType::ApiKey, AWS_KEY)).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.body);
    // New values get the new version.
    let r = register(&mut op, register_body("d", SecretType::Token, "ghp_0123456789abcdefghijABCDEFGHIJ0123")).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let v: i16 =
        sqlx::query_scalar("SELECT pepper_version FROM secrets WHERE name = 'd'").fetch_one(&pool).await.unwrap();
    assert_eq!(v, 2);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn rbac_and_csrf(pool: PgPool) {
    let app = router(state(pool.clone()));
    let mut viewer = logged_in(&pool, &app, "viewer1", Role::Viewer).await;
    let mut op = logged_in(&pool, &app, "op", Role::Operator).await;

    assert_eq!(
        register(&mut viewer, register_body("x", SecretType::ApiKey, AWS_KEY)).await.status,
        StatusCode::FORBIDDEN
    );
    let created = register(&mut op, register_body("x", SecretType::ApiKey, AWS_KEY)).await;
    let id = created.body["id"].as_str().unwrap().to_owned();
    assert_eq!(viewer.call(Method::GET, "/api/v1/secrets", None).await.status, StatusCode::OK);
    let patch = viewer.call(Method::PATCH, &format!("/api/v1/secrets/{id}"), Some(json!({ "owner": "me" }))).await;
    assert_eq!(patch.status, StatusCode::FORBIDDEN);

    let mut anon = Client::new(&app);
    assert_eq!(anon.call(Method::GET, "/api/v1/secrets", None).await.status, StatusCode::UNAUTHORIZED);

    op.csrf = None;
    let r = register(&mut op, register_body("y", SecretType::Token, "some-token-value-123")).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn validation_errors_are_problem_json(pool: PgPool) {
    let app = router(state(pool.clone()));
    let mut op = logged_in(&pool, &app, "op", Role::Operator).await;
    let base = register_body("v", SecretType::ApiKey, AWS_KEY);

    let with = |patch: Value| {
        let mut b = base.clone();
        for (k, v) in patch.as_object().unwrap() {
            b[k] = v.clone();
        }
        b
    };
    let past = (chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339();
    let cases = [
        ("bad digest", with(json!({ "digest": "AKIAIOSFODNN7EXAMPLE" }))),
        ("uppercase digest", with(json!({ "digest": "A".repeat(64) }))),
        ("forged prefix", with(json!({ "hints": { "prefix": "Sup3", "length": 20 } }))),
        ("hints on password", {
            let mut b = register_body("pw", SecretType::Password, "correct horse battery");
            b["hints"] = json!({ "prefix": "AKIA", "length": 21 });
            b
        }),
        ("expiry in past", with(json!({ "expires_at": past }))),
        ("bad glob", with(json!({ "allow_rules": [{ "uri_pattern": "dangling\\" }] }))),
        ("unknown field", with(json!({ "value": AWS_KEY }))),
        ("blank name", with(json!({ "name": "   " }))),
        ("unknown type", with(json!({ "type": "nuclear_codes" }))),
    ];
    for (what, body) in cases {
        let r = register(&mut op, body).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{what}: {}", r.body);
        assert_eq!(r.headers[header::CONTENT_TYPE], "application/problem+json", "{what}");
    }
    // The plaintext sent by mistake in `digest` is not echoed back.
    let r = register(&mut op, with(json!({ "digest": AWS_KEY }))).await;
    assert!(!r.body.to_string().contains(AWS_KEY), "{}", r.body);

    // Malformed JSON and wrong content type.
    let mut req = Request::post("/api/v1/secrets")
        .header(header::COOKIE, format!("st_session={}", op.cookie.clone().unwrap()))
        .header("x-csrf-token", op.csrf.clone().unwrap());
    req = req.header(header::CONTENT_TYPE, "application/json");
    let resp = app.clone().oneshot(req.body(Body::from("{not json")).unwrap()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let req = Request::post("/api/v1/secrets")
        .header(header::COOKIE, format!("st_session={}", op.cookie.clone().unwrap()))
        .header("x-csrf-token", op.csrf.clone().unwrap())
        .header(header::CONTENT_TYPE, "text/plain");
    let resp = app.clone().oneshot(req.body(Body::from("{}")).unwrap()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    // Bad path / query parameters.
    assert_eq!(op.call(Method::GET, "/api/v1/secrets/not-a-uuid", None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(op.call(Method::GET, "/api/v1/secrets?limit=0", None).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(op.call(Method::GET, "/api/v1/secrets?cursor=garbage", None).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(op.call(Method::GET, "/api/v1/secrets?status=bogus", None).await.status, StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn updates_and_status_transitions(pool: PgPool) {
    let app = router(state(pool.clone()));
    let mut op = logged_in(&pool, &app, "op", Role::Operator).await;
    let mut body = register_body("rot", SecretType::ApiKey, AWS_KEY);
    body["expires_at"] = json!((chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339());
    body["allow_rules"] = json!([{ "uri_pattern": "a" }, { "uri_pattern": "b" }]);
    let id = register(&mut op, body).await.body["id"].as_str().unwrap().to_owned();
    let url = format!("/api/v1/secrets/{id}");

    let empty = op.call(Method::PATCH, &url, Some(json!({}))).await;
    assert_eq!(empty.status, StatusCode::UNPROCESSABLE_ENTITY);

    let r = op
        .call(
            Method::PATCH,
            &url,
            Some(json!({ "owner": "sec-team", "expires_at": null, "allow_rules": [{ "uri_pattern": "c/**" }] })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["owner"], "sec-team");
    assert_eq!(r.body["expires_at"], Value::Null);
    let rules = r.body["allow_rules"].as_array().unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["uri_pattern"], "c/**");

    let revoked = op.call(Method::PATCH, &url, Some(json!({ "status": "revoked" }))).await;
    assert_eq!(revoked.body["status"], "revoked");
    let back = op.call(Method::PATCH, &url, Some(json!({ "status": "active" }))).await;
    assert_eq!(back.status, StatusCode::CONFLICT);
    let missing = op
        .call(Method::PATCH, &format!("/api/v1/secrets/{}", uuid::Uuid::new_v4()), Some(json!({ "owner": "x" })))
        .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);

    let actions: Vec<String> =
        sqlx::query_scalar("SELECT action FROM audit_log WHERE target_type = 'secret' ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(actions, ["secret.create", "secret.update", "secret.revoke"]);
    let details: Value = sqlx::query_scalar("SELECT details FROM audit_log WHERE action = 'secret.update'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(details["changed"], json!(["owner", "expires_at", "allow_rules"]));
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn pagination_and_filters(pool: PgPool) {
    let app = router(state(pool.clone()));
    let mut op = logged_in(&pool, &app, "op", Role::Operator).await;
    for i in 0..5 {
        let b = register_body(&format!("token-{i}"), SecretType::Token, &format!("internal-token-value-{i:03}"));
        assert_eq!(register(&mut op, b).await.status, StatusCode::CREATED);
    }
    let mut pw = register_body("db_100%_prod", SecretType::Password, "correct horse battery");
    pw["owner"] = json!("dba");
    assert_eq!(register(&mut op, pw).await.status, StatusCode::CREATED);

    // Walk all pages of size 2.
    let mut seen = Vec::new();
    let mut url = "/api/v1/secrets?limit=2".to_owned();
    loop {
        let page = op.call(Method::GET, &url, None).await;
        assert_eq!(page.status, StatusCode::OK);
        for item in page.body["items"].as_array().unwrap() {
            seen.push(item["name"].as_str().unwrap().to_owned());
        }
        match page.body.get("next_cursor").and_then(Value::as_str) {
            Some(c) => url = format!("/api/v1/secrets?limit=2&cursor={c}"),
            None => break,
        }
    }
    assert_eq!(seen.len(), 6);
    let mut unique = seen.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), 6, "no duplicates across pages: {seen:?}");
    assert_eq!(seen[0], "db_100%_prod", "newest first");

    let by_type = op.call(Method::GET, "/api/v1/secrets?type=password", None).await;
    assert_eq!(by_type.body["items"].as_array().unwrap().len(), 1);
    let by_owner = op.call(Method::GET, "/api/v1/secrets?owner=dba", None).await;
    assert_eq!(by_owner.body["items"].as_array().unwrap().len(), 1);
    // `%` and `_` in q are literals, not wildcards.
    let literal = op.call(Method::GET, "/api/v1/secrets?q=100%25_", None).await;
    assert_eq!(literal.body["items"].as_array().unwrap().len(), 1);
    let wildcard_free = op.call(Method::GET, "/api/v1/secrets?q=%25", None).await;
    assert_eq!(wildcard_free.body["items"].as_array().unwrap().len(), 1, "only the name containing a real %");
    let q = op.call(Method::GET, "/api/v1/secrets?q=TOKEN-3", None).await;
    assert_eq!(q.body["items"][0]["name"], "token-3");
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn locations_and_violation_counts(pool: PgPool) {
    let app = router(state(pool.clone()));
    let mut viewer = logged_in(&pool, &app, "viewer1", Role::Viewer).await;
    let mut op = logged_in(&pool, &app, "op", Role::Operator).await;
    let id = register(&mut op, register_body("leaky", SecretType::ApiKey, AWS_KEY)).await.body["id"]
        .as_str()
        .unwrap()
        .parse::<uuid::Uuid>()
        .unwrap();

    for (key, allowed, path) in [(1u8, true, "sealed/a.yaml"), (2, false, ".env"), (3, false, "ci.log")] {
        sqlx::query(
            "INSERT INTO locations (secret_id, source_type, uri, locator, locator_key, in_current_state, is_allowed)
             VALUES ($1, 'git_repo', 'git@github.com:acme/app.git', $2, $3, true, $4)",
        )
        .bind(id)
        .bind(json!({ "path": path, "line": 3 }))
        .bind(vec![key; 32])
        .bind(allowed)
        .execute(&pool)
        .await
        .unwrap();
    }

    let s = viewer.call(Method::GET, &format!("/api/v1/secrets/{id}"), None).await;
    assert_eq!(s.body["location_count"], 3);
    assert_eq!(s.body["violation_count"], 2);

    let all = viewer.call(Method::GET, &format!("/api/v1/secrets/{id}/locations"), None).await;
    assert_eq!(all.status, StatusCode::OK);
    assert_eq!(all.body["items"].as_array().unwrap().len(), 3);
    let bad = viewer.call(Method::GET, &format!("/api/v1/secrets/{id}/locations?is_allowed=false&limit=1"), None).await;
    assert_eq!(bad.body["items"].as_array().unwrap().len(), 1);
    assert_eq!(bad.body["items"][0]["is_allowed"], false);
    let cursor = bad.body["next_cursor"].as_str().unwrap();
    let next = viewer
        .call(Method::GET, &format!("/api/v1/secrets/{id}/locations?is_allowed=false&limit=1&cursor={cursor}"), None)
        .await;
    assert_eq!(next.body["items"].as_array().unwrap().len(), 1);
    assert!(next.body.get("next_cursor").is_none());
    assert_ne!(next.body["items"][0]["id"], bad.body["items"][0]["id"]);

    let missing = viewer.call(Method::GET, &format!("/api/v1/secrets/{}/locations", uuid::Uuid::new_v4()), None).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn replacing_allow_rules_reevaluates_existing_locations(pool: PgPool) {
    let app = router(state(pool.clone()));
    let mut op = logged_in(&pool, &app, "op", Role::Operator).await;
    let id = register(&mut op, register_body("reeval", SecretType::ApiKey, AWS_KEY)).await.body["id"]
        .as_str()
        .unwrap()
        .parse::<uuid::Uuid>()
        .unwrap();
    for (key, path) in [(1u8, "sealed/a.yaml"), (2, ".env")] {
        sqlx::query(
            "INSERT INTO locations (secret_id, source_type, uri, locator, locator_key, in_current_state, is_allowed)
             VALUES ($1, 'git_repo', 'git@github.com:acme/app.git', $2, $3, true, false)",
        )
        .bind(id)
        .bind(json!({ "path": path, "line": 1 }))
        .bind(vec![key; 32])
        .execute(&pool)
        .await
        .unwrap();
    }
    let url = format!("/api/v1/secrets/{id}");
    assert_eq!(op.call(Method::GET, &url, None).await.body["violation_count"], 2);

    let rules = json!({ "allow_rules": [
        { "uri_pattern": "git@github.com:acme/*", "path_pattern": "sealed/**" },
        { "uri_pattern": "**", "environment": "prod" }
    ] });
    let r = op.call(Method::PATCH, &url, Some(rules)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["violation_count"], 1);
    let rule_id = r.body["allow_rules"][0]["id"].as_i64().unwrap();
    let state: Vec<(String, bool, Option<i64>)> = sqlx::query_as(
        "SELECT locator->>'path', is_allowed, allow_rule_id FROM locations WHERE secret_id = $1 ORDER BY 1",
    )
    .bind(id)
    .fetch_all(&pool)
    .await
    .unwrap();
    // The env-scoped catch-all does not apply: these locations have no environment.
    assert_eq!(state, vec![(".env".into(), false, None), ("sealed/a.yaml".into(), true, Some(rule_id))]);

    // Removing all rules turns the allowed location back into a violation.
    let r = op.call(Method::PATCH, &url, Some(json!({ "allow_rules": [] }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["violation_count"], 2);
    let allowed: i64 =
        sqlx::query_scalar("SELECT count(*) FROM locations WHERE is_allowed OR allow_rule_id IS NOT NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(allowed, 0);
}
