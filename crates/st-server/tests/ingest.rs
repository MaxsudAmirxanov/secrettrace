//! Ingest API (stage 8): scan lifecycle, two-phase matching, locations, allow rules,
//! scopes, validation, rate limits and audit. Run with `make test`.
//!
//! Secret values are generated at runtime; only their digests ever reach the server.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc, clippy::too_many_lines)]

mod common;

use axum::Router;
use axum::http::{Method, StatusCode};
use base64::Engine as _;
use common::*;
use serde_json::{Value, json};
use sqlx::PgPool;
use st_core::{SecretType, prepare};
use st_server::app::IngestLimits;
use st_server::auth::Role;
use uuid::Uuid;

const SCANS: &str = "/api/v1/ingest/scans";
const URI: &str = "https://git.example/infra/app";
const ALL_SCOPES: &[&str] = &["ingest:profile", "ingest:match", "ingest:findings"];

/// Deterministic generator of secret-like values (xorshift), so no credential literals
/// live in the repository.
struct Gen(u64);

impl Gen {
    fn value(&mut self, prefix: &str) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        let mut s = String::from(prefix);
        for _ in 0..32 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            let i = usize::try_from(self.0 % ALPHABET.len() as u64).unwrap();
            s.push(char::from(ALPHABET[i]));
        }
        s
    }
}

fn digest(ty: SecretType, value: &str) -> String {
    prepare(ty, value).unwrap().0.to_hex()
}

/// A registered secret: its id, name and client-side digest.
struct Registered {
    id: String,
    name: String,
    digest: String,
}

struct Env {
    app: Router,
    admin: Client,
    op: Client,
}

async fn setup(pool: &PgPool, app: Router) -> Env {
    let admin = logged_in(pool, &app, "root", Role::Admin).await;
    let op = logged_in(pool, &app, "op", Role::Operator).await;
    Env { app, admin, op }
}

impl Env {
    async fn register(&mut self, name: &str, ty: SecretType, value: &str, allow_rules: Value) -> Registered {
        let (d, hints) = prepare(ty, value).unwrap();
        let body = json!({ "name": name, "type": ty, "owner": "platform", "digest": d.to_hex(), "hints": hints,
                           "allow_rules": allow_rules });
        let r = self.op.call(Method::POST, "/api/v1/secrets", Some(body)).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
        Registered { id: r.body["id"].as_str().unwrap().to_owned(), name: name.to_owned(), digest: d.to_hex() }
    }

    async fn token(&mut self, name: &str, scopes: &[&str]) -> (String, String) {
        issue_token(&mut self.admin, name, "ci", scopes).await
    }

    async fn post(&self, path: &str, token: &str, body: Value) -> Resp {
        bearer(&self.app, Method::POST, path, Some(token), Some(body)).await
    }

    async fn start(&self, token: &str, uri: &str, environment: Option<&str>, full: bool) -> Resp {
        let mut body = json!({ "source": { "type": "git_repo", "uri": uri }, "full": full });
        if let Some(e) = environment {
            body["environment"] = json!(e);
        }
        self.post(SCANS, token, body).await
    }

    /// Start a scan and return its id.
    async fn scan(&self, token: &str, environment: Option<&str>, full: bool) -> String {
        let r = self.start(token, URI, environment, full).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
        r.body["scan_id"].as_str().unwrap().to_owned()
    }

    async fn matched(&self, token: &str, scan: &str, digests: &[&str]) -> Resp {
        self.post(&format!("{SCANS}/{scan}/match"), token, json!({ "digests": digests })).await
    }

    async fn findings(&self, token: &str, scan: &str, findings: Value) -> Resp {
        self.post(&format!("{SCANS}/{scan}/findings"), token, json!({ "findings": findings })).await
    }

    async fn complete(&self, token: &str, scan: &str, body: Value) -> Resp {
        self.post(&format!("{SCANS}/{scan}/complete"), token, body).await
    }
}

/// Minimal valid finding.
fn finding(digest: &str, path: &str) -> Value {
    json!({ "digest": digest, "path": path, "in_current_state": true, "detector": "key_value", "confidence": "medium" })
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_owned()).collect()
}

fn counts(r: &Resp) -> [i64; 5] {
    ["accepted", "ignored", "new_locations", "updated_locations", "violations"]
        .map(|k| r.body[k].as_i64().unwrap_or_else(|| panic!("missing {k}: {}", r.body)))
}

#[derive(Debug, sqlx::FromRow)]
struct LocationRow {
    path: String,
    uri: String,
    source_type: String,
    environment: Option<String>,
    in_current_state: bool,
    is_allowed: bool,
    allow_rule_id: Option<i64>,
    last_job_id: Option<Uuid>,
    source_id: Option<Uuid>,
    locator: Value,
}

async fn locations(pool: &PgPool, secret_id: &str) -> Vec<LocationRow> {
    sqlx::query_as(
        "SELECT locator->>'path' AS path, uri, source_type::text AS source_type, environment, in_current_state,
                is_allowed, allow_rule_id, last_job_id, source_id, locator
         FROM locations WHERE secret_id = $1::uuid ORDER BY locator->>'path'",
    )
    .bind(secret_id)
    .fetch_all(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn full_scan_flow(pool: PgPool) {
    let mut env = setup(&pool, router(state(pool.clone()))).await;
    let mut g = Gen(0x5eed);
    let tok_value = g.value("tok_");
    let pw_value = g.value("pw-");
    let gh = env.register("deploy-token", SecretType::Token, &tok_value, json!([])).await;
    let db = env.register("db-password", SecretType::Password, &pw_value, json!([])).await;
    let unknown = digest(SecretType::Token, &g.value("nope_"));
    let (token, token_id) = env.token("github-ci", ALL_SCOPES).await;

    // 1. Start.
    let r = env.start(&token, URI, Some("prod"), true).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    let scan = r.body["scan_id"].as_str().unwrap().to_owned();
    let source_id: Uuid = r.body["source_id"].as_str().unwrap().parse().unwrap();
    assert_eq!(
        r.body["limits"],
        json!({ "max_digests_per_request": 10000, "max_findings_per_request": 5000, "digests_per_hour": 200_000 })
    );

    // 2. Match: only registered digests come back, sorted and unique; nothing else about them.
    let r = env.matched(&token, &scan, &[&gh.digest, &db.digest, &unknown, &gh.digest]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let mut expected = vec![gh.digest.clone(), db.digest.clone()];
    expected.sort();
    assert_eq!(strings(&r.body["matched"]), expected);
    let text = r.body.to_string();
    for leak in [&gh.id, &gh.name, &db.id, &db.name, &unknown] {
        assert!(!text.contains(leak.as_str()), "match response leaks {leak}");
    }

    // 3. Findings: unregistered digests are ignored, the rest become locations.
    let blob = "a".repeat(40);
    let commit = "b".repeat(40);
    let rich = json!({
        "digest": gh.digest, "path": "config/prod.env", "line": 3, "column": 13, "blob": blob, "commit": commit,
        "in_current_state": true, "detector": "known", "rule": "github_token", "confidence": "high",
        "key": "GITHUB_TOKEN", "encodings": ["base64"]
    });
    let r = env.findings(&token, &scan, json!([rich, finding(&db.digest, ".env"), finding(&unknown, "x.env")])).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(counts(&r), [2, 1, 2, 0, 2]);

    // Same location again (a historical version): updated, not new.
    let mut historical = finding(&gh.digest, "config/prod.env");
    historical["in_current_state"] = json!(false);
    let r = env.findings(&token, &scan, json!([historical])).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(counts(&r), [1, 0, 0, 1, 1]);

    let scan_id: Uuid = scan.parse().unwrap();
    let rows = locations(&pool, &gh.id).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let row = &rows[0];
    assert_eq!((row.path.as_str(), row.uri.as_str(), row.source_type.as_str()), ("config/prod.env", URI, "git_repo"));
    assert_eq!(row.environment.as_deref(), Some("prod"));
    assert_eq!((row.last_job_id, row.source_id), (Some(scan_id), Some(source_id)));
    assert!(row.in_current_state && !row.is_allowed && row.allow_rule_id.is_none());
    // Same job, stored row in current state, new report not: the stored locator stays.
    // It carries location metadata only (absent fields omitted).
    let first: Value = json!({ "path": "config/prod.env", "line": 3, "column": 13, "blob": blob, "commit": commit,
                               "detector": "known", "rule": "github_token", "confidence": "high",
                               "key": "GITHUB_TOKEN", "encodings": ["base64"] });
    assert_eq!(row.locator, first);
    let minimal = &locations(&pool, &db.id).await[0].locator;
    assert_eq!(*minimal, json!({ "path": ".env", "detector": "key_value", "confidence": "medium" }));
    let all_locators: Vec<String> =
        sqlx::query_scalar("SELECT locator::text FROM locations").fetch_all(&pool).await.unwrap();
    assert_eq!(all_locators.len(), 2);
    for l in &all_locators {
        for d in [&gh.digest, &db.digest, &unknown] {
            assert!(!l.contains(d.as_str()), "locator contains a digest: {l}");
        }
    }

    // 4. Complete.
    let r = env
        .complete(&token, &scan, json!({ "status": "succeeded", "stats": { "documents": 12, "bytes": 3400 } }))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body, json!({ "status": "succeeded", "no_longer_present": 0 }));

    let job: (String, String, i64, bool, Option<Uuid>, bool, Option<String>) = sqlx::query_as(
        "SELECT status::text, trigger, (stats->>'documents')::bigint, finished_at IS NOT NULL, api_token_id,
                full_scan, environment
         FROM scan_jobs WHERE id = $1",
    )
    .bind(scan_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let token_uuid: Uuid = token_id.parse().unwrap();
    assert_eq!(job, ("succeeded".into(), "ci".into(), 12, true, Some(token_uuid), true, Some("prod".into())));
    let source: (String, String, bool) =
        sqlx::query_as("SELECT type::text, uri, last_scan_at IS NOT NULL FROM sources WHERE id = $1")
            .bind(source_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(source, ("git_repo".into(), URI.into(), true));

    // The registry sees the new locations.
    let s = env.op.call(Method::GET, &format!("/api/v1/secrets/{}", gh.id), None).await;
    assert_eq!((s.body["location_count"].as_i64(), s.body["violation_count"].as_i64()), (Some(1), Some(1)));

    // A second scan of the same source reuses it.
    let r = env.start(&token, URI, None, false).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    assert_eq!(r.body["source_id"].as_str().unwrap().parse::<Uuid>().unwrap(), source_id);
    let sources: i64 = sqlx::query_scalar("SELECT count(*) FROM sources").fetch_one(&pool).await.unwrap();
    assert_eq!(sources, 1);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn allow_rules_are_applied_on_ingest(pool: PgPool) {
    let mut env = setup(&pool, router(state(pool.clone()))).await;
    let mut g = Gen(77);
    let rules = json!([
        { "source_type": "git_repo", "uri_pattern": "https://git.example/infra/**", "path_pattern": "sealed/**" },
        { "uri_pattern": "https://git.example/**", "path_pattern": "deploy/*.yaml", "environment": "prod" }
    ]);
    let s = env.register("sealed-key", SecretType::Token, &g.value("k_"), rules).await;
    let secret = env.op.call(Method::GET, &format!("/api/v1/secrets/{}", s.id), None).await;
    let rule_ids: Vec<i64> =
        secret.body["allow_rules"].as_array().unwrap().iter().map(|r| r["id"].as_i64().unwrap()).collect();
    let (token, _) = env.token("agent", ALL_SCOPES).await;

    let dev = env.scan(&token, Some("dev"), false).await;
    let r = env
        .findings(
            &token,
            &dev,
            json!([
                finding(&s.digest, "sealed/a.yaml"),
                finding(&s.digest, "deploy/app.yaml"),
                finding(&s.digest, ".env")
            ]),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(counts(&r), [3, 0, 3, 0, 2]);
    let rows = locations(&pool, &s.id).await;
    let state: Vec<_> = rows.iter().map(|r| (r.path.as_str(), r.is_allowed, r.allow_rule_id)).collect();
    assert_eq!(
        state,
        vec![(".env", false, None), ("deploy/app.yaml", false, None), ("sealed/a.yaml", true, Some(rule_ids[0]))]
    );

    // The environment-scoped rule applies once the same path is seen in prod.
    let prod = env.scan(&token, Some("prod"), false).await;
    let r = env.findings(&token, &prod, json!([finding(&s.digest, "deploy/app.yaml")])).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(counts(&r), [1, 0, 0, 1, 0]);
    let rows = locations(&pool, &s.id).await;
    let deploy = rows.iter().find(|r| r.path == "deploy/app.yaml").unwrap();
    assert_eq!(
        (deploy.is_allowed, deploy.allow_rule_id, deploy.environment.as_deref()),
        (true, Some(rule_ids[1]), Some("prod"))
    );
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn location_identity_and_current_state(pool: PgPool) {
    let mut env = setup(&pool, router(state(pool.clone()))).await;
    let mut g = Gen(99);
    let s = env.register("app-token", SecretType::Token, &g.value("t_"), json!([])).await;
    let (token, _) = env.token("agent", ALL_SCOPES).await;
    let state_of = |rows: &[LocationRow]| -> Vec<(String, bool)> {
        rows.iter().map(|r| (r.path.clone(), r.in_current_state)).collect()
    };

    // Two blobs of the same path in one request collapse into one location; the
    // in-current-state one wins the locator.
    let scan1 = env.scan(&token, None, true).await;
    let old_blob = json!({ "digest": s.digest, "path": "app.env", "line": 1, "blob": "1".repeat(40),
                           "in_current_state": false, "detector": "key_value", "confidence": "medium" });
    let head_blob = json!({ "digest": s.digest, "path": "app.env", "line": 5, "blob": "2".repeat(40),
                            "in_current_state": true, "detector": "key_value", "confidence": "medium" });
    let r = env.findings(&token, &scan1, json!([old_blob, head_blob, finding(&s.digest, "old.env")])).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["new_locations"], 2);
    let rows = locations(&pool, &s.id).await;
    assert_eq!(state_of(&rows), vec![("app.env".into(), true), ("old.env".into(), true)]);
    assert_eq!(rows[0].locator["line"], 5);
    assert_eq!(rows[0].locator["blob"], "2".repeat(40));

    // Later in the same job, a historical version does not clear in_current_state (OR).
    let r = env.findings(&token, &scan1, json!([old_blob])).await;
    assert_eq!(counts(&r), [1, 0, 0, 1, 1]);
    let rows = locations(&pool, &s.id).await;
    assert!(rows[0].in_current_state);
    assert_eq!(rows[0].locator["line"], 5, "in-current-state locator kept");
    let r = env.complete(&token, &scan1, json!({ "status": "succeeded" })).await;
    assert_eq!(r.body["no_longer_present"], 0, "{}", r.body);

    // A full scan that no longer reports old.env marks it as gone from the current state.
    let scan2 = env.scan(&token, None, true).await;
    let r = env.findings(&token, &scan2, json!([finding(&s.digest, "app.env")])).await;
    assert_eq!(counts(&r), [1, 0, 0, 1, 1]);
    let r = env.complete(&token, &scan2, json!({ "status": "succeeded" })).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["no_longer_present"], 1);
    let rows = locations(&pool, &s.id).await;
    assert_eq!(state_of(&rows), vec![("app.env".into(), true), ("old.env".into(), false)]);

    // A partial (non-full) scan reporting nothing changes nothing.
    let scan3 = env.scan(&token, None, false).await;
    let r = env.complete(&token, &scan3, json!({ "status": "succeeded" })).await;
    assert_eq!(r.body["no_longer_present"], 0, "{}", r.body);
    // A failed full scan does not mark anything either.
    let scan4 = env.scan(&token, None, true).await;
    let r = env.complete(&token, &scan4, json!({ "status": "failed", "error": "clone timed out" })).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["status"], "failed");
    let rows = locations(&pool, &s.id).await;
    assert_eq!(state_of(&rows), vec![("app.env".into(), true), ("old.env".into(), false)]);
    let failed: (String, Option<String>) =
        sqlx::query_as("SELECT status::text, error FROM scan_jobs WHERE id = $1::uuid")
            .bind(&scan4)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(failed, ("failed".into(), Some("clone timed out".into())));

    // In a new job, a not-in-current-state report replaces the stored value.
    let scan5 = env.scan(&token, None, false).await;
    let mut gone = finding(&s.digest, "app.env");
    gone["in_current_state"] = json!(false);
    let r = env.findings(&token, &scan5, json!([gone])).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let rows = locations(&pool, &s.id).await;
    assert_eq!(state_of(&rows), vec![("app.env".into(), false), ("old.env".into(), false)]);
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM locations").fetch_one(&pool).await.unwrap();
    assert_eq!(total, 2);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn matching_covers_every_pepper_version(pool: PgPool) {
    let b64 = base64::engine::general_purpose::STANDARD;
    let v1 = format!("1:{}", b64.encode([1u8; 32]));
    let mut env = setup(&pool, router(state_with_pepper(pool.clone(), &v1))).await;
    let mut g = Gen(4242);
    let old = env.register("old", SecretType::Token, &g.value("o_"), json!([])).await;
    let (token, _) = env.token("agent", ALL_SCOPES).await;

    // "Restart" with a second pepper version; new registrations use v2.
    let rotated = format!("{v1},2:{}", b64.encode([3u8; 32]));
    env.app = router(state_with_pepper(pool.clone(), &rotated));
    env.op = logged_in(&pool, &env.app, "op2", Role::Operator).await;
    let new = env.register("new", SecretType::Token, &g.value("n_"), json!([])).await;
    let versions: Vec<i16> =
        sqlx::query_scalar("SELECT pepper_version FROM secrets ORDER BY name DESC").fetch_all(&pool).await.unwrap();
    assert_eq!(versions, vec![1, 2], "old under v1, new under v2");

    let scan = env.scan(&token, None, false).await;
    let r = env.matched(&token, &scan, &[&old.digest, &new.digest]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(strings(&r.body["matched"]).len(), 2, "{}", r.body);
    let r = env.findings(&token, &scan, json!([finding(&old.digest, "a"), finding(&new.digest, "b")])).await;
    assert_eq!(counts(&r)[..3], [2, 0, 2]);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn revoked_and_rotated_secrets_still_match(pool: PgPool) {
    let mut env = setup(&pool, router(state(pool.clone()))).await;
    let mut g = Gen(31337);
    let revoked = env.register("revoked", SecretType::Token, &g.value("r_"), json!([])).await;
    let rotated = env.register("rotated", SecretType::Token, &g.value("q_"), json!([])).await;
    for (s, status) in [(&revoked, "revoked"), (&rotated, "rotated")] {
        let r =
            env.op.call(Method::PATCH, &format!("/api/v1/secrets/{}", s.id), Some(json!({ "status": status }))).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    }
    let (token, _) = env.token("agent", ALL_SCOPES).await;
    let scan = env.scan(&token, None, false).await;
    let r = env.matched(&token, &scan, &[&revoked.digest, &rotated.digest]).await;
    assert_eq!(strings(&r.body["matched"]).len(), 2, "{}", r.body);
    let r = env.findings(&token, &scan, json!([finding(&revoked.digest, "a"), finding(&rotated.digest, "b")])).await;
    assert_eq!(counts(&r), [2, 0, 2, 0, 2]);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn scopes_tokens_and_scan_ownership(pool: PgPool) {
    let mut env = setup(&pool, router(state(pool.clone()))).await;
    let mut g = Gen(5);
    let s = env.register("x", SecretType::Token, &g.value("x_"), json!([])).await;
    let (full, _) = env.token("full", ALL_SCOPES).await;
    let (no_profile, _) = env.token("no-profile", &["ingest:match", "ingest:findings"]).await;
    let (no_match, _) = env.token("no-match", &["ingest:profile", "ingest:findings"]).await;
    let (no_findings, _) = env.token("no-findings", &["ingest:profile", "ingest:match"]).await;

    // Each endpoint requires its own scope.
    assert_eq!(env.start(&no_profile, URI, None, false).await.status, StatusCode::FORBIDDEN);
    let mine = env.scan(&no_match, None, false).await;
    assert_eq!(env.matched(&no_match, &mine, &[&s.digest]).await.status, StatusCode::FORBIDDEN);
    let mine = env.scan(&no_findings, None, false).await;
    assert_eq!(env.findings(&no_findings, &mine, json!([finding(&s.digest, "a")])).await.status, StatusCode::FORBIDDEN);
    let other = env.scan(&full, None, false).await;
    assert_eq!(env.complete(&no_profile, &other, json!({ "status": "succeeded" })).await.status, StatusCode::FORBIDDEN);

    // Another token's scan does not exist for you; neither does a random id.
    let (stranger, _) = env.token("stranger", ALL_SCOPES).await;
    assert_eq!(env.matched(&stranger, &other, &[&s.digest]).await.status, StatusCode::NOT_FOUND);
    assert_eq!(env.findings(&stranger, &other, json!([finding(&s.digest, "a")])).await.status, StatusCode::NOT_FOUND);
    assert_eq!(env.complete(&stranger, &other, json!({ "status": "succeeded" })).await.status, StatusCode::NOT_FOUND);
    let random = Uuid::new_v4().to_string();
    assert_eq!(env.matched(&full, &random, &[&s.digest]).await.status, StatusCode::NOT_FOUND);
    assert_eq!(env.matched(&full, "not-a-uuid", &[&s.digest]).await.status, StatusCode::NOT_FOUND);
    let none: i64 = sqlx::query_scalar("SELECT count(*) FROM locations").fetch_one(&pool).await.unwrap();
    assert_eq!(none, 0);

    // Authentication.
    let body = json!({ "source": { "type": "git_repo", "uri": URI } });
    assert_eq!(bearer(&env.app, Method::POST, SCANS, None, Some(body.clone())).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(env.post(SCANS, "stk_garbage", body.clone()).await.status, StatusCode::UNAUTHORIZED);
    let (revoked, revoked_id) = env.token("revoked", ALL_SCOPES).await;
    let revoked_scan = env.scan(&revoked, None, false).await;
    let r = env.admin.call(Method::DELETE, &format!("/api/v1/api-tokens/{revoked_id}"), None).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(env.post(SCANS, &revoked, body).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(env.matched(&revoked, &revoked_scan, &[&s.digest]).await.status, StatusCode::UNAUTHORIZED);
    // A browser session is not a machine credential.
    let r = env.op.call(Method::POST, SCANS, Some(json!({ "source": { "type": "git_repo", "uri": URI } }))).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn finished_scans_reject_further_calls(pool: PgPool) {
    let mut env = setup(&pool, router(state(pool.clone()))).await;
    let mut g = Gen(6);
    let s = env.register("x", SecretType::Token, &g.value("x_"), json!([])).await;
    let (token, _) = env.token("agent", ALL_SCOPES).await;
    for status in ["succeeded", "failed"] {
        let scan = env.scan(&token, None, false).await;
        assert_eq!(env.complete(&token, &scan, json!({ "status": status })).await.status, StatusCode::OK);
        assert_eq!(env.matched(&token, &scan, &[&s.digest]).await.status, StatusCode::CONFLICT);
        assert_eq!(env.findings(&token, &scan, json!([finding(&s.digest, "a")])).await.status, StatusCode::CONFLICT);
        assert_eq!(env.complete(&token, &scan, json!({ "status": "succeeded" })).await.status, StatusCode::CONFLICT);
    }
    // A scan older than 24 h is no longer running for ingest purposes.
    let stale = env.scan(&token, None, false).await;
    sqlx::query("UPDATE scan_jobs SET started_at = now() - interval '25 hours' WHERE id = $1::uuid")
        .bind(&stale)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(env.matched(&token, &stale, &[&s.digest]).await.status, StatusCode::CONFLICT);
    assert_eq!(env.findings(&token, &stale, json!([finding(&s.digest, "a")])).await.status, StatusCode::CONFLICT);
    // R4: a stale scan cannot succeed, but it can still be closed as failed.
    let r = env.complete(&token, &stale, json!({ "status": "succeeded" })).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.body);
    let r = env.complete(&token, &stale, json!({ "status": "failed", "error": "abandoned" })).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let status: String = sqlx::query_scalar("SELECT status::text FROM scan_jobs WHERE id = $1::uuid")
        .bind(&stale)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "failed");
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn source_validation(pool: PgPool) {
    let mut env = setup(&pool, router(state(pool.clone()))).await;
    let (token, _) = env.token("agent", ALL_SCOPES).await;
    let creds = "https://deploy:hunter2hunter2@git.example/infra/app";
    for uri in [creds, "https://git.example/a b", "", "https://git.example/\u{7}bell"] {
        let r = env.start(&token, uri, None, false).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{uri:?}: {}", r.body);
    }
    let long = format!("https://git.example/{}", "a".repeat(2048));
    assert_eq!(env.start(&token, &long, None, false).await.status, StatusCode::UNPROCESSABLE_ENTITY);
    for e in ["pr od", "", &"e".repeat(65)] {
        assert_eq!(env.start(&token, URI, Some(e), false).await.status, StatusCode::UNPROCESSABLE_ENTITY, "{e:?}");
    }
    let bad_type = env.post(SCANS, &token, json!({ "source": { "type": "ftp", "uri": URI } })).await;
    assert_eq!(bad_type.status, StatusCode::UNPROCESSABLE_ENTITY);
    // `user@host:path` scp-style git URIs carry no password and are fine.
    assert_eq!(env.start(&token, "git@github.com:acme/app.git", None, false).await.status, StatusCode::CREATED);

    // Long URIs get a bounded, unique auto-generated source name.
    let long_ok = format!("https://git.example/{}", "b".repeat(400));
    assert_eq!(env.start(&token, &long_ok, None, false).await.status, StatusCode::CREATED);
    let name: String =
        sqlx::query_scalar("SELECT name FROM sources WHERE uri = $1").bind(&long_ok).fetch_one(&pool).await.unwrap();
    assert_eq!(name.chars().count(), 200);
    assert!(name.starts_with("git_repo:https://git.example/"));

    // A disabled source refuses new scans.
    assert_eq!(env.start(&token, URI, None, false).await.status, StatusCode::CREATED);
    sqlx::query("UPDATE sources SET enabled = false WHERE uri = $1").bind(URI).execute(&pool).await.unwrap();
    assert_eq!(env.start(&token, URI, None, false).await.status, StatusCode::CONFLICT);

    // No rejected request left the credential in the database (sources, jobs or audit).
    let dump: String = sqlx::query_scalar(
        "SELECT coalesce(string_agg(t, ' '), '') FROM (
            SELECT uri || name AS t FROM sources
            UNION ALL SELECT details::text FROM audit_log) x",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!dump.contains("hunter2"), "credential stored somewhere");
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn payload_validation(pool: PgPool) {
    // Large enough to reach the item-count checks instead of the body limit.
    let mut env = setup(&pool, router_with_body_limit(state(pool.clone()), 4 * 1024 * 1024)).await;
    let mut g = Gen(8);
    let s = env.register("x", SecretType::Token, &g.value("x_"), json!([])).await;
    let (token, _) = env.token("agent", ALL_SCOPES).await;
    let scan = env.scan(&token, None, false).await;
    let unprocessable = StatusCode::UNPROCESSABLE_ENTITY;

    // Match.
    let upper = s.digest.to_uppercase();
    for bad in [json!({ "digests": [] }), json!({ "digests": [upper] }), json!({ "digests": ["abc"] }), json!({})] {
        let r = env.post(&format!("{SCANS}/{scan}/match"), &token, bad.clone()).await;
        assert_eq!(r.status, unprocessable, "{bad}: {}", r.body);
    }
    let many: Vec<String> = (0..10_001u32).map(|i| format!("{i:064x}")).collect();
    let r = env.post(&format!("{SCANS}/{scan}/match"), &token, json!({ "digests": many[..10_000] })).await;
    assert_eq!(r.status, StatusCode::OK, "10000 is allowed: {}", r.body);
    assert_eq!(r.body["matched"], json!([]));
    let r = env.post(&format!("{SCANS}/{scan}/match"), &token, json!({ "digests": many })).await;
    assert_eq!(r.status, unprocessable);

    // Findings.
    let ok = finding(&s.digest, "a.env");
    let with = |key: &str, value: Value| {
        let mut f = ok.clone();
        f[key] = value;
        f
    };
    let without = |key: &str| {
        let mut f = ok.clone();
        f.as_object_mut().unwrap().remove(key);
        f
    };
    let bad_items = [
        with("digest", json!("zz")),
        with("detector", json!("regex_magic")),
        with("confidence", json!("certain")),
        with("path", json!("a\u{0}b")),
        with("path", json!("line\nbreak")),
        with("path", json!("")),
        with("path", json!("p".repeat(1025))),
        with("line", json!(0)),
        with("column", json!(-1)),
        with("blob", json!("XYZ")),
        with("commit", json!("A".repeat(40))),
        with("rule", json!("Bad Rule")),
        with("key", json!("k".repeat(65))),
        with("key", json!("a b")),
        with("encodings", json!(["rot13"])),
        with("encodings", json!(vec!["base64"; 9])),
        without("in_current_state"),
        without("path"),
        without("detector"),
    ];
    for item in bad_items {
        let r = env.findings(&token, &scan, json!([item])).await;
        assert_eq!(r.status, unprocessable, "{item}: {}", r.body);
    }
    let r = env.findings(&token, &scan, json!([])).await;
    assert_eq!(r.status, unprocessable);
    let too_many: Vec<Value> = (0..5001).map(|i| finding(&s.digest, &format!("f{i}"))).collect();
    let r = env.findings(&token, &scan, json!(too_many)).await;
    assert_eq!(r.status, unprocessable);
    let none: i64 = sqlx::query_scalar("SELECT count(*) FROM locations").fetch_one(&pool).await.unwrap();
    assert_eq!(none, 0, "rejected requests store nothing");

    // Complete.
    let wide: serde_json::Map<String, Value> = (0..33).map(|i| (format!("k{i}"), json!(1))).collect();
    let bad_completes = [
        json!({ "status": "running" }),
        json!({}),
        json!({ "status": "succeeded", "stats": wide }),
        json!({ "status": "succeeded", "stats": { "documents": -1 } }),
        json!({ "status": "succeeded", "stats": { "documents": 1.5 } }),
        json!({ "status": "succeeded", "stats": { "Documents": 1 } }),
        json!({ "status": "succeeded", "stats": { "documents": "many" } }),
        json!({ "status": "succeeded", "stats": [1, 2] }),
        json!({ "status": "failed", "error": "e".repeat(501) }),
        json!({ "status": "failed", "error": "line\nbreak" }),
    ];
    for body in bad_completes {
        let r = env.complete(&token, &scan, body.clone()).await;
        assert_eq!(r.status, unprocessable, "{body}: {}", r.body);
    }
    // Still running after all the rejected attempts.
    let r = env.complete(&token, &scan, json!({ "status": "succeeded", "stats": { "documents": 1 } })).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn match_rate_limits(pool: PgPool) {
    let limits = IngestLimits { digests_per_hour: 5, ..IngestLimits::default() };
    let mut env = setup(&pool, router(state(pool.clone()).with_ingest_limits(limits))).await;
    let (token, _) = env.token("agent", ALL_SCOPES).await;
    let (other, _) = env.token("other", ALL_SCOPES).await;
    let scan = env.scan(&token, None, false).await;
    let d = |i: u32| format!("{i:064x}");

    let r = env.matched(&token, &scan, &[&d(1), &d(1), &d(2), &d(3)]).await;
    assert_eq!(r.status, StatusCode::OK, "duplicates count once: {}", r.body);
    assert_eq!(env.matched(&token, &scan, &[&d(4), &d(5)]).await.status, StatusCode::OK);
    let r = env.matched(&token, &scan, &[&d(6)]).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{}", r.body);
    // Budgets are per token.
    let other_scan = env.scan(&other, None, false).await;
    assert_eq!(env.matched(&other, &other_scan, &[&d(6)]).await.status, StatusCode::OK);

    // Request-count limit.
    let limits = IngestLimits { match_requests_per_minute: 2, ..IngestLimits::default() };
    env.app = router(state(pool.clone()).with_ingest_limits(limits));
    let scan = env.scan(&token, None, false).await;
    let statuses = [
        env.matched(&token, &scan, &[&d(7)]).await.status,
        env.matched(&token, &scan, &[&d(8)]).await.status,
        env.matched(&token, &scan, &[&d(9)]).await.status,
    ];
    assert_eq!(statuses, [StatusCode::OK, StatusCode::OK, StatusCode::TOO_MANY_REQUESTS]);
}

/// `(action, actor_type, actor_id, target_type, target_id, details)`.
type AuditRow = (String, String, String, Option<String>, Option<String>, Value);

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn ingest_is_audited_without_digests(pool: PgPool) {
    let mut env = setup(&pool, router(state(pool.clone()))).await;
    let mut g = Gen(12);
    let s = env.register("audited", SecretType::Token, &g.value("a_"), json!([])).await;
    let unknown = digest(SecretType::Token, &g.value("u_"));
    let (token, token_id) = env.token("agent", ALL_SCOPES).await;
    let scan = env.scan(&token, Some("prod"), true).await;
    let r = env.matched(&token, &scan, &[&s.digest, &unknown, &s.digest]).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = env.findings(&token, &scan, json!([finding(&s.digest, "deploy/.env"), finding(&unknown, "x")])).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = env.complete(&token, &scan, json!({ "status": "succeeded" })).await;
    assert_eq!(r.status, StatusCode::OK);

    let rows: Vec<AuditRow> = sqlx::query_as(
        "SELECT action, actor_type, actor_id, target_type, target_id, details FROM audit_log
         WHERE action LIKE 'ingest.%' ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let actions: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
    assert_eq!(actions, ["ingest.scan_start", "ingest.match", "ingest.findings", "ingest.scan_complete"]);
    for (_, actor_type, actor_id, target_type, target_id, _) in &rows {
        assert_eq!((actor_type.as_str(), actor_id.as_str()), ("token", token_id.as_str()));
        assert_eq!((target_type.as_deref(), target_id.as_deref()), (Some("scan_job"), Some(scan.as_str())));
    }
    let match_details = &rows[1].5;
    assert_eq!((match_details["submitted"].as_i64(), match_details["matched"].as_i64()), (Some(2), Some(1)));
    let findings_details = &rows[2].5;
    assert_eq!((findings_details["accepted"].as_i64(), findings_details["ignored"].as_i64()), (Some(1), Some(1)));

    let all: Vec<String> = sqlx::query_scalar("SELECT details::text FROM audit_log").fetch_all(&pool).await.unwrap();
    for text in &all {
        for d in [&s.digest, &unknown] {
            assert!(!text.contains(d.as_str()), "audit contains a digest: {text}");
        }
    }
    let report = st_server::audit::verify_chain(&pool).await;
    assert!(report.is_ok(), "audit chain broken: {report:?}");
}

// ── security review addendum (R1–R6) ───────────────────────────────────────

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn findings_share_the_match_budgets(pool: PgPool) {
    // R1: /findings re-matches digests, so it is an oracle too and spends the same budgets.
    let limits = IngestLimits { digests_per_hour: 5, ..IngestLimits::default() };
    let mut env = setup(&pool, router(state(pool.clone()).with_ingest_limits(limits))).await;
    let d = |i: u32| format!("{i:064x}");
    let items = |range: std::ops::Range<u32>| -> Value {
        Value::Array(range.map(|i| finding(&d(i), &format!("f{i}"))).collect())
    };

    // Budget spent by /match → /findings is refused.
    let (a, _) = env.token("a", ALL_SCOPES).await;
    let scan = env.scan(&a, None, false).await;
    assert_eq!(env.matched(&a, &scan, &[&d(1), &d(2), &d(3), &d(4), &d(5)]).await.status, StatusCode::OK);
    let r = env.findings(&a, &scan, items(6..7)).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{}", r.body);

    // Budget spent by /findings → /match is refused.
    let (b, _) = env.token("b", ALL_SCOPES).await;
    let scan = env.scan(&b, None, false).await;
    let r = env.findings(&b, &scan, items(10..15)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["ignored"], 5);
    assert_eq!(env.matched(&b, &scan, &[&d(20)]).await.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(env.findings(&b, &scan, items(21..22)).await.status, StatusCode::TOO_MANY_REQUESTS);

    // The request budget is shared as well.
    let limits = IngestLimits { match_requests_per_minute: 2, ..IngestLimits::default() };
    env.app = router(state(pool.clone()).with_ingest_limits(limits));
    let (c, _) = env.token("c", ALL_SCOPES).await;
    let scan = env.scan(&c, None, false).await;
    let statuses = [
        env.matched(&c, &scan, &[&d(30)]).await.status,
        env.findings(&c, &scan, items(31..32)).await.status,
        env.findings(&c, &scan, items(32..33)).await.status,
    ];
    assert_eq!(statuses, [StatusCode::OK, StatusCode::OK, StatusCode::TOO_MANY_REQUESTS]);
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM locations").fetch_one(&pool).await.unwrap();
    assert_eq!(stored, 0);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn credential_bypass_uris_are_rejected(pool: PgPool) {
    // R2: variants of "credentials in the URI" that a naive `://userinfo@` check misses.
    let mut env = setup(&pool, router(state(pool.clone()))).await;
    let (token, _) = env.token("agent", ALL_SCOPES).await;
    let rejected = [
        "https:///u:p@h/r",
        r"https:\\u:p@h/r",
        "https:/u:p@h/r",
        "HTTPS://u:p@h/r",
        "user:pass@host/repo",
        "https://gitlab/x?private_token=abc",
        "https://h/x#access_token=abc",
        "https://h/x?Password=abc",
        "https://h/x?a=1&api_key=abc",
        r"https://h\u@x/r",
        // Any userinfo after `://` is refused, even without a password (contract §1).
        "ssh://git@h/org/repo.git",
    ];
    for uri in rejected {
        let r = env.start(&token, uri, None, false).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{uri}: {}", r.body);
        assert!(!r.body.to_string().contains("abc"), "error echoes the URI: {}", r.body);
    }
    for uri in ["git@github.com:org/repo.git", "https://h/repo?ref=main"] {
        let r = env.start(&token, uri, None, false).await;
        assert_eq!(r.status, StatusCode::CREATED, "{uri}: {}", r.body);
    }
    let uris: Vec<String> = sqlx::query_scalar("SELECT uri FROM sources ORDER BY uri").fetch_all(&pool).await.unwrap();
    assert_eq!(uris, ["git@github.com:org/repo.git", "https://h/repo?ref=main"]);
    let audit: Vec<String> = sqlx::query_scalar("SELECT details::text || coalesce(target_id, '') FROM audit_log")
        .fetch_all(&pool)
        .await
        .unwrap();
    for row in &audit {
        assert!(!row.contains("abc") && !row.contains("u:p@") && !row.contains("pass@"), "{row}");
    }
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn scan_starts_are_rate_limited(pool: PgPool) {
    // R3: starting scans is bounded per token.
    let limits = IngestLimits { scan_starts_per_minute: 2, ..IngestLimits::default() };
    let mut env = setup(&pool, router(state(pool.clone()).with_ingest_limits(limits))).await;
    let (a, _) = env.token("a", ALL_SCOPES).await;
    let (b, _) = env.token("b", ALL_SCOPES).await;
    let statuses = [
        env.start(&a, URI, None, false).await.status,
        env.start(&a, URI, None, false).await.status,
        env.start(&a, URI, None, false).await.status,
        env.start(&b, URI, None, false).await.status,
    ];
    assert_eq!(
        statuses,
        [StatusCode::CREATED, StatusCode::CREATED, StatusCode::TOO_MANY_REQUESTS, StatusCode::CREATED]
    );
    let jobs: i64 = sqlx::query_scalar("SELECT count(*) FROM scan_jobs").fetch_one(&pool).await.unwrap();
    assert_eq!(jobs, 3);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn full_scans_only_clear_their_own_older_rows(pool: PgPool) {
    let mut env = setup(&pool, router(state(pool.clone()))).await;
    let mut g = Gen(2024);
    let s = env.register("shared", SecretType::Token, &g.value("s_"), json!([])).await;
    let (a, _) = env.token("a", ALL_SCOPES).await;
    let (b, _) = env.token("b", ALL_SCOPES).await;
    let current = |pool: PgPool, id: String| async move {
        locations(&pool, &id).await.into_iter().map(|r| (r.path, r.in_current_state)).collect::<Vec<_>>()
    };

    // R3a: token A reported a.env; token B's full scan of the same source reports nothing.
    let ja = env.scan(&a, None, true).await;
    assert_eq!(env.findings(&a, &ja, json!([finding(&s.digest, "a.env")])).await.status, StatusCode::OK);
    assert_eq!(env.complete(&a, &ja, json!({ "status": "succeeded" })).await.status, StatusCode::OK);
    let jb = env.scan(&b, None, true).await;
    let r = env.complete(&b, &jb, json!({ "status": "succeeded" })).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["no_longer_present"], 0, "another token's full scan must not clear A's rows");
    assert_eq!(current(pool.clone(), s.id.clone()).await, vec![("a.env".to_owned(), true)]);

    // R3b: J1 (full) starts; a concurrent J2 of the same token reports p.env after J1 began.
    // Completing J1 clears a.env (older than J1) but not p.env.
    let j1 = env.scan(&a, None, true).await;
    let j2 = env.scan(&a, None, false).await;
    assert_eq!(env.findings(&a, &j2, json!([finding(&s.digest, "p.env")])).await.status, StatusCode::OK);
    let r = env.complete(&a, &j1, json!({ "status": "succeeded" })).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["no_longer_present"], 1, "{}", r.body);
    assert_eq!(
        current(pool.clone(), s.id.clone()).await,
        vec![("a.env".to_owned(), false), ("p.env".to_owned(), true)]
    );
    assert_eq!(env.complete(&a, &j2, json!({ "status": "succeeded" })).await.status, StatusCode::OK);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn a_full_findings_batch_fits_the_default_body_limit(pool: PgPool) {
    // R5: the test router uses a 64 KiB global limit; /findings has its own (≥ 8 MiB).
    let mut env = setup(&pool, router(state(pool.clone()))).await;
    let mut g = Gen(55);
    let s = env.register("big", SecretType::Token, &g.value("b_"), json!([])).await;
    let (token, _) = env.token("agent", ALL_SCOPES).await;
    let scan = env.scan(&token, None, false).await;
    let items: Vec<Value> = (0..5000u32)
        .map(|i| {
            json!({ "digest": s.digest, "path": format!("services/team-{i:04}/config/application-production.env"),
                    "line": i + 1, "column": 17, "blob": format!("{i:040x}"), "commit": format!("{:040x}", i + 7),
                    "in_current_state": true, "detector": "key_value", "rule": "generic_secret",
                    "confidence": "medium", "key": "SERVICE_API_TOKEN", "encodings": ["base64", "json_string"] })
        })
        .collect();
    let body = json!({ "findings": items });
    assert!(body.to_string().len() > 1024 * 1024, "the batch must exceed the global limit by far");
    let r = env.post(&format!("{SCANS}/{scan}/findings"), &token, body).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["new_locations"], 5000);
    // Other routes keep the global limit.
    let big_match = json!({ "digests": (0..2000u32).map(|i| format!("{i:064x}")).collect::<Vec<_>>() });
    let r = env.post(&format!("{SCANS}/{scan}/match"), &token, big_match).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE, "{}", r.body);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn validation_errors_do_not_echo_input(pool: PgPool) {
    // R6: a misplaced secret in a JSON field must not come back in the 422 body.
    let mut env = setup(&pool, router(state(pool.clone()))).await;
    let mut g = Gen(66);
    let s = env.register("echo", SecretType::Token, &g.value("e_"), json!([])).await;
    let (token, _) = env.token("agent", ALL_SCOPES).await;
    let scan = env.scan(&token, None, false).await;
    let marker = "MARKER_q7Zx9vLp2Rw";

    let mut wrong_type = finding(&s.digest, "a.env");
    wrong_type["line"] = json!(marker);
    let mut bad_variant = finding(&s.digest, "a.env");
    bad_variant["detector"] = json!(marker);
    let mut bad_confidence = finding(&s.digest, "a.env");
    bad_confidence["confidence"] = json!(marker);
    for item in [wrong_type, bad_variant, bad_confidence] {
        let r = env.findings(&token, &scan, json!([item])).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.body);
        assert!(!r.body.to_string().contains(marker), "422 echoes input: {}", r.body);
    }
    let r = env.post(&format!("{SCANS}/{scan}/match"), &token, json!({ "digests": [marker] })).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!r.body.to_string().contains(marker), "{}", r.body);
    let r = env.post(SCANS, &token, json!({ "source": { "type": marker, "uri": URI } })).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!r.body.to_string().contains(marker), "{}", r.body);

    // Every ApiJson user is covered, e.g. the registry PATCH (unknown field, unknown variant).
    let url = format!("/api/v1/secrets/{}", s.id);
    for body in [json!({ marker: 1 }), json!({ "status": marker }), json!({ "owner": [marker] })] {
        let r = env.op.call(Method::PATCH, &url, Some(body.clone())).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}: {}", r.body);
        assert!(!r.body.to_string().contains(marker), "422 echoes input: {}", r.body);
    }
}
