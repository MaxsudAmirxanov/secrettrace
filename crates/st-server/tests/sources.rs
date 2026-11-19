//! Sources & scans API (stage 9): CRUD, RBAC, CSRF, validation, manual scans, cancellation,
//! listing. Written against the stage 9 contract. Run with `make test`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc, clippy::too_many_lines)]

mod common;

use std::collections::BTreeSet;

use axum::http::{Method, StatusCode, header};
use chrono::{DateTime, Utc};
use common::*;
use serde_json::{Value, json};
use sqlx::PgPool;
use st_server::auth::Role;
use st_server::schedule::Schedule;
use uuid::Uuid;

const SOURCES: &str = "/api/v1/sources";
const SCANS: &str = "/api/v1/scans";
const URI: &str = "https://git.example/infra/app.git";

const SOURCE_KEYS: &[&str] = &[
    "id",
    "name",
    "type",
    "uri",
    "environment",
    "credential_ref",
    "schedule",
    "enabled",
    "config",
    "created_at",
    "last_scan_at",
    "next_scan_at",
    "active_scan",
];
const SCAN_KEYS: &[&str] = &[
    "id",
    "source_id",
    "source_name",
    "trigger",
    "status",
    "full_scan",
    "attempts",
    "requested_by",
    "created_at",
    "started_at",
    "finished_at",
    "run_after",
    "stats",
    "error",
];

fn keys(v: &Value) -> BTreeSet<String> {
    v.as_object().unwrap_or_else(|| panic!("not an object: {v}")).keys().cloned().collect()
}

/// Responses carry exactly the documented fields (nullable ones may be omitted).
fn assert_shape(v: &Value, allowed: &[&str], required: &[&str]) {
    let got = keys(v);
    let allowed: BTreeSet<String> = allowed.iter().map(|s| (*s).to_owned()).collect();
    let extra: Vec<_> = got.difference(&allowed).collect();
    assert!(extra.is_empty(), "unexpected fields {extra:?} in {v}");
    for r in required {
        assert!(got.contains(*r), "missing {r} in {v}");
    }
}

fn assert_source_shape(v: &Value) {
    assert_shape(v, SOURCE_KEYS, &["id", "name", "type", "uri", "enabled", "config", "created_at"]);
}

fn assert_scan_shape(v: &Value) {
    assert_shape(
        v,
        SCAN_KEYS,
        &["id", "trigger", "status", "full_scan", "attempts", "created_at", "run_after", "stats"],
    );
}

fn ts(v: &Value) -> DateTime<Utc> {
    v.as_str().unwrap_or_else(|| panic!("not a timestamp: {v}")).parse().unwrap()
}

fn id_of(r: &Resp) -> String {
    r.body["id"].as_str().unwrap_or_else(|| panic!("no id: {}", r.body)).to_owned()
}

async fn create(c: &mut Client, body: Value) -> Resp {
    c.call(Method::POST, SOURCES, Some(body)).await
}

async fn create_ok(c: &mut Client, body: Value) -> String {
    let r = create(c, body).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    id_of(&r)
}

async fn enqueue(c: &mut Client, source: &str) -> Resp {
    c.call(Method::POST, &format!("{SOURCES}/{source}/scans"), None).await
}

async fn job_row(pool: &PgPool, job: &str) -> (String, Option<String>, Option<Uuid>, bool) {
    sqlx::query_as("SELECT status::text, error, source_id, finished_at IS NOT NULL FROM scan_jobs WHERE id = $1::uuid")
        .bind(job)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn user_id(pool: &PgPool, username: &str) -> String {
    let id: Uuid =
        sqlx::query_scalar("SELECT id FROM users WHERE username = $1").bind(username).fetch_one(pool).await.unwrap();
    id.to_string()
}

async fn audit_details(pool: &PgPool, action: &str) -> Vec<(String, Value)> {
    sqlx::query_as("SELECT actor_type, details FROM audit_log WHERE action = $1 ORDER BY id")
        .bind(action)
        .fetch_all(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn create_read_update_delete(pool: PgPool) {
    let app = router(state(pool.clone()));
    let mut op = logged_in(&pool, &app, "op", Role::Operator).await;

    let before = Utc::now();
    let r = create(
        &mut op,
        json!({
            "name": "infra-app", "type": "git_repo", "uri": URI, "environment": "prod",
            "credential_ref": "github_infra", "schedule": "0  3 * * *",
            "config": { "username": "x-access-token", "max_blob_bytes": 1_048_576 }
        }),
    )
    .await;
    let after = Utc::now();
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    let s = &r.body;
    assert_source_shape(s);
    assert_eq!(s["name"], "infra-app");
    assert_eq!(s["type"], "git_repo");
    assert_eq!(s["uri"], URI);
    assert_eq!(s["environment"], "prod");
    assert_eq!(s["credential_ref"], "github_infra");
    assert_eq!(s["schedule"], "0 3 * * *", "normalized expression is stored");
    assert_eq!(s["enabled"], true);
    assert_eq!(s["config"], json!({ "username": "x-access-token", "max_blob_bytes": 1_048_576 }));
    assert!(s.get("active_scan").is_none_or(Value::is_null), "{s}");
    let sched = Schedule::parse("0 3 * * *").unwrap();
    let next = ts(&s["next_scan_at"]);
    assert!(
        Some(next) == sched.next_after(before) || Some(next) == sched.next_after(after),
        "next_scan_at {next} is the next 03:00 UTC"
    );
    let id = id_of(&r);

    // Read back, single and in the list.
    let got = op.call(Method::GET, &format!("{SOURCES}/{id}"), None).await;
    assert_eq!(got.status, StatusCode::OK, "{}", got.body);
    assert_source_shape(&got.body);
    assert_eq!(got.body["credential_ref"], "github_infra");
    let list = op.call(Method::GET, SOURCES, None).await;
    assert_eq!(list.status, StatusCode::OK);
    let items = list.body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_source_shape(&items[0]);

    // Minimal source: defaults.
    let minimal = create(&mut op, json!({ "name": "logs", "type": "app_log", "uri": "host:web-1/var/log/app" })).await;
    assert_eq!(minimal.status, StatusCode::CREATED, "{}", minimal.body);
    assert_eq!(minimal.body["enabled"], true);
    assert!(minimal.body.get("next_scan_at").is_none_or(Value::is_null));
    assert!(minimal.body.get("schedule").is_none_or(Value::is_null));

    // PATCH: nullable fields cleared with null, absent ones unchanged, config replaced.
    let url = format!("{SOURCES}/{id}");
    let r = op
        .call(
            Method::PATCH,
            &url,
            Some(json!({ "name": "infra-app-2", "credential_ref": null, "environment": null, "config": { "max_blob_bytes": 4096 } })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["name"], "infra-app-2");
    assert!(r.body.get("credential_ref").is_none_or(Value::is_null), "{}", r.body);
    assert!(r.body.get("environment").is_none_or(Value::is_null), "{}", r.body);
    assert_eq!(r.body["config"], json!({ "max_blob_bytes": 4096 }), "config is replaced as a whole");
    assert_eq!(r.body["schedule"], "0 3 * * *", "absent field unchanged");
    assert_eq!(r.body["uri"], URI);

    // Schedule cleared → no next scan; set again → recomputed.
    let r = op.call(Method::PATCH, &url, Some(json!({ "schedule": null }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(r.body.get("next_scan_at").is_none_or(Value::is_null), "{}", r.body);
    let r = op.call(Method::PATCH, &url, Some(json!({ "schedule": "*/30 * * * *" }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let next = ts(&r.body["next_scan_at"]);
    assert!(next > Utc::now() && next <= Utc::now() + chrono::Duration::minutes(31), "{next}");

    // Disabling clears next_scan_at; enabling recomputes it.
    let r = op.call(Method::PATCH, &url, Some(json!({ "enabled": false }))).await;
    assert_eq!(r.body["enabled"], false);
    assert!(r.body.get("next_scan_at").is_none_or(Value::is_null), "{}", r.body);
    let r = op.call(Method::PATCH, &url, Some(json!({ "enabled": true }))).await;
    assert!(ts(&r.body["next_scan_at"]) > Utc::now(), "{}", r.body);

    // type and uri are immutable.
    for body in [json!({ "uri": "https://git.example/other.git" }), json!({ "type": "filesystem" })] {
        let r = op.call(Method::PATCH, &url, Some(body.clone())).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}: {}", r.body);
    }
    assert_eq!(op.call(Method::GET, &url, None).await.body["uri"], URI);

    // Delete.
    let r = op.call(Method::DELETE, &url, None).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    assert_eq!(op.call(Method::GET, &url, None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(op.call(Method::DELETE, &url, None).await.status, StatusCode::NOT_FOUND);
    let missing = format!("{SOURCES}/{}", Uuid::new_v4());
    assert_eq!(op.call(Method::GET, &missing, None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(op.call(Method::PATCH, &missing, Some(json!({ "name": "x" }))).await.status, StatusCode::NOT_FOUND);

    let actions = audit_actions(&pool).await;
    for a in ["source.create", "source.update", "source.delete"] {
        assert!(actions.iter().any(|x| x == a), "{a} audited: {actions:?}");
    }
    // Update audit lists the changed field names, never values; a changed credential
    // reference is recorded by name (null when removed), it is not a credential value.
    let updates = audit_details(&pool, "source.update").await;
    let first = &updates[0].1;
    let changed = first["changed"].to_string();
    assert!(changed.contains("name") && changed.contains("credential_ref"), "{first}");
    assert!(!first.to_string().contains("infra-app-2"), "values are not audited: {first}");
    assert!(first.get("credential_ref").is_some_and(Value::is_null), "removed ref is audited: {first}");
    assert!(updates[1].1.get("credential_ref").is_none(), "unchanged ref is not repeated: {}", updates[1].1);
    let created = audit_details(&pool, "source.create").await;
    assert_eq!(created[0].0, "user");
    assert_eq!(created[0].1["credential_ref"], "github_infra", "{}", created[0].1);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn manual_scan_body_selects_full_history(pool: PgPool) {
    let app = router(state(pool.clone()));
    let mut op = logged_in(&pool, &app, "op", Role::Operator).await;
    let mut src = Vec::new();
    for i in 0..5 {
        let body =
            json!({ "name": format!("r{i}"), "type": "git_repo", "uri": format!("https://git.example/r{i}.git") });
        src.push(create_ok(&mut op, body).await);
    }
    let url = |s: &str| format!("{SOURCES}/{s}/scans");

    // No body and no Content-Type, `{}` and `{"full": false}` all mean an incremental scan.
    let r = op.call(Method::POST, &url(&src[0]), None).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{}", r.body);
    assert_scan_shape(&r.body);
    assert_eq!(r.body["full_scan"], false);
    let r = op.call(Method::POST, &url(&src[1]), Some(json!({}))).await;
    assert_eq!((r.status, &r.body["full_scan"]), (StatusCode::ACCEPTED, &json!(false)), "{}", r.body);
    let r = op.call(Method::POST, &url(&src[2]), Some(json!({ "full": false }))).await;
    assert_eq!((r.status, &r.body["full_scan"]), (StatusCode::ACCEPTED, &json!(false)), "{}", r.body);

    let r = op.call(Method::POST, &url(&src[3]), Some(json!({ "full": true }))).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{}", r.body);
    assert_eq!(r.body["full_scan"], true);
    let job = id_of(&r);
    let stored: bool = sqlx::query_scalar("SELECT full_scan FROM scan_jobs WHERE id = $1::uuid")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(stored);
    let got = op.call(Method::GET, &format!("{SCANS}/{job}"), None).await;
    assert_eq!(got.body["full_scan"], true);

    // Unknown fields and wrong types are rejected without echoing the input; nothing is queued.
    for bad in [json!({ "fast": true }), json!({ "full": "yes-secret" }), json!([])] {
        let r = op.call(Method::POST, &url(&src[4]), Some(bad.clone())).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}: {}", r.body);
        assert!(!r.body.to_string().contains("yes-secret"), "{}", r.body);
    }
    let queued: i64 = sqlx::query_scalar("SELECT count(*) FROM scan_jobs WHERE source_id = $1::uuid")
        .bind(&src[4])
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(queued, 0);

    let enq = audit_details(&pool, "scan.enqueue").await;
    let fulls: Vec<&Value> = enq.iter().map(|(_, d)| &d["full"]).collect();
    assert_eq!(fulls, [&json!(false), &json!(false), &json!(false), &json!(true)]);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn rbac_and_csrf(pool: PgPool) {
    let app = router(state(pool.clone()));
    let mut viewer = logged_in(&pool, &app, "viewer1", Role::Viewer).await;
    let mut op = logged_in(&pool, &app, "op", Role::Operator).await;
    let body = json!({ "name": "a", "type": "git_repo", "uri": URI });

    assert_eq!(create(&mut viewer, body.clone()).await.status, StatusCode::FORBIDDEN);
    let id = create_ok(&mut op, body).await;
    let url = format!("{SOURCES}/{id}");

    assert_eq!(viewer.call(Method::GET, SOURCES, None).await.status, StatusCode::OK);
    assert_eq!(viewer.call(Method::GET, &url, None).await.status, StatusCode::OK);
    assert_eq!(viewer.call(Method::GET, SCANS, None).await.status, StatusCode::OK);
    assert_eq!(viewer.call(Method::PATCH, &url, Some(json!({ "name": "b" }))).await.status, StatusCode::FORBIDDEN);
    assert_eq!(viewer.call(Method::DELETE, &url, None).await.status, StatusCode::FORBIDDEN);
    assert_eq!(enqueue(&mut viewer, &id).await.status, StatusCode::FORBIDDEN);

    let scan = enqueue(&mut op, &id).await;
    assert_eq!(scan.status, StatusCode::ACCEPTED, "{}", scan.body);
    let scan_id = id_of(&scan);
    assert_eq!(viewer.call(Method::GET, &format!("{SCANS}/{scan_id}"), None).await.status, StatusCode::OK);
    let cancel = format!("{SCANS}/{scan_id}/cancel");
    assert_eq!(viewer.call(Method::POST, &cancel, None).await.status, StatusCode::FORBIDDEN);

    let mut anon = Client::new(&app);
    for path in [SOURCES.to_owned(), url.clone(), SCANS.to_owned(), format!("{SCANS}/{scan_id}")] {
        assert_eq!(anon.call(Method::GET, &path, None).await.status, StatusCode::UNAUTHORIZED, "{path}");
    }

    // Unsafe methods need the CSRF token.
    op.csrf = None;
    assert_eq!(
        create(&mut op, json!({ "name": "c", "type": "git_repo", "uri": "https://x.example/c" })).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(op.call(Method::PATCH, &url, Some(json!({ "name": "d" }))).await.status, StatusCode::FORBIDDEN);
    assert_eq!(op.call(Method::DELETE, &url, None).await.status, StatusCode::FORBIDDEN);
    assert_eq!(enqueue(&mut op, &id).await.status, StatusCode::FORBIDDEN);
    assert_eq!(op.call(Method::POST, &cancel, None).await.status, StatusCode::FORBIDDEN);
    assert_eq!(op.call(Method::GET, &url, None).await.body["name"], "a", "nothing changed");
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn validation(pool: PgPool) {
    let app = router(state(pool.clone()));
    let mut op = logged_in(&pool, &app, "op", Role::Operator).await;
    let base = json!({ "name": "src", "type": "git_repo", "uri": URI });
    let with = |patch: Value| {
        let mut b = base.clone();
        for (k, v) in patch.as_object().unwrap() {
            b[k] = v.clone();
        }
        b
    };
    let hunter = "hunter2-Very-Secret";
    let cases = [
        ("empty name", with(json!({ "name": "" }))),
        ("long name", with(json!({ "name": "n".repeat(201) }))),
        ("control in name", with(json!({ "name": "a\u{7}b" }))),
        ("userinfo", with(json!({ "uri": format!("https://deploy:{hunter}@git.example/x.git") }))),
        ("token param", with(json!({ "uri": format!("https://git.example/x.git?private_token={hunter}") }))),
        ("scp password", with(json!({ "uri": format!("deploy:{hunter}@git.example:x.git") }))),
        ("whitespace uri", with(json!({ "uri": "https://git.example/a b" }))),
        ("empty uri", with(json!({ "uri": "" }))),
        ("long uri", with(json!({ "uri": format!("https://git.example/{}", "a".repeat(2048)) }))),
        ("bad env", with(json!({ "environment": "prod env" }))),
        ("long env", with(json!({ "environment": "e".repeat(65) }))),
        ("ref traversal", with(json!({ "credential_ref": "../pepper_keys" }))),
        ("ref slash", with(json!({ "credential_ref": "git/key" }))),
        ("ref space", with(json!({ "credential_ref": "a b" }))),
        ("ref long", with(json!({ "credential_ref": "r".repeat(65) }))),
        ("ref empty", with(json!({ "credential_ref": "" }))),
        ("cron fields", with(json!({ "schedule": "0 3 * *" }))),
        ("cron macro", with(json!({ "schedule": "@daily" }))),
        ("cron seconds", with(json!({ "schedule": "0 0 3 * * *" }))),
        ("cron garbage", with(json!({ "schedule": "a b c d e" }))),
        ("cron too frequent", with(json!({ "schedule": "* * * * *" }))),
        ("cron never", with(json!({ "schedule": "0 0 31 2 *" }))),
        (
            "schedule on non-git",
            json!({ "name": "fs", "type": "filesystem", "uri": "/srv/app", "schedule": "0 3 * * *" }),
        ),
        ("unknown config field", with(json!({ "config": { "password": hunter } }))),
        ("config username dash", with(json!({ "config": { "username": "-oProxyCommand=x" } }))),
        ("config username colon", with(json!({ "config": { "username": "a:b" } }))),
        ("config username long", with(json!({ "config": { "username": "u".repeat(65) } }))),
        ("config blob zero", with(json!({ "config": { "max_blob_bytes": 0 } }))),
        ("config blob huge", with(json!({ "config": { "max_blob_bytes": 67_108_865 } }))),
        ("config not object", with(json!({ "config": "x" }))),
        ("bad type", with(json!({ "type": "ftp" }))),
        ("missing uri", json!({ "name": "x", "type": "git_repo" })),
    ];
    for (what, body) in cases {
        let r = create(&mut op, body).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{what}: {}", r.body);
        let ct = r.headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or_default();
        assert!(ct.starts_with("application/problem+json"), "{what}: {ct}");
        assert!(!r.body.to_string().contains(hunter), "{what}: error echoes input: {}", r.body);
    }
    // Upper bounds are inclusive.
    let ok = with(json!({ "name": "n".repeat(200), "credential_ref": "R".repeat(64), "environment": "e".repeat(64),
                          "config": { "username": "git.user@corp", "max_blob_bytes": 67_108_864 } }));
    assert_eq!(create(&mut op, ok).await.status, StatusCode::CREATED);
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM sources").fetch_one(&pool).await.unwrap(), 1);

    // PATCH validates too.
    let id: Uuid = sqlx::query_scalar("SELECT id FROM sources").fetch_one(&pool).await.unwrap();
    let url = format!("{SOURCES}/{id}");
    for body in [
        json!({ "schedule": "* * * * *" }),
        json!({ "credential_ref": "../x" }),
        json!({ "environment": "a b" }),
        json!({ "config": { "nope": 1 } }),
        json!({ "name": "" }),
    ] {
        let r = op.call(Method::PATCH, &url, Some(body.clone())).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}: {}", r.body);
    }
    // Scheduling a non-git source through PATCH is rejected as well.
    let fs = create_ok(&mut op, json!({ "name": "fs", "type": "filesystem", "uri": "/srv/app" })).await;
    let r = op.call(Method::PATCH, &format!("{SOURCES}/{fs}"), Some(json!({ "schedule": "0 3 * * *" }))).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.body);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn duplicates_conflict(pool: PgPool) {
    let app = router(state(pool.clone()));
    let mut op = logged_in(&pool, &app, "op", Role::Operator).await;
    create_ok(&mut op, json!({ "name": "a", "type": "git_repo", "uri": URI })).await;
    let r = create(&mut op, json!({ "name": "a", "type": "git_repo", "uri": "https://git.example/other.git" })).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "same name: {}", r.body);
    let r = create(&mut op, json!({ "name": "b", "type": "git_repo", "uri": URI })).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "same type and uri: {}", r.body);
    // Same URI with another type is a different source.
    let r = create(&mut op, json!({ "name": "c", "type": "wiki", "uri": URI })).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    // Renaming onto an existing name conflicts.
    let r = op.call(Method::PATCH, &format!("{SOURCES}/{}", id_of(&r)), Some(json!({ "name": "a" }))).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.body);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn manual_scans_and_cancellation(pool: PgPool) {
    let app = router(state(pool.clone()));
    let mut op = logged_in(&pool, &app, "op", Role::Operator).await;
    let op_id = user_id(&pool, "op").await;
    let src = create_ok(&mut op, json!({ "name": "a", "type": "git_repo", "uri": URI, "environment": "stage" })).await;

    let r = enqueue(&mut op, &src).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{}", r.body);
    assert_scan_shape(&r.body);
    assert_eq!(r.body["status"], "queued");
    assert_eq!(r.body["trigger"], "manual");
    assert_eq!(r.body["attempts"], 0);
    assert_eq!(r.body["source_id"], src.as_str());
    assert_eq!(r.body["requested_by"], op_id.as_str());
    let job = id_of(&r);
    let (full, env): (bool, Option<String>) =
        sqlx::query_as("SELECT full_scan, environment FROM scan_jobs WHERE id = $1::uuid")
            .bind(&job)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!full);
    assert_eq!(env.as_deref(), Some("stage"), "job inherits the source environment");

    // One active worker job per source.
    let again = enqueue(&mut op, &src).await;
    assert_eq!(again.status, StatusCode::CONFLICT, "{}", again.body);
    let s = op.call(Method::GET, &format!("{SOURCES}/{src}"), None).await;
    assert_eq!(s.body["active_scan"], json!({ "id": job, "status": "queued" }));

    // The scan is readable and listed.
    let got = op.call(Method::GET, &format!("{SCANS}/{job}"), None).await;
    assert_eq!(got.status, StatusCode::OK, "{}", got.body);
    assert_scan_shape(&got.body);
    assert_eq!(got.body["id"], job.as_str());
    assert_eq!(op.call(Method::GET, &format!("{SCANS}/{}", Uuid::new_v4()), None).await.status, StatusCode::NOT_FOUND);

    // Cancel.
    let r = op.call(Method::POST, &format!("{SCANS}/{job}/cancel"), None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["status"], "cancelled");
    assert_eq!(r.body["error"], "cancelled by user");
    assert!(r.body["finished_at"].is_string(), "{}", r.body);
    let r = op.call(Method::POST, &format!("{SCANS}/{job}/cancel"), None).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "already cancelled: {}", r.body);
    let s = op.call(Method::GET, &format!("{SOURCES}/{src}"), None).await;
    assert!(s.body.get("active_scan").is_none_or(Value::is_null), "{}", s.body);

    // A new scan may be queued after cancellation; a running one can be cancelled too.
    let job2 = id_of(&enqueue(&mut op, &src).await);
    sqlx::query("UPDATE scan_jobs SET status = 'running', started_at = now(), locked_by = 'w1', locked_at = now(), attempts = 1 WHERE id = $1::uuid")
        .bind(&job2)
        .execute(&pool)
        .await
        .unwrap();
    let s = op.call(Method::GET, &format!("{SOURCES}/{src}"), None).await;
    assert_eq!(s.body["active_scan"]["status"], "running");
    let r = op.call(Method::POST, &format!("{SCANS}/{job2}/cancel"), None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(job_row(&pool, &job2).await.0, "cancelled");

    // Finished jobs cannot be cancelled.
    let job3 = id_of(&enqueue(&mut op, &src).await);
    sqlx::query("UPDATE scan_jobs SET status = 'succeeded', finished_at = now() WHERE id = $1::uuid")
        .bind(&job3)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(op.call(Method::POST, &format!("{SCANS}/{job3}/cancel"), None).await.status, StatusCode::CONFLICT);
    assert_eq!(
        op.call(Method::POST, &format!("{SCANS}/{}/cancel", Uuid::new_v4()), None).await.status,
        StatusCode::NOT_FOUND
    );

    // Only git_repo sources can be scanned by the server; disabled sources cannot be scanned.
    let fs = create_ok(&mut op, json!({ "name": "fs", "type": "filesystem", "uri": "/srv/app" })).await;
    assert_eq!(enqueue(&mut op, &fs).await.status, StatusCode::UNPROCESSABLE_ENTITY);
    let off = create_ok(
        &mut op,
        json!({ "name": "off", "type": "git_repo", "uri": "https://git.example/off.git", "enabled": false }),
    )
    .await;
    assert_eq!(enqueue(&mut op, &off).await.status, StatusCode::CONFLICT);
    assert_eq!(enqueue(&mut op, &Uuid::new_v4().to_string()).await.status, StatusCode::NOT_FOUND);

    let actions = audit_actions(&pool).await;
    assert_eq!(actions.iter().filter(|a| *a == "scan.enqueue").count(), 3, "{actions:?}");
    assert_eq!(actions.iter().filter(|a| *a == "scan.cancel").count(), 2, "{actions:?}");
    let enq = audit_details(&pool, "scan.enqueue").await;
    assert_eq!(enq[0].0, "user");
    assert_eq!(enq[0].1["trigger"], "manual");
    assert_eq!(enq[0].1["source_id"], src.as_str());
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn api_token_scans_are_listed_but_not_cancellable(pool: PgPool) {
    let app = router(state(pool.clone()));
    let mut admin = logged_in(&pool, &app, "root", Role::Admin).await;
    let (token, _) = issue_token(&mut admin, "ci", "ci", &["ingest:profile"]).await;
    let r = bearer(
        &app,
        Method::POST,
        "/api/v1/ingest/scans",
        Some(&token),
        Some(json!({ "source": { "type": "git_repo", "uri": URI } })),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    let scan = r.body["scan_id"].as_str().unwrap().to_owned();

    let got = admin.call(Method::GET, &format!("{SCANS}/{scan}"), None).await;
    assert_eq!(got.status, StatusCode::OK, "{}", got.body);
    assert_scan_shape(&got.body);
    assert_eq!(got.body["trigger"], "ci");
    assert_eq!(got.body["status"], "running");
    let r = admin.call(Method::POST, &format!("{SCANS}/{scan}/cancel"), None).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.body);
    let list = admin.call(Method::GET, &format!("{SCANS}?trigger=ci"), None).await;
    assert_eq!(list.body["items"].as_array().unwrap().len(), 1, "{}", list.body);
    // Ingest-created sources are listed like any other.
    let sources = admin.call(Method::GET, SOURCES, None).await;
    assert_eq!(sources.body["items"][0]["uri"], URI);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn disabling_and_deleting_cancel_active_jobs(pool: PgPool) {
    let app = router(state(pool.clone()));
    let mut op = logged_in(&pool, &app, "op", Role::Operator).await;

    // Disabling cancels a queued job.
    let a = create_ok(&mut op, json!({ "name": "a", "type": "git_repo", "uri": URI })).await;
    let ja = id_of(&enqueue(&mut op, &a).await);
    let r = op.call(Method::PATCH, &format!("{SOURCES}/{a}"), Some(json!({ "enabled": false }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let (status, error, _, finished) = job_row(&pool, &ja).await;
    assert_eq!((status.as_str(), error.as_deref(), finished), ("cancelled", Some("source disabled"), true));

    // ... and a running one (the worker notices at its next heartbeat).
    let b = create_ok(&mut op, json!({ "name": "b", "type": "git_repo", "uri": "https://git.example/b.git" })).await;
    let jb = id_of(&enqueue(&mut op, &b).await);
    sqlx::query("UPDATE scan_jobs SET status = 'running', started_at = now(), locked_by = 'w1', locked_at = now(), attempts = 1 WHERE id = $1::uuid")
        .bind(&jb)
        .execute(&pool)
        .await
        .unwrap();
    op.call(Method::PATCH, &format!("{SOURCES}/{b}"), Some(json!({ "enabled": false }))).await;
    assert_eq!(job_row(&pool, &jb).await.0, "cancelled");

    // Deleting cancels active jobs in the same transaction; finished jobs are kept.
    let c = create_ok(&mut op, json!({ "name": "c", "type": "git_repo", "uri": "https://git.example/c.git" })).await;
    let done = id_of(&enqueue(&mut op, &c).await);
    sqlx::query("UPDATE scan_jobs SET status = 'succeeded', finished_at = now() WHERE id = $1::uuid")
        .bind(&done)
        .execute(&pool)
        .await
        .unwrap();
    let jc = id_of(&enqueue(&mut op, &c).await);
    sqlx::query("UPDATE scan_jobs SET status = 'running', started_at = now(), locked_by = 'w1', locked_at = now(), attempts = 1 WHERE id = $1::uuid")
        .bind(&jc)
        .execute(&pool)
        .await
        .unwrap();
    let r = op.call(Method::DELETE, &format!("{SOURCES}/{c}"), None).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    let (status, error, source_id, _) = job_row(&pool, &jc).await;
    assert_eq!((status.as_str(), error.as_deref(), source_id), ("cancelled", Some("source deleted"), None));
    assert_eq!(job_row(&pool, &done).await.0, "succeeded");
    let r = op.call(Method::GET, &format!("{SCANS}/{jc}"), None).await;
    assert_eq!(r.status, StatusCode::OK, "jobs of deleted sources stay readable: {}", r.body);
    assert!(r.body.get("source_id").is_none_or(Value::is_null));
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn listing_filters_and_pagination(pool: PgPool) {
    let app = router(state(pool.clone()));
    let mut op = logged_in(&pool, &app, "op", Role::Operator).await;
    let mut ids = Vec::new();
    for i in 0..5 {
        let ty = if i % 2 == 0 { "git_repo" } else { "filesystem" };
        let uri = if ty == "git_repo" { format!("https://git.example/r{i}.git") } else { format!("/srv/r{i}") };
        ids.push(
            create_ok(&mut op, json!({ "name": format!("s{i}"), "type": ty, "uri": uri, "enabled": i != 4 })).await,
        );
    }

    // Walk all pages of size 2, newest first, no duplicates.
    let mut seen = Vec::new();
    let mut url = format!("{SOURCES}?limit=2");
    loop {
        let page = op.call(Method::GET, &url, None).await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        let items = page.body["items"].as_array().unwrap();
        assert!(items.len() <= 2);
        seen.extend(items.iter().map(|s| s["name"].as_str().unwrap().to_owned()));
        match page.body.get("next_cursor").and_then(Value::as_str) {
            Some(c) => url = format!("{SOURCES}?limit=2&cursor={c}"),
            None => break,
        }
    }
    assert_eq!(seen, ["s4", "s3", "s2", "s1", "s0"]);

    let names = |r: &Resp| -> Vec<String> {
        r.body["items"].as_array().unwrap().iter().map(|s| s["name"].as_str().unwrap().to_owned()).collect()
    };
    assert_eq!(names(&op.call(Method::GET, &format!("{SOURCES}?type=filesystem"), None).await), ["s3", "s1"]);
    assert_eq!(names(&op.call(Method::GET, &format!("{SOURCES}?enabled=false"), None).await), ["s4"]);
    assert_eq!(
        names(&op.call(Method::GET, &format!("{SOURCES}?type=git_repo&enabled=true"), None).await),
        ["s2", "s0"]
    );
    assert_eq!(op.call(Method::GET, &format!("{SOURCES}?limit=0"), None).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(op.call(Method::GET, &format!("{SOURCES}?cursor=garbage"), None).await.status, StatusCode::BAD_REQUEST);

    // Scans: filters by source, status, trigger; newest first; pagination.
    let j0 = id_of(&enqueue(&mut op, &ids[0]).await);
    sqlx::query("UPDATE scan_jobs SET status = 'failed', finished_at = now(), error = 'x' WHERE id = $1::uuid")
        .bind(&j0)
        .execute(&pool)
        .await
        .unwrap();
    let j1 = id_of(&enqueue(&mut op, &ids[0]).await);
    let j2 = id_of(&enqueue(&mut op, &ids[2]).await);
    let scan_ids = |r: &Resp| -> Vec<String> {
        r.body["items"].as_array().unwrap().iter().map(|s| s["id"].as_str().unwrap().to_owned()).collect()
    };
    let all = op.call(Method::GET, SCANS, None).await;
    assert_eq!(all.status, StatusCode::OK, "{}", all.body);
    assert_eq!(scan_ids(&all), [j2.clone(), j1.clone(), j0.clone()]);
    for item in all.body["items"].as_array().unwrap() {
        assert_scan_shape(item);
    }
    assert_eq!(
        scan_ids(&op.call(Method::GET, &format!("{SCANS}?source_id={}", ids[0]), None).await),
        [j1.clone(), j0.clone()]
    );
    assert_eq!(scan_ids(&op.call(Method::GET, &format!("{SCANS}?status=failed"), None).await), vec![j0.clone()]);
    assert_eq!(
        scan_ids(&op.call(Method::GET, &format!("{SCANS}?status=queued&source_id={}", ids[0]), None).await),
        vec![j1.clone()]
    );
    assert_eq!(scan_ids(&op.call(Method::GET, &format!("{SCANS}?trigger=schedule"), None).await), Vec::<String>::new());
    let p1 = op.call(Method::GET, &format!("{SCANS}?limit=2"), None).await;
    assert_eq!(scan_ids(&p1), [j2, j1]);
    let c = p1.body["next_cursor"].as_str().unwrap();
    assert_eq!(scan_ids(&op.call(Method::GET, &format!("{SCANS}?limit=2&cursor={c}"), None).await), [j0]);
    assert_eq!(op.call(Method::GET, &format!("{SCANS}?status=bogus"), None).await.status.as_u16() / 100, 4);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn worker_state_is_never_exposed(pool: PgPool) {
    let app = router(state(pool.clone()));
    let mut op = logged_in(&pool, &app, "op", Role::Operator).await;
    let id = create_ok(&mut op, json!({ "name": "a", "type": "git_repo", "uri": URI })).await;
    let tip = "c0ffee".repeat(6) + "abcd";
    sqlx::query("UPDATE sources SET scan_state = jsonb_build_object('v', 1, 'tips', jsonb_build_array($1::text)) WHERE id = $2::uuid")
        .bind(&tip)
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();
    let job = id_of(&enqueue(&mut op, &id).await);
    sqlx::query("UPDATE scan_jobs SET locked_by = 'worker-secret-host' WHERE id = $1::uuid")
        .bind(&job)
        .execute(&pool)
        .await
        .unwrap();
    for path in [format!("{SOURCES}/{id}"), SOURCES.to_owned(), format!("{SCANS}/{job}"), SCANS.to_owned()] {
        let r = op.call(Method::GET, &path, None).await;
        let text = r.body.to_string();
        assert!(!text.contains("scan_state") && !text.contains(&tip), "{path}: {text}");
        assert!(!text.contains("worker-secret-host") && !text.contains("locked_by"), "{path}: {text}");
    }
    let r = op.call(Method::PATCH, &format!("{SOURCES}/{id}"), Some(json!({ "scan_state": {} }))).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "scan_state is not writable: {}", r.body);
}
