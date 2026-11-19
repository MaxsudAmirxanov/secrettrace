//! Worker (stage 9): server-side git scans through the queue, scheduler and reaper, against
//! local repositories (`allow_local_repos`). Written against the stage 9 contract.
//! Run with `make test` (needs `git`).
//!
//! Secret values are generated at runtime; only their digests are registered.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc, clippy::too_many_lines)]

mod common;

use std::fs;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use axum::Router;
use axum::http::{Method, StatusCode};
use chrono::Utc;
use common::*;
use serde_json::{Value, json};
use sqlx::PgPool;
use st_core::{SecretType, prepare};
use st_server::auth::Role;
use st_server::schedule::Schedule;
use st_server::worker::{JobOutcome, OutcomeStatus, Worker, WorkerConfig};
use uuid::Uuid;

// ── fixtures ────────────────────────────────────────────────────────────────

/// A directory removed on drop (the test crate has no `tempfile`).
struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("st-worker-test-{tag}-{}", Uuid::new_v4().simple()));
        fs::create_dir_all(&dir).unwrap();
        Self(dir.canonicalize().unwrap())
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Deterministic generator of GitHub-token-shaped values (`ghp_` + 36), no literals in the repo.
struct Gen(u64);

impl Gen {
    fn github(&mut self) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut s = String::from("ghp_");
        for _ in 0..36 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            s.push(char::from(ALPHABET[usize::try_from(self.0 % 62).unwrap()]));
        }
        s
    }
}

/// A working-tree repository with deterministic commit dates.
struct Repo {
    dir: TmpDir,
    clock: std::cell::Cell<u64>,
}

impl Repo {
    fn new() -> Self {
        let repo = Self { dir: TmpDir::new("repo"), clock: std::cell::Cell::new(1_700_000_000) };
        repo.git(&["init", "-q", "-b", "main"]);
        repo
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// The URI a source uses for this repository (an absolute path).
    fn uri(&self) -> String {
        self.path().display().to_string()
    }

    fn git(&self, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(self.path())
            .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"])
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_DATE", self.date())
            .env("GIT_COMMITTER_DATE", self.date())
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    fn date(&self) -> String {
        format!("@{} +0000", self.clock.get())
    }

    fn write(&self, path: &str, content: impl AsRef<[u8]>) {
        let full = self.path().join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, content).unwrap();
    }

    fn remove(&self, path: &str) {
        fs::remove_file(self.path().join(path)).unwrap();
    }

    fn commit(&self, message: &str) -> String {
        self.git(&["add", "-A"]);
        self.clock.set(self.clock.get() + 60);
        self.git(&["commit", "-q", "--allow-empty", "-m", message]);
        self.git(&["rev-parse", "HEAD"])
    }

    fn blob(&self, rev_path: &str) -> String {
        self.git(&["rev-parse", rev_path])
    }
}

fn config(data: &TmpDir, creds: &TmpDir) -> WorkerConfig {
    let mut c = WorkerConfig::new(data.path().join("data"), creds.path().to_path_buf());
    c.worker_id = format!("test-{}", Uuid::new_v4().simple());
    c.tmp_dir = data.path().join("tmp");
    fs::create_dir_all(&c.tmp_dir).unwrap();
    c.allow_local_repos = true;
    c.scan_threads = NonZeroUsize::new(2).unwrap();
    c.concurrency = NonZeroUsize::new(1).unwrap();
    c.job_timeout = Duration::from_secs(120);
    c.lease_timeout = Duration::from_secs(60);
    c.poll_interval = Duration::from_millis(50);
    c.max_attempts = 3;
    c.retry_backoff = Duration::from_secs(60);
    c
}

struct Env {
    pool: PgPool,
    app: Router,
    admin: Client,
    op: Client,
    worker: Worker,
    data: TmpDir,
    creds: TmpDir,
}

async fn setup(pool: &PgPool) -> Env {
    setup_with(pool, |_| {}).await
}

async fn setup_with(pool: &PgPool, tweak: impl FnOnce(&mut WorkerConfig)) -> Env {
    let state = state(pool.clone());
    let pepper = state.pepper.clone();
    let app = router(state);
    let admin = logged_in(pool, &app, "root", Role::Admin).await;
    let op = logged_in(pool, &app, "op", Role::Operator).await;
    let data = TmpDir::new("data");
    let creds = TmpDir::new("creds");
    let mut cfg = config(&data, &creds);
    tweak(&mut cfg);
    let worker = Worker::new(pool.clone(), pepper, cfg);
    Env { pool: pool.clone(), app, admin, op, worker, data, creds }
}

impl Env {
    async fn register(&mut self, name: &str, value: &str, allow_rules: Value) -> String {
        let (d, hints) = prepare(SecretType::Token, value).unwrap();
        let body = json!({ "name": name, "type": "token", "owner": "platform", "digest": d.to_hex(), "hints": hints,
                           "allow_rules": allow_rules });
        let r = self.op.call(Method::POST, "/api/v1/secrets", Some(body)).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
        r.body["id"].as_str().unwrap().to_owned()
    }

    async fn source(&mut self, name: &str, uri: &str, extra: Value) -> String {
        let mut body = json!({ "name": name, "type": "git_repo", "uri": uri });
        for (k, v) in extra.as_object().unwrap() {
            body[k] = v.clone();
        }
        let r = self.op.call(Method::POST, "/api/v1/sources", Some(body)).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
        r.body["id"].as_str().unwrap().to_owned()
    }

    async fn enqueue(&mut self, source: &str) -> Uuid {
        let r = self.op.call(Method::POST, &format!("/api/v1/sources/{source}/scans"), None).await;
        assert_eq!(r.status, StatusCode::ACCEPTED, "{}", r.body);
        r.body["id"].as_str().unwrap().parse().unwrap()
    }

    async fn run(&self) -> JobOutcome {
        self.worker.run_once().await.unwrap().expect("a job was due")
    }

    /// Enqueue a manual scan and run it; asserts it succeeded.
    async fn scan(&mut self, source: &str) -> JobOutcome {
        let job = self.enqueue(source).await;
        let out = self.run().await;
        assert_eq!(out.job_id, job);
        assert_eq!(out.status, OutcomeStatus::Succeeded, "{out:?}");
        out
    }

    async fn job(&self, id: Uuid) -> JobRow {
        sqlx::query_as(
            "SELECT status::text AS status, attempts, error, stats, locked_by, run_after, finished_at
             FROM scan_jobs WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }
}

#[derive(Debug, sqlx::FromRow)]
struct JobRow {
    status: String,
    attempts: i32,
    error: Option<String>,
    stats: Value,
    locked_by: Option<String>,
    run_after: chrono::DateTime<Utc>,
    finished_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, sqlx::FromRow)]
struct Loc {
    path: String,
    uri: String,
    source_type: String,
    environment: Option<String>,
    in_current_state: bool,
    is_allowed: bool,
    source_id: Option<Uuid>,
    last_job_id: Option<Uuid>,
    locator: Value,
}

async fn locations(pool: &PgPool, secret_id: &str) -> Vec<Loc> {
    sqlx::query_as(
        "SELECT locator->>'path' AS path, uri, source_type::text AS source_type, environment, in_current_state,
                is_allowed, source_id, last_job_id, locator
         FROM locations WHERE secret_id = $1::uuid ORDER BY locator->>'path'",
    )
    .bind(secret_id)
    .fetch_all(pool)
    .await
    .unwrap()
}

fn stat(o: &JobOutcome, key: &str) -> u64 {
    *o.stats.get(key).unwrap_or_else(|| panic!("stats lack {key}: {:?}", o.stats))
}

async fn total_locations(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM locations").fetch_one(pool).await.unwrap()
}

/// Everything the server stored about scans, as text, for leak checks.
async fn stored_text(pool: &PgPool) -> String {
    let parts: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT string_agg(t, ' ') FROM (
            SELECT row_to_json(j)::text AS t FROM scan_jobs j
            UNION ALL SELECT row_to_json(a)::text FROM audit_log a
            UNION ALL SELECT row_to_json(l)::text FROM locations l
            UNION ALL SELECT row_to_json(s)::text FROM sources s) x",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    parts.into_iter().flatten().collect()
}

fn digest_hex(value: &str) -> String {
    prepare(SecretType::Token, value).unwrap().0.to_hex()
}

// ── scanning ────────────────────────────────────────────────────────────────

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn scans_history_and_current_state(pool: PgPool) {
    let mut env = setup(&pool).await;
    let mut g = Gen(0x9e37);
    let (current, old, unregistered) = (g.github(), g.github(), g.github());
    let cur_id = env.register("current", &current, json!([])).await;
    let old_id = env.register("old", &old, json!([])).await;

    let repo = Repo::new();
    repo.write("README.md", "hello\n");
    repo.write("config/prod.env", format!("# prod\nGITHUB_TOKEN={current}\n"));
    repo.write("old.env", format!("token: {old}\n"));
    repo.write("other.env", format!("token: {unregistered}\n"));
    let c1 = repo.commit("initial");
    let old_blob = repo.blob("HEAD:old.env");
    repo.remove("old.env");
    repo.commit("remove old token");

    let src = env.source("app", &repo.uri(), json!({ "environment": "prod" })).await;
    let out = env.scan(&src).await;
    assert_eq!(out.source_id, Some(src.parse().unwrap()));
    assert!(out.error.is_none(), "{out:?}");
    assert_eq!(stat(&out, "incremental"), 0, "first scan is full");
    assert_eq!(stat(&out, "documents"), 4, "every unique blob once: {:?}", out.stats);
    assert_eq!(stat(&out, "matched"), 2, "{:?}", out.stats);
    assert_eq!(stat(&out, "new_locations"), 2, "{:?}", out.stats);
    assert_eq!(stat(&out, "violations"), 2, "{:?}", out.stats);
    assert_eq!(stat(&out, "no_longer_present"), 0);
    assert!(stat(&out, "candidates") >= 3, "{:?}", out.stats);
    assert_eq!(stat(&out, "read_errors"), 0);

    let cur = locations(&pool, &cur_id).await;
    assert_eq!(cur.len(), 1, "{cur:?}");
    let l = &cur[0];
    assert_eq!(l.path, "config/prod.env");
    assert!(l.in_current_state);
    assert!(!l.is_allowed);
    assert_eq!(l.environment.as_deref(), Some("prod"), "source environment");
    assert_eq!(l.uri, repo.uri());
    assert_eq!(l.source_type, "git_repo");
    assert_eq!(l.source_id, Some(src.parse().unwrap()));
    assert_eq!(l.last_job_id, Some(out.job_id));
    assert_eq!(l.locator["blob"], repo.blob("HEAD:config/prod.env"));
    assert_eq!(l.locator["commit"], c1.as_str(), "first commit that added the blob");
    assert_eq!(l.locator["line"], 2);
    assert!(l.locator.get("digest").is_none());

    let hist = locations(&pool, &old_id).await;
    assert_eq!(hist.len(), 1, "{hist:?}");
    assert_eq!(hist[0].path, "old.env");
    assert!(!hist[0].in_current_state, "only in history");
    assert_eq!(hist[0].locator["blob"], old_blob);
    assert_eq!(hist[0].locator["commit"], c1.as_str());

    // Unregistered values leave nothing behind.
    assert_eq!(total_locations(&pool).await, 2);

    // Job row, source and audit.
    let job = env.job(out.job_id).await;
    assert_eq!(job.status, "succeeded");
    assert_eq!(job.attempts, 1);
    assert!(job.finished_at.is_some());
    assert!(job.error.is_none());
    assert!(job.stats.as_object().unwrap().values().all(Value::is_u64), "integer stats: {}", job.stats);
    assert_eq!(job.stats["matched"], 2);
    let last_scan: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT last_scan_at FROM sources WHERE id = $1::uuid")
            .bind(&src)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(last_scan.is_some());
    let audit: Vec<(String, Value)> =
        sqlx::query_as("SELECT actor_type, details FROM audit_log WHERE action = 'scan.finish' AND target_id = $1")
            .bind(out.job_id.to_string())
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(audit.len(), 1, "scan.finish audited once");
    assert_eq!(audit[0].0, "system");
    let s = env.op.call(Method::GET, &format!("/api/v1/sources/{src}"), None).await;
    assert!(s.body.get("active_scan").is_none_or(Value::is_null), "{}", s.body);
    let scan = env.op.call(Method::GET, &format!("/api/v1/scans/{}", out.job_id), None).await;
    assert_eq!(scan.body["status"], "succeeded");

    // Nothing secret is stored anywhere.
    let text = stored_text(&pool).await;
    for v in [&current, &old, &unregistered] {
        assert!(!text.contains(v.as_str()), "plaintext stored");
        assert!(!text.contains(&digest_hex(v)), "digest stored");
    }
    // The queue is empty now.
    assert!(env.worker.run_once().await.unwrap().is_none());
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn allow_rules_and_file_uri(pool: PgPool) {
    let mut env = setup(&pool).await;
    let mut g = Gen(77);
    let tok = g.github();
    let repo = Repo::new();
    let uri = format!("file://{}", repo.uri());
    let id = env
        .register(
            "deploy",
            &tok,
            json!([{ "source_type": "git_repo", "uri_pattern": uri, "path_pattern": "deploy/**", "environment": "prod" }]),
        )
        .await;
    repo.write("deploy/k8s/secret.env", format!("TOKEN={tok}\n"));
    repo.write("src/leak.env", format!("TOKEN={tok}\n"));
    repo.commit("c1");

    let src = env.source("app", &uri, json!({ "environment": "prod" })).await;
    let out = env.scan(&src).await;
    assert_eq!(stat(&out, "new_locations"), 2, "{:?}", out.stats);
    assert_eq!(stat(&out, "violations"), 1, "{:?}", out.stats);
    let locs = locations(&pool, &id).await;
    let allowed: Vec<(&str, bool)> = locs.iter().map(|l| (l.path.as_str(), l.is_allowed)).collect();
    assert_eq!(allowed, [("deploy/k8s/secret.env", true), ("src/leak.env", false)]);

    // Without the environment the env-scoped rule no longer applies on the next scan.
    let r = env.op.call(Method::PATCH, &format!("/api/v1/sources/{src}"), Some(json!({ "environment": null }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let out = env.scan(&src).await;
    assert_eq!(stat(&out, "violations"), 2, "{:?}", out.stats);
    assert!(locations(&pool, &id).await.iter().all(|l| !l.is_allowed && l.environment.is_none()));
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn incremental_rescan_reads_new_blobs_and_the_head_tree(pool: PgPool) {
    let mut env = setup(&pool).await;
    let mut g = Gen(4242);
    let (first, second) = (g.github(), g.github());
    let first_id = env.register("first", &first, json!([])).await;
    let second_id = env.register("second", &second, json!([])).await;

    let repo = Repo::new();
    repo.write("README.md", "readme\n");
    repo.write("a.env", format!("TOKEN={first}\n"));
    for i in 0..30 {
        repo.write(&format!("hist/{i}.txt"), format!("history file {i}\n"));
    }
    repo.commit("c1");
    for i in 0..30 {
        repo.remove(&format!("hist/{i}.txt"));
    }
    let c2 = repo.commit("drop history files");

    let src = env.source("app", &repo.uri(), json!({})).await;
    let out1 = env.scan(&src).await;
    assert_eq!(stat(&out1, "incremental"), 0);
    assert_eq!(stat(&out1, "documents"), 32, "{:?}", out1.stats);
    let tips: Value = sqlx::query_scalar("SELECT scan_state FROM sources WHERE id = $1::uuid")
        .bind(&src)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(tips["v"], 1, "{tips}");
    assert!(tips["tips"].as_array().unwrap().iter().any(|t| t == c2.as_str()), "{tips}");

    // New commit: history pass sees only the new blob; the HEAD tree is read in full.
    repo.write("new.env", format!("TOKEN={second}\n"));
    let c3 = repo.commit("add new token");
    let out2 = env.scan(&src).await;
    assert_eq!(stat(&out2, "incremental"), 1, "{:?}", out2.stats);
    assert_eq!(stat(&out2, "documents"), 3, "new blob + rest of HEAD tree, no old history: {:?}", out2.stats);
    assert_eq!(stat(&out2, "new_locations"), 1, "{:?}", out2.stats);
    assert_eq!(stat(&out2, "updated_locations"), 1, "a.env re-reported from the HEAD tree: {:?}", out2.stats);
    assert_eq!(stat(&out2, "no_longer_present"), 0);
    let a = locations(&pool, &first_id).await;
    assert!(a[0].in_current_state);
    assert_eq!(a[0].last_job_id, Some(out2.job_id));
    let n = locations(&pool, &second_id).await;
    assert_eq!(n.len(), 1);
    assert!(n[0].in_current_state);
    assert_eq!(n[0].locator["commit"], c3.as_str());

    // Nothing new: still incremental, only the HEAD tree.
    let out3 = env.scan(&src).await;
    assert_eq!(stat(&out3, "incremental"), 1);
    assert_eq!(stat(&out3, "documents"), 3, "{:?}", out3.stats);
    assert_eq!(stat(&out3, "new_locations"), 0);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn removed_files_are_no_longer_present_but_api_rows_are_kept(pool: PgPool) {
    let mut env = setup(&pool).await;
    let mut g = Gen(31337);
    let (tok, ci_tok) = (g.github(), g.github());
    let id = env.register("tok", &tok, json!([])).await;
    let ci_id = env.register("ci-tok", &ci_tok, json!([])).await;

    let repo = Repo::new();
    repo.write("a.env", format!("TOKEN={tok}\n"));
    repo.write("keep.txt", "keep\n");
    repo.commit("c1");
    let src = env.source("app", &repo.uri(), json!({})).await;
    env.scan(&src).await;
    assert!(locations(&pool, &id).await[0].in_current_state);

    // A CI token reports a location for the same source through ingest.
    let (token, _) = issue_token(&mut env.admin, "ci", "ci", &["ingest:profile", "ingest:findings"]).await;
    let r = bearer(
        &env.app,
        Method::POST,
        "/api/v1/ingest/scans",
        Some(&token),
        Some(json!({ "source": { "type": "git_repo", "uri": repo.uri() } })),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    assert_eq!(r.body["source_id"], src.as_str(), "same source by (type, uri)");
    let scan = r.body["scan_id"].as_str().unwrap().to_owned();
    let finding = json!({ "digest": digest_hex(&ci_tok), "path": "ci-only.env", "in_current_state": true,
                          "detector": "known", "rule": "github_token", "confidence": "high" });
    let r = bearer(
        &env.app,
        Method::POST,
        &format!("/api/v1/ingest/scans/{scan}/findings"),
        Some(&token),
        Some(json!({ "findings": [finding] })),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let r = bearer(
        &env.app,
        Method::POST,
        &format!("/api/v1/ingest/scans/{scan}/complete"),
        Some(&token),
        Some(json!({ "status": "succeeded" })),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    // Make sure "last_seen < started_at" holds for every earlier row.
    sqlx::query("UPDATE locations SET last_seen = last_seen - interval '1 minute'").execute(&pool).await.unwrap();

    repo.remove("a.env");
    repo.commit("remove token");
    let out = env.scan(&src).await;
    assert_eq!(stat(&out, "no_longer_present"), 1, "{:?}", out.stats);
    let l = locations(&pool, &id).await;
    assert_eq!(l.len(), 1, "history is kept");
    assert!(!l[0].in_current_state);
    let ci = locations(&pool, &ci_id).await;
    assert!(ci[0].in_current_state, "rows reported by API tokens are never cleared by the worker");
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn rewritten_history_and_unusable_state_fall_back_to_full(pool: PgPool) {
    let mut env = setup(&pool).await;
    let mut g = Gen(999);
    let (a, b) = (g.github(), g.github());
    let a_id = env.register("a", &a, json!([])).await;
    let b_id = env.register("b", &b, json!([])).await;

    let repo = Repo::new();
    repo.write("a.env", format!("TOKEN={a}\n"));
    repo.write("x.txt", "x\n");
    repo.commit("c1");
    let src = env.source("app", &repo.uri(), json!({})).await;
    env.scan(&src).await;
    sqlx::query("UPDATE locations SET last_seen = last_seen - interval '1 minute'").execute(&pool).await.unwrap();

    // Force-push: main is replaced by an unrelated history.
    repo.git(&["checkout", "-q", "--orphan", "rewrite"]);
    repo.git(&["rm", "-rq", "--cached", "."]);
    repo.remove("a.env");
    repo.write("b.env", format!("TOKEN={b}\n"));
    let new_head = repo.commit("rewritten");
    repo.git(&["branch", "-D", "main"]);
    repo.git(&["branch", "-m", "main"]);
    let out = env.scan(&src).await;
    assert_eq!(stat(&out, "no_longer_present"), 1, "{:?}", out.stats);
    assert!(!locations(&pool, &a_id).await[0].in_current_state);
    let bl = locations(&pool, &b_id).await;
    assert!(bl[0].in_current_state);
    assert_eq!(bl[0].locator["commit"], new_head.as_str());

    // Stored tips that no longer exist: the next scan is a full one.
    sqlx::query("UPDATE sources SET scan_state = jsonb_build_object('v', 1, 'tips', jsonb_build_array(repeat('0', 39) || '1')) WHERE id = $1::uuid")
        .bind(&src)
        .execute(&pool)
        .await
        .unwrap();
    let out = env.scan(&src).await;
    assert_eq!(stat(&out, "incremental"), 0, "{:?}", out.stats);
    // Empty / garbage state too.
    sqlx::query("UPDATE sources SET scan_state = '{\"v\": 99, \"tips\": \"nope\"}' WHERE id = $1::uuid")
        .bind(&src)
        .execute(&pool)
        .await
        .unwrap();
    let out = env.scan(&src).await;
    assert_eq!(stat(&out, "incremental"), 0, "{:?}", out.stats);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn odd_paths_are_sanitized(pool: PgPool) {
    let mut env = setup(&pool).await;
    let mut g = Gen(5);
    let tok = g.github();
    let id = env.register("t", &tok, json!([])).await;
    let repo = Repo::new();
    let long = format!("{}/{}.env", "d".repeat(200), "f".repeat(240));
    let long = format!("{long}/{long}/{long}");
    repo.write(&long, format!("TOKEN={tok}\n"));
    repo.write("tab\there.env", format!("TOKEN={tok}\n"));
    repo.commit("c1");
    let src = env.source("app", &repo.uri(), json!({})).await;
    let out = env.scan(&src).await;
    assert_eq!(stat(&out, "new_locations"), 2, "{:?}", out.stats);
    for l in locations(&pool, &id).await {
        assert!(!l.path.is_empty() && l.path.len() <= 1024, "{}", l.path.len());
        assert!(!l.path.chars().any(char::is_control), "{:?}", l.path);
    }
}

// ── queue ───────────────────────────────────────────────────────────────────

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn concurrent_workers_claim_different_jobs(pool: PgPool) {
    let mut env = setup(&pool).await;
    let (r1, r2) = (Repo::new(), Repo::new());
    for r in [&r1, &r2] {
        r.write("f.txt", "content\n");
        r.commit("c1");
    }
    let s1 = env.source("one", &r1.uri(), json!({})).await;
    let s2 = env.source("two", &r2.uri(), json!({})).await;
    let j1 = env.enqueue(&s1).await;
    let j2 = env.enqueue(&s2).await;

    let data2 = TmpDir::new("data2");
    let other = Worker::new(pool.clone(), state(pool.clone()).pepper.clone(), config(&data2, &env.creds));
    let (a, b) = tokio::join!(env.worker.run_once(), other.run_once());
    let (a, b) = (a.unwrap().unwrap(), b.unwrap().unwrap());
    assert_ne!(a.job_id, b.job_id);
    let mut got = [a.job_id, b.job_id];
    got.sort();
    let mut want = [j1, j2];
    want.sort();
    assert_eq!(got, want);
    assert!(env.worker.run_once().await.unwrap().is_none());
    assert!(other.run_once().await.unwrap().is_none());
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn expired_leases_are_requeued_then_failed(pool: PgPool) {
    let mut env = setup(&pool).await;
    let src = env.source("app", "https://git.example/infra/app.git", json!({})).await;
    let job = env.enqueue(&src).await;
    // A worker took the job and died.
    let dead =
        "UPDATE scan_jobs SET status = 'running', locked_by = 'dead-worker', locked_at = now() - interval '1 hour',
                started_at = now() - interval '1 hour', attempts = $2 WHERE id = $1";
    sqlx::query(dead).bind(job).bind(1).execute(&pool).await.unwrap();
    // A fresh lease is left alone.
    let fresh_src = env.source("fresh", "https://git.example/infra/fresh.git", json!({})).await;
    let fresh = env.enqueue(&fresh_src).await;
    sqlx::query("UPDATE scan_jobs SET status = 'running', locked_by = 'alive', locked_at = now(), started_at = now(), attempts = 1 WHERE id = $1")
        .bind(fresh)
        .execute(&pool)
        .await
        .unwrap();

    let report = env.worker.reap().await.unwrap();
    assert_eq!((report.requeued, report.failed), (1, 0), "{report:?}");
    let row = env.job(job).await;
    assert_eq!(row.status, "queued");
    assert!(row.locked_by.is_none());
    assert_eq!(env.job(fresh).await.status, "running");

    sqlx::query(dead).bind(job).bind(3).execute(&pool).await.unwrap();
    let report = env.worker.reap().await.unwrap();
    assert_eq!((report.requeued, report.failed), (0, 1), "{report:?}");
    let row = env.job(job).await;
    assert_eq!(row.status, "failed");
    assert!(row.error.as_deref().unwrap_or_default().contains("lease"), "{row:?}");
    assert!(row.finished_at.is_some());
    assert_eq!(env.worker.reap().await.unwrap().requeued, 0);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn failures_retry_with_backoff_then_fail(pool: PgPool) {
    let mut env = setup(&pool).await;
    let missing = env.data.path().join("no-such-repo");
    let src = env.source("gone", &missing.display().to_string(), json!({})).await;
    let job = env.enqueue(&src).await;

    let out = env.run().await;
    assert_eq!(out.status, OutcomeStatus::Retrying, "{out:?}");
    let row = env.job(job).await;
    assert_eq!((row.status.as_str(), row.attempts), ("queued", 1));
    assert!(row.error.is_some());
    assert!(row.locked_by.is_none());
    let wait = (row.run_after - Utc::now()).num_seconds();
    assert!((45..=75).contains(&wait), "first retry after ~60 s, got {wait}");
    assert!(env.worker.run_once().await.unwrap().is_none(), "not due before run_after");

    sqlx::query("UPDATE scan_jobs SET run_after = now() - interval '1 second' WHERE id = $1")
        .bind(job)
        .execute(&pool)
        .await
        .unwrap();
    let out = env.run().await;
    assert_eq!(out.status, OutcomeStatus::Retrying);
    let row = env.job(job).await;
    assert_eq!(row.attempts, 2);
    let wait = (row.run_after - Utc::now()).num_seconds();
    assert!((105..=135).contains(&wait), "backoff doubles, got {wait}");

    sqlx::query("UPDATE scan_jobs SET run_after = now() - interval '1 second' WHERE id = $1")
        .bind(job)
        .execute(&pool)
        .await
        .unwrap();
    let out = env.run().await;
    assert_eq!(out.status, OutcomeStatus::Failed, "attempts exhausted: {out:?}");
    let row = env.job(job).await;
    assert_eq!((row.status.as_str(), row.attempts), ("failed", 3));
    assert!(row.finished_at.is_some());
    // A failed scan does not advance the incremental state.
    let state: Value = sqlx::query_scalar("SELECT scan_state FROM sources WHERE id = $1::uuid")
        .bind(&src)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(state, json!({}));
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn cancelled_disabled_and_deleted(pool: PgPool) {
    let mut env = setup(&pool).await;
    let repo = Repo::new();
    repo.write("f.txt", "x\n");
    repo.commit("c1");

    // Cancelled through the API: never claimed.
    let src = env.source("app", &repo.uri(), json!({})).await;
    let job = env.enqueue(&src).await;
    let r = env.op.call(Method::POST, &format!("/api/v1/scans/{job}/cancel"), None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(env.worker.run_once().await.unwrap().is_none());
    assert_eq!(env.job(job).await.status, "cancelled");

    // Disabled behind the API's back after enqueueing: the worker cancels the job.
    let job = env.enqueue(&src).await;
    sqlx::query("UPDATE sources SET enabled = false WHERE id = $1::uuid").bind(&src).execute(&pool).await.unwrap();
    let out = env.run().await;
    assert_eq!((out.job_id, out.status), (job, OutcomeStatus::Cancelled), "{out:?}");
    assert_eq!(env.job(job).await.status, "cancelled");
    assert_eq!(total_locations(&pool).await, 0);

    // Source deleted behind the API's back.
    let src2 = env.source("app2", &format!("file://{}", repo.uri()), json!({})).await;
    let job = env.enqueue(&src2).await;
    sqlx::query("DELETE FROM sources WHERE id = $1::uuid").bind(&src2).execute(&pool).await.unwrap();
    let out = env.run().await;
    assert_eq!((out.job_id, out.status), (job, OutcomeStatus::Cancelled), "{out:?}");
    assert_eq!(env.job(job).await.status, "cancelled");
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn shutdown_stops_the_loop(pool: PgPool) {
    let env = setup(&pool).await;
    let done = tokio::time::timeout(Duration::from_secs(15), env.worker.run(std::future::ready(()))).await;
    assert!(matches!(done, Ok(Ok(()))), "run returns promptly after shutdown: {done:?}");
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn run_loop_processes_queued_jobs(pool: PgPool) {
    let mut env = setup(&pool).await;
    let mut g = Gen(8);
    let tok = g.github();
    let id = env.register("t", &tok, json!([])).await;
    let repo = Repo::new();
    repo.write("a.env", format!("TOKEN={tok}\n"));
    repo.commit("c1");
    let src = env.source("app", &repo.uri(), json!({})).await;
    let job = env.enqueue(&src).await;

    let pool2 = pool.clone();
    let shutdown = async move {
        for _ in 0..300 {
            let status: String = sqlx::query_scalar("SELECT status::text FROM scan_jobs WHERE id = $1")
                .bind(job)
                .fetch_one(&pool2)
                .await
                .unwrap();
            if status == "succeeded" || status == "failed" {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(60), env.worker.run(shutdown)).await.unwrap().unwrap();
    assert_eq!(env.job(job).await.status, "succeeded");
    assert_eq!(locations(&pool, &id).await.len(), 1);
}

// ── URIs and credentials ────────────────────────────────────────────────────

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn unsupported_uris_fail_without_retry(pool: PgPool) {
    let mut env = setup_with(&pool, |c| {
        c.allow_local_repos = false;
        c.allowed_hosts = vec!["git.example".into()];
    })
    .await;
    let repo = Repo::new();
    repo.write("f.txt", "x\n");
    repo.commit("c1");
    let cases = [
        ("local path", repo.uri()),
        ("file uri", format!("file://{}", repo.uri())),
        ("ext transport", "ext::git-upload-pack".to_owned()),
        ("host not allowed", "https://evil.example/infra/app.git".to_owned()),
        ("scp host not allowed", "git@evil.example:infra/app.git".to_owned()),
        ("ssh host not allowed", "ssh://evil.example/infra/app.git".to_owned()),
        ("option-looking host", "ssh://-oProxyCommand=touch/x".to_owned()),
        ("http", "http://git.example/infra/app.git".to_owned()),
        ("ftp", "ftp://git.example/infra/app.git".to_owned()),
    ];
    for (i, (what, uri)) in cases.iter().enumerate() {
        let src = env.source(&format!("s{i}"), uri, json!({})).await;
        let job = env.enqueue(&src).await;
        let out = env.run().await;
        assert_eq!((out.job_id, out.status), (job, OutcomeStatus::Failed), "{what}: {out:?}");
        let row = env.job(job).await;
        assert_eq!((row.status.as_str(), row.attempts), ("failed", 1), "{what}: not retried");
        assert!(row.error.is_some(), "{what}");
    }
    // Nothing was cloned.
    let repos = env.data.path().join("data").join("repos");
    let cloned = fs::read_dir(&repos).map(Iterator::count).unwrap_or(0);
    assert_eq!(cloned, 0, "no mirror created for rejected URIs");
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn bad_credentials_fail_without_leaking(pool: PgPool) {
    let mut env = setup_with(&pool, |c| c.allowed_hosts = vec!["git.example".into()]).await;
    let content = "CREDENTIAL-CONTENT-Do-Not-Leak-0123456789";
    let outside = TmpDir::new("outside");
    fs::write(outside.path().join("real"), content).unwrap();
    std::os::unix::fs::symlink(outside.path().join("real"), env.creds.path().join("linked")).unwrap();
    fs::write(env.creds.path().join("huge"), format!("{content}{}", "A".repeat(20 * 1024))).unwrap();
    fs::create_dir(env.creds.path().join("adir")).unwrap();
    // A valid credential without a hosts file is never used.
    fs::write(env.creds.path().join("unbound"), content).unwrap();
    // A credential bound to another host is never sent to this one.
    fs::write(env.creds.path().join("elsewhere"), content).unwrap();
    fs::write(env.creds.path().join("elsewhere.hosts"), "other.example\n").unwrap();
    // The others are bound to git.example, so their file checks are what fails.
    for cref in ["missing", "linked", "huge", "adir"] {
        fs::write(env.creds.path().join(format!("{cref}.hosts")), "git.example\n").unwrap();
    }

    let expected = [
        ("missing", "not found"),
        ("linked", "is not a regular file"),
        ("huge", "is too large"),
        ("adir", "is not a regular file"),
        ("unbound", "is not allowed for this host"),
        ("elsewhere", "is not allowed for this host"),
    ];
    for (i, (cref, why)) in expected.iter().enumerate() {
        let uri = format!("https://git.example/infra/app{i}.git");
        let src = env.source(&format!("s{i}"), &uri, json!({ "credential_ref": cref })).await;
        let job = env.enqueue(&src).await;
        let out = env.run().await;
        assert_eq!((out.job_id, out.status), (job, OutcomeStatus::Failed), "{cref}: {out:?}");
        let row = env.job(job).await;
        assert_eq!(row.attempts, 1, "{cref}: credential errors are not retried");
        let err = row.error.unwrap_or_default();
        assert_eq!(err, format!("credential \"{cref}\" {why}"), "{cref}");
        assert!(!err.contains(content), "{cref}: error leaks the credential: {err}");
        assert!(!format!("{out:?}").contains(content), "{cref}");
    }
    let text = stored_text(&pool).await;
    assert!(!text.contains(content), "credential content stored somewhere");
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn ssh_without_known_hosts_fails_without_retry(pool: PgPool) {
    let mut env = setup_with(&pool, |c| {
        c.ssh_known_hosts = None;
        c.allowed_hosts = vec!["git.example".into()];
    })
    .await;
    fs::write(
        env.creds.path().join("deploy_key"),
        "-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-key\n-----END OPENSSH PRIVATE KEY-----\n",
    )
    .unwrap();
    let src = env.source("ssh", "git@git.example:infra/app.git", json!({ "credential_ref": "deploy_key" })).await;
    let job = env.enqueue(&src).await;
    let out = env.run().await;
    assert_eq!(out.status, OutcomeStatus::Failed, "{out:?}");
    let row = env.job(job).await;
    assert_eq!(row.attempts, 1);
    let err = row.error.unwrap_or_default();
    assert_eq!(err, "ssh known_hosts file is not configured");
    assert!(!err.contains("not-a-key"));
}

// ── scheduler & reaper ──────────────────────────────────────────────────────

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn scheduler_enqueues_due_sources_once(pool: PgPool) {
    let mut env = setup(&pool).await;
    let a =
        env.source("a", "https://git.example/a.git", json!({ "schedule": "0 3 * * *", "environment": "prod" })).await;
    let b = env.source("b", "https://git.example/b.git", json!({ "schedule": "*/30 * * * *" })).await;
    env.source("c", "https://git.example/c.git", json!({})).await;
    assert_eq!(env.worker.schedule_due().await.unwrap(), 0, "nothing due yet");

    let due = |id: &str| {
        let id = id.to_owned();
        let pool = pool.clone();
        async move {
            sqlx::query("UPDATE sources SET next_scan_at = now() - interval '1 minute' WHERE id = $1::uuid")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }
    };
    due(&a).await;
    due(&b).await;
    let before = Utc::now();
    assert_eq!(env.worker.schedule_due().await.unwrap(), 2);
    let after = Utc::now();
    let jobs: Vec<(Uuid, String, String, Option<String>)> =
        sqlx::query_as("SELECT source_id, trigger, status::text, environment FROM scan_jobs ORDER BY created_at")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(jobs.len(), 2, "{jobs:?}");
    for (source, trigger, status, environment) in &jobs {
        assert_eq!((trigger.as_str(), status.as_str()), ("schedule", "queued"));
        if source.to_string() == a {
            assert_eq!(environment.as_deref(), Some("prod"));
        }
    }
    let next: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT next_scan_at FROM sources WHERE id = $1::uuid")
        .bind(&a)
        .fetch_one(&pool)
        .await
        .unwrap();
    let sched = Schedule::parse("0 3 * * *").unwrap();
    assert!(Some(next) == sched.next_after(before) || Some(next) == sched.next_after(after), "{next}");
    assert_eq!(env.worker.schedule_due().await.unwrap(), 0, "advanced: not due again");

    // Due again while a job is still queued: no duplicate, but the schedule advances.
    due(&a).await;
    assert_eq!(env.worker.schedule_due().await.unwrap(), 0);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM scan_jobs WHERE source_id = $1::uuid")
        .bind(&a)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
    let next: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT next_scan_at FROM sources WHERE id = $1::uuid")
        .bind(&a)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(next > Utc::now());

    // Disabled and non-git sources are never enqueued, even with a stale next_scan_at.
    sqlx::query("UPDATE scan_jobs SET status = 'cancelled', finished_at = now()").execute(&pool).await.unwrap();
    sqlx::query("UPDATE sources SET enabled = false, next_scan_at = now() - interval '1 minute' WHERE id = $1::uuid")
        .bind(&a)
        .execute(&pool)
        .await
        .unwrap();
    let fs: Uuid = sqlx::query_scalar(
        "INSERT INTO sources (name, type, uri, schedule_cron, next_scan_at) VALUES ('fs', 'filesystem', '/srv', '0 3 * * *', now() - interval '1 minute') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let created = env.worker.schedule_due().await.unwrap();
    let active: Vec<Uuid> =
        sqlx::query_scalar("SELECT source_id FROM scan_jobs WHERE status = 'queued'").fetch_all(&pool).await.unwrap();
    assert!(!active.contains(&a.parse().unwrap()), "disabled source enqueued");
    assert!(!active.contains(&fs), "non-git source enqueued");
    assert_eq!(created, 0);

    // Scheduled enqueues are audited as the system.
    let audit: Vec<(String, Value)> =
        sqlx::query_as("SELECT actor_type, details FROM audit_log WHERE action = 'scan.enqueue' ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert!(audit.len() >= 2);
    assert!(audit.iter().all(|(actor, _)| actor == "system"), "{audit:?}");
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn scheduled_job_runs_like_a_manual_one(pool: PgPool) {
    let mut env = setup(&pool).await;
    let mut g = Gen(12);
    let tok = g.github();
    let id = env.register("t", &tok, json!([])).await;
    let repo = Repo::new();
    repo.write("a.env", format!("TOKEN={tok}\n"));
    repo.commit("c1");
    let src = env.source("app", &repo.uri(), json!({ "schedule": "0 3 * * *" })).await;
    sqlx::query("UPDATE sources SET next_scan_at = now() - interval '1 minute' WHERE id = $1::uuid")
        .bind(&src)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(env.worker.schedule_due().await.unwrap(), 1);
    let out = env.run().await;
    assert_eq!(out.status, OutcomeStatus::Succeeded, "{out:?}");
    assert_eq!(locations(&pool, &id).await.len(), 1);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn reaper_fails_abandoned_api_scans(pool: PgPool) {
    let mut env = setup(&pool).await;
    let (token, _) = issue_token(&mut env.admin, "ci", "ci", &["ingest:profile"]).await;
    let mut scans = Vec::new();
    for uri in ["https://git.example/old.git", "https://git.example/new.git"] {
        let r = bearer(
            &env.app,
            Method::POST,
            "/api/v1/ingest/scans",
            Some(&token),
            Some(json!({ "source": { "type": "git_repo", "uri": uri } })),
        )
        .await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
        scans.push(r.body["scan_id"].as_str().unwrap().parse::<Uuid>().unwrap());
    }
    sqlx::query("UPDATE scan_jobs SET started_at = now() - interval '25 hours' WHERE id = $1")
        .bind(scans[0])
        .execute(&pool)
        .await
        .unwrap();
    let report = env.worker.reap().await.unwrap();
    assert_eq!(report.api_scans_failed, 1, "{report:?}");
    assert_eq!(report.requeued, 0, "API scans are never requeued");
    let old = env.job(scans[0]).await;
    assert_eq!(old.status, "failed");
    assert!(old.error.as_deref().unwrap_or_default().contains("abandoned"), "{old:?}");
    assert_eq!(env.job(scans[1]).await.status, "running");
    // The worker never claims API scans.
    assert!(env.worker.run_once().await.unwrap().is_none());
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn mirrors_of_deleted_sources_are_removed(pool: PgPool) {
    let mut env = setup(&pool).await;
    let repo = Repo::new();
    repo.write("f.txt", "x\n");
    repo.commit("c1");
    let src = env.source("app", &repo.uri(), json!({})).await;
    env.scan(&src).await;
    let repos = env.data.path().join("data").join("repos");
    let mirror = repos.join(format!("{src}.git"));
    assert!(mirror.is_dir(), "mirror at <data_dir>/repos/<source_id>.git");
    // Unrelated entries are never touched.
    let stranger = repos.join("not-a-uuid.git");
    fs::create_dir_all(&stranger).unwrap();

    let r = env.op.call(Method::DELETE, &format!("/api/v1/sources/{src}"), None).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    // Housekeeping runs on start: a short run loop removes the orphaned mirror.
    let shutdown = tokio::time::sleep(Duration::from_millis(1500));
    tokio::time::timeout(Duration::from_secs(15), env.worker.run(shutdown)).await.unwrap().unwrap();
    assert!(!mirror.exists(), "orphaned mirror removed");
    assert!(stranger.is_dir(), "only <uuid>.git entries are removed");
}

// ── security addendum (W1, W4, W5, W7, W8) ──────────────────────────────────

/// W4: a registry change forces a full history pass; `{"full": true}` does too.
#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn registry_changes_and_full_requests_force_full_history(pool: PgPool) {
    let mut env = setup(&pool).await;
    let mut g = Gen(0xfeed);
    let (head_tok, old_tok) = (g.github(), g.github());
    env.register("head", &head_tok, json!([])).await;

    let repo = Repo::new();
    repo.write("a.env", format!("TOKEN={head_tok}\n"));
    repo.write("old.env", format!("TOKEN={old_tok}\n"));
    let c1 = repo.commit("c1");
    repo.remove("old.env");
    repo.commit("drop old token");

    let src = env.source("app", &repo.uri(), json!({})).await;
    let first = env.scan(&src).await;
    assert_eq!(stat(&first, "incremental"), 0);
    assert_eq!(stat(&first, "matched"), 1, "old token not registered yet: {:?}", first.stats);
    let quiet = env.scan(&src).await;
    assert_eq!(stat(&quiet, "incremental"), 1, "no registry change: {:?}", quiet.stats);

    // A secret registered after the scan whose value lives only in old history.
    let old_id = env.register("old", &old_tok, json!([])).await;
    let after_change = env.scan(&src).await;
    assert_eq!(stat(&after_change, "incremental"), 0, "registry changed: {:?}", after_change.stats);
    let locs = locations(&pool, &old_id).await;
    assert_eq!(locs.len(), 1, "found in history: {locs:?}");
    assert_eq!(locs[0].path, "old.env");
    assert!(!locs[0].in_current_state);
    assert_eq!(locs[0].locator["commit"], c1.as_str());

    let again = env.scan(&src).await;
    assert_eq!(stat(&again, "incremental"), 1, "watermark stored: {:?}", again.stats);

    // A manual full scan ignores the stored tips.
    let r = env.op.call(Method::POST, &format!("/api/v1/sources/{src}/scans"), Some(json!({ "full": true }))).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{}", r.body);
    assert_eq!(r.body["full_scan"], true);
    let job: Uuid = r.body["id"].as_str().unwrap().parse().unwrap();
    let full = env.run().await;
    assert_eq!((full.job_id, full.status), (job, OutcomeStatus::Succeeded), "{full:?}");
    assert_eq!(stat(&full, "incremental"), 0, "{:?}", full.stats);
    let after_full = env.scan(&src).await;
    assert_eq!(stat(&after_full, "incremental"), 1);
}

/// W1: credentials are usable only for the hosts their `.hosts` file lists.
#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn credentials_are_bound_to_hosts(pool: PgPool) {
    let mut env = setup_with(&pool, |c| c.allowed_hosts = vec!["git.example".into(), "other.example".into()]).await;
    let content = "BOUND-CREDENTIAL-Do-Not-Leak-9876543210";
    let creds = env.creds.path().to_path_buf();
    for name in ["nohosts", "comments", "linkedhosts", "emptyhosts"] {
        fs::write(creds.join(name), content).unwrap();
    }
    // `nohosts`: no `.hosts` file at all.
    fs::write(creds.join("comments.hosts"), "# deploy keys for the mirror\n\nother.example\n  # git.example\n")
        .unwrap();
    let outside = TmpDir::new("outside-hosts");
    fs::write(outside.path().join("hosts"), "git.example\n").unwrap();
    std::os::unix::fs::symlink(outside.path().join("hosts"), creds.join("linkedhosts.hosts")).unwrap();
    fs::write(creds.join("emptyhosts.hosts"), "").unwrap();

    for (i, cref) in ["nohosts", "comments", "linkedhosts", "emptyhosts"].iter().enumerate() {
        let uri = format!("https://git.example/infra/bound{i}.git");
        let src = env.source(&format!("b{i}"), &uri, json!({ "credential_ref": cref })).await;
        let job = env.enqueue(&src).await;
        let out = env.run().await;
        assert_eq!((out.job_id, out.status), (job, OutcomeStatus::Failed), "{cref}: {out:?}");
        let row = env.job(job).await;
        assert_eq!((row.status.as_str(), row.attempts), ("failed", 1), "{cref}: not retried");
        let err = row.error.unwrap_or_default();
        assert_eq!(err, format!("credential \"{cref}\" is not allowed for this host"), "{cref}");
        assert!(!row.stats.to_string().contains(content), "{cref}");
    }
    // The `.hosts` file itself can never be referenced as a credential (the API rejects the dot).
    let r = env
        .op
        .call(
            Method::POST,
            "/api/v1/sources",
            Some(json!({ "name": "dot", "type": "git_repo", "uri": "https://git.example/d.git", "credential_ref": "comments.hosts" })),
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.body);

    let text = stored_text(&pool).await;
    assert!(!text.contains(content), "credential content stored somewhere");
}

/// W1: an empty host allowlist refuses remote hosts unless any host is explicitly allowed;
/// local repositories stay governed by `allow_local_repos` alone.
#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn empty_allowlist_refuses_remote_hosts(pool: PgPool) {
    let mut env = setup_with(&pool, |c| {
        c.allowed_hosts = Vec::new();
        c.allow_any_host = false;
    })
    .await;
    for (i, uri) in
        ["https://git.example/infra/app.git", "git@git.example:infra/app.git", "ssh://git.example/infra/app.git"]
            .iter()
            .enumerate()
    {
        let src = env.source(&format!("r{i}"), uri, json!({})).await;
        let job = env.enqueue(&src).await;
        let out = env.run().await;
        assert_eq!((out.job_id, out.status), (job, OutcomeStatus::Failed), "{uri}: {out:?}");
        let row = env.job(job).await;
        assert_eq!(row.attempts, 1, "{uri}");
        assert_eq!(row.error.as_deref(), Some("source host is not allowed"), "{uri}");
    }
    let repo = Repo::new();
    repo.write("f.txt", "x\n");
    repo.commit("c1");
    let local = env.source("local", &repo.uri(), json!({})).await;
    env.scan(&local).await;
}

/// W1: IP literals in any notation are not host names.
#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn ip_literal_hosts_are_rejected(pool: PgPool) {
    let mut env = setup_with(&pool, |c| {
        c.allowed_hosts = Vec::new();
        c.allow_any_host = true;
    })
    .await;
    let uris = [
        "https://127.0.0.1/x.git",
        "https://2130706433/x.git",
        "https://0x7f000001/x.git",
        "https://0177.0.0.1/x.git",
        "https://127.1/x.git",
        "https://169.254.169.254:443/x.git",
        "https://[::1]/x.git",
        "https://[::ffff:127.0.0.1]/x.git",
        "ssh://10.0.0.1/x.git",
        "git@192.168.0.1:x.git",
    ];
    for (i, uri) in uris.iter().enumerate() {
        let src = env.source(&format!("ip{i}"), uri, json!({})).await;
        let job = env.enqueue(&src).await;
        let out = env.run().await;
        assert_eq!((out.job_id, out.status), (job, OutcomeStatus::Failed), "{uri}: {out:?}");
        let row = env.job(job).await;
        assert_eq!(row.attempts, 1, "{uri}: not retried");
        assert!(row.error.is_some(), "{uri}");
    }
    let repos = env.data.path().join("data").join("repos");
    let mirrors =
        fs::read_dir(&repos).map(|d| d.filter_map(Result::ok).filter(|e| e.path().is_dir()).count()).unwrap_or(0);
    assert_eq!(mirrors, 0, "no mirror created for IP-literal hosts");
}

/// W7: git failures are stored as fixed categories, never remote text or local paths.
#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn fetch_errors_are_fixed_categories(pool: PgPool) {
    let mut env = setup(&pool).await;
    let missing = env.data.path().join("missing-repo-dir-XYZ");
    let src = env.source("gone", &format!("file://{}", missing.display()), json!({})).await;
    let job = env.enqueue(&src).await;
    let out = env.run().await;
    assert_eq!(out.status, OutcomeStatus::Retrying, "{out:?}");
    let err = env.job(job).await.error.unwrap_or_default();
    let categories = [
        "repository not found or access denied",
        "authentication failed",
        "could not connect",
        "TLS error",
        "timed out",
        "remote rejected the request",
        "host key verification failed",
    ];
    let fixed = err.strip_prefix("git ").and_then(|rest| rest.split_once(" failed")).is_some_and(|(cmd, tail)| {
        !cmd.is_empty()
            && cmd.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
            && (tail.is_empty() || tail.strip_prefix(": ").is_some_and(|c| categories.contains(&c)))
    });
    assert!(fixed, "fixed category expected, got {err:?}");
    for leak in ["missing-repo-dir-XYZ", "remote:", "fatal", "/tmp", "file://"] {
        assert!(!err.contains(leak), "{leak} in {err:?}");
    }
    assert!(!format!("{out:?}").contains("missing-repo-dir-XYZ"), "{out:?}");
}

/// W8: a current file whose blob is skipped (over the size cap) keeps its locations current.
#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn skipped_head_blobs_are_not_cleared(pool: PgPool) {
    let mut env = setup(&pool).await;
    let mut g = Gen(0xb10b);
    let tok = g.github();
    let id = env.register("t", &tok, json!([])).await;
    let repo = Repo::new();
    repo.write("config.env", format!("TOKEN={tok}\n"));
    repo.commit("c1");
    let src = env.source("app", &repo.uri(), json!({ "config": { "max_blob_bytes": 4096 } })).await;
    let out = env.scan(&src).await;
    assert_eq!(stat(&out, "new_locations"), 1, "{:?}", out.stats);
    sqlx::query("UPDATE locations SET last_seen = last_seen - interval '1 minute'").execute(&pool).await.unwrap();

    // The file grows past the cap: the scanner cannot read it, so it cannot tell.
    repo.write("config.env", format!("TOKEN={tok}\n# {}\n", "padding ".repeat(1024)));
    repo.commit("grow");
    let out = env.scan(&src).await;
    assert!(stat(&out, "skipped_large") >= 1, "{:?}", out.stats);
    assert_eq!(stat(&out, "no_longer_present"), 0, "{:?}", out.stats);
    let locs = locations(&pool, &id).await;
    assert_eq!(locs.len(), 1);
    assert!(locs[0].in_current_state, "path is still in HEAD, its blob was not read");

    // Removing the file does clear it.
    repo.remove("config.env");
    repo.commit("remove");
    sqlx::query("UPDATE locations SET last_seen = last_seen - interval '1 minute'").execute(&pool).await.unwrap();
    let out = env.scan(&src).await;
    assert_eq!(stat(&out, "no_longer_present"), 1, "{:?}", out.stats);
    assert!(!locations(&pool, &id).await[0].in_current_state);
}

/// W5: the lease of a running job is `<worker_id>/<claim uuid>`, new for every claim.
#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn leases_name_worker_and_claim(pool: PgPool) {
    let mut env = setup_with(&pool, |c| c.worker_id = "w5-worker".into()).await;
    let repo = Repo::new();
    // Enough content that the run is observable while it lasts.
    for i in 0..1500 {
        repo.write(&format!("f/{i}.txt"), format!("line {i}\n").repeat(40));
    }
    repo.commit("c1");
    let src = env.source("app", &repo.uri(), json!({})).await;

    let mut leases = Vec::new();
    for _ in 0..2 {
        let job = env.enqueue(&src).await;
        let pool2 = pool.clone();
        let watch = async move {
            loop {
                let row: (String, Option<String>) =
                    sqlx::query_as("SELECT status::text, locked_by FROM scan_jobs WHERE id = $1")
                        .bind(job)
                        .fetch_one(&pool2)
                        .await
                        .unwrap();
                match row {
                    (s, Some(lease)) if s == "running" => return Some(lease),
                    (s, _) if s != "queued" => return None,
                    _ => tokio::task::yield_now().await,
                }
            }
        };
        let (out, seen) = tokio::join!(env.worker.run_once(), watch);
        assert_eq!(out.unwrap().unwrap().status, OutcomeStatus::Succeeded);
        let lease = seen.expect("the running job was observed");
        let (worker, claim) = lease.split_once('/').unwrap_or_else(|| panic!("{lease}"));
        assert_eq!(worker, "w5-worker");
        assert!(claim.parse::<Uuid>().is_ok(), "claim id is a UUID: {lease}");
        assert!(lease.len() <= 128);
        leases.push(lease);
    }
    assert_ne!(leases[0], leases[1], "every claim gets its own lease");
}
