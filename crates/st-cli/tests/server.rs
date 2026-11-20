//! `secrettrace scan … --server` against a real server on Postgres. Run with `make test`
//! (needs `DATABASE_URL` of a superuser, like the server's integration tests).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::process::{Command, Output};
use std::time::Duration;

use base64::Engine as _;
use secrecy::SecretString;
use serde_json::{Value, json};
use sqlx::PgPool;
use st_core::{SecretType, prepare};
use st_server::app::{self, AppState, HttpLimits};
use st_server::audit::AuditEvent;
use st_server::auth::{AuthSettings, Role, tokens};
use st_server::crypto::{DataKey, Pepper};
use st_server::{registry, users};
use uuid::Uuid;
use zeroize::Zeroizing;

const SCOPES: &[&str] = &["ingest:profile", "ingest:match", "ingest:findings"];

fn token(seed: u8) -> String {
    let body: String = (0..36u8)
        .map(|i| char::from(b"abcdefghijkmnopqrstuvwxyzABCDEFGH23456789"[usize::from((i * 7 + seed) % 41)]))
        .collect();
    format!("ghp_{body}")
}

fn git(dir: &std::path::Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"])
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
}

fn pepper() -> Pepper {
    let b64 = base64::engine::general_purpose::STANDARD;
    Pepper::parse(&SecretString::from(format!("1:{}", b64.encode([1u8; 32]))), None).unwrap()
}

struct Server {
    url: String,
    pool: PgPool,
    admin: Uuid,
}

impl Server {
    async fn start(pool: PgPool) -> Self {
        let b64 = base64::engine::general_purpose::STANDARD;
        let data_key = DataKey::parse(&SecretString::from(b64.encode([2u8; 32]))).unwrap();
        let auth = AuthSettings {
            session_ttl: Duration::from_secs(3600),
            session_idle: Duration::from_secs(600),
            cookie_secure: false,
            totp_issuer: "SecretTrace".into(),
            trusted_proxies: vec![],
            require_client_cert: false,
        };
        let state = AppState::new(pool.clone(), pepper(), data_key, auth);
        let limits = HttpLimits { request_timeout: Duration::from_secs(30), max_body_bytes: 1024 * 1024 };
        let router = app::router(state, limits);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
        });

        let mut tx = pool.begin().await.unwrap();
        let admin = users::create(
            &mut tx,
            "admin",
            Zeroizing::new("correct horse battery staple".into()),
            Role::Admin,
            AuditEvent::system("user.create"),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        Self { url: format!("http://{addr}"), pool, admin }
    }

    async fn api_token(&self, scopes: &[&str]) -> String {
        let new = tokens::new_api_token();
        let scopes: Vec<String> = scopes.iter().map(|s| (*s).to_owned()).collect();
        sqlx::query(
            "INSERT INTO api_tokens (name, kind, token_hash, token_prefix, scopes, expires_at)
             VALUES ($1, 'ci', $2, $3, $4, now() + interval '1 day')",
        )
        .bind(format!("ci-{}", new.prefix))
        .bind(new.hash.as_slice())
        .bind(&new.prefix)
        .bind(&scopes)
        .execute(&self.pool)
        .await
        .unwrap();
        new.token.to_string()
    }

    async fn register(&self, name: &str, value: &str, allow_rules: Value) -> Uuid {
        let (digest, hints) = prepare(SecretType::Token, value).unwrap();
        let req: registry::SecretCreate = serde_json::from_value(json!({
            "name": name, "type": "token", "owner": "platform", "digest": digest.to_hex(),
            "hints": hints, "allow_rules": allow_rules,
        }))
        .unwrap();
        let mut tx = self.pool.begin().await.unwrap();
        let out =
            registry::create(&mut tx, &pepper(), &req, self.admin, AuditEvent::system("secret.create")).await.unwrap();
        tx.commit().await.unwrap();
        out.id
    }

    /// `(path, in_current_state, is_allowed, has_commit)` of a secret's locations, sorted.
    async fn locations(&self, secret: Uuid) -> Vec<(String, bool, bool, bool)> {
        let rows: Vec<(Value, bool, bool)> = sqlx::query_as(
            "SELECT locator, in_current_state, is_allowed FROM locations WHERE secret_id = $1 ORDER BY locator->>'path'",
        )
        .bind(secret)
        .fetch_all(&self.pool)
        .await
        .unwrap();
        rows.into_iter()
            .map(|(l, current, allowed)| {
                (l["path"].as_str().unwrap().to_owned(), current, allowed, l["commit"].as_str().is_some())
            })
            .collect()
    }
}

/// Run the CLI off the async runtime (the server shares it).
async fn cli(args: Vec<String>, token: Option<String>) -> Output {
    tokio::task::spawn_blocking(move || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_secrettrace"));
        cmd.args(&args).env_remove("SECRETTRACE_TOKEN").env_remove("SECRETTRACE_ENVIRONMENT");
        if let Some(t) = token {
            cmd.env("SECRETTRACE_TOKEN", t);
        }
        cmd.output().unwrap()
    })
    .await
    .unwrap()
}

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

fn rows(out: &Output) -> Vec<Value> {
    String::from_utf8_lossy(&out.stdout).lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn scan_git_reports_registered_secrets_and_sets_the_exit_code(pool: PgPool) {
    let server = Server::start(pool).await;
    let ci = server.api_token(SCOPES).await;
    let current = server.register("current", &token(1), json!([])).await;
    let old = server.register("old", &token(2), json!([])).await;

    let dir = tempfile::TempDir::new().unwrap();
    let repo = dir.path();
    git(repo, &["init", "-q", "-b", "main"]);
    // A CI checkout: the remote URL carries a job token, which must never be sent.
    git(repo, &["remote", "add", "origin", "https://gitlab-ci-token:glcbt-xyz@git.example.com/acme/app.git"]);
    std::fs::write(repo.join("leak.env"), format!("TOKEN={}\n", token(2))).unwrap();
    git(repo, &["add", "-A"]);
    git(repo, &["commit", "-q", "-m", "old leak"]);
    git(repo, &["rm", "-q", "leak.env"]);
    std::fs::create_dir(repo.join("config")).unwrap();
    std::fs::write(repo.join("config/app.env"), format!("TOKEN={}\nOTHER={}\n", token(1), token(3))).unwrap();
    git(repo, &["add", "-A"]);
    git(repo, &["commit", "-q", "-m", "current"]);
    let repo_s = repo.to_str().unwrap();

    let out = cli(args(&["scan", "git", repo_s, "--server", &server.url]), Some(ci.clone())).await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    // Only registered candidates are printed, never digests.
    let printed = rows(&out);
    assert_eq!(printed.len(), 2, "{printed:?}");
    assert!(printed.iter().all(|r| r.get("digest").is_none()));
    assert!(stderr.contains("2 registered secret(s) in 2 location(s): 2 violation(s)"), "{stderr}");
    assert!(stderr.contains("https://git.example.com/acme/app.git"), "{stderr}");
    assert!(!stderr.contains("glcbt"), "{stderr}");

    assert_eq!(server.locations(current).await, [("config/app.env".to_owned(), true, false, true)]);
    assert_eq!(server.locations(old).await, [("leak.env".to_owned(), false, false, true)]);
    let (uri, status): (String, String) =
        sqlx::query_as("SELECT s.uri, j.status::text FROM scan_jobs j JOIN sources s ON s.id = j.source_id")
            .fetch_one(&server.pool)
            .await
            .unwrap();
    assert_eq!((uri.as_str(), status.as_str()), ("https://git.example.com/acme/app.git", "succeeded"));

    // Allowed everywhere in this repository: no violations, exit 0; `--fail-on found` still fails.
    sqlx::query("INSERT INTO secret_allow_rules (secret_id, uri_pattern) SELECT id, 'https://git.example.com/acme/**' FROM secrets")
        .execute(&server.pool)
        .await
        .unwrap();
    let out = cli(args(&["scan", "git", repo_s, "--server", &server.url]), Some(ci.clone())).await;
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    let out =
        cli(args(&["scan", "git", repo_s, "--server", &server.url, "--fail-on", "found"]), Some(ci.clone())).await;
    assert_eq!(out.status.code(), Some(1), "{}", String::from_utf8_lossy(&out.stderr));

    // The secret leaves HEAD: it is still in history, but no longer in the current state.
    git(repo, &["rm", "-q", "config/app.env"]);
    git(repo, &["commit", "-q", "-m", "remove"]);
    let out = cli(args(&["scan", "git", repo_s, "--server", &server.url]), Some(ci)).await;
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(server.locations(current).await, [("config/app.env".to_owned(), false, true, true)]);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn scan_fs_and_error_exit_codes(pool: PgPool) {
    let server = Server::start(pool).await;
    let ci = server.api_token(SCOPES).await;
    let secret = server.register("fs", &token(4), json!([])).await;
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(dir.path().join("etc")).unwrap();
    std::fs::write(dir.path().join("etc/app.conf"), format!("api_token = {}\n", token(4))).unwrap();
    let root = dir.path().to_str().unwrap();

    let out = cli(
        args(&[
            "scan",
            "fs",
            root,
            "--server",
            &server.url,
            "--source-uri",
            "host:web-01/srv",
            "--environment",
            "prod",
        ]),
        Some(ci.clone()),
    )
    .await;
    assert_eq!(out.status.code(), Some(1), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(server.locations(secret).await, [("etc/app.conf".to_owned(), true, false, false)]);
    let env: Option<String> =
        sqlx::query_scalar("SELECT environment FROM locations").fetch_one(&server.pool).await.unwrap();
    assert_eq!(env.as_deref(), Some("prod"));

    // Errors are exit code 2: the result is unknown, not "clean".
    let no_uri = cli(args(&["scan", "fs", root, "--server", &server.url]), Some(ci.clone())).await;
    assert_eq!(no_uri.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&no_uri.stderr).contains("--source-uri is required"));

    let no_token = cli(args(&["scan", "fs", root, "--server", &server.url, "--source-uri", "x"]), None).await;
    assert_eq!(no_token.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&no_token.stderr).contains("SECRETTRACE_TOKEN"));

    let match_only = server.api_token(&["ingest:profile"]).await;
    let out = cli(args(&["scan", "fs", root, "--server", &server.url, "--source-uri", "x"]), Some(match_only)).await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("ingest:match scope"), "{stderr}");
    // The aborted scan was closed as failed.
    let failed: i64 = sqlx::query_scalar("SELECT count(*) FROM scan_jobs WHERE status = 'failed'")
        .fetch_one(&server.pool)
        .await
        .unwrap();
    assert_eq!(failed, 1);

    let revoked = format!("stk_00000000_{}", "a".repeat(43));
    let out = cli(args(&["scan", "fs", root, "--server", &server.url, "--source-uri", "x"]), Some(revoked)).await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("401"), "{stderr}");

    // Plain http to a non-loopback host is refused before anything is sent.
    let out =
        cli(args(&["scan", "fs", root, "--server", "http://st.example.com", "--source-uri", "x"]), Some(ci)).await;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("refusing plain http"));
}
