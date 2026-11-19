//! Black-box tests of the `secrettrace` binary.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write as _;
use std::process::{Command, Output, Stdio};

use serde_json::Value;
use st_core::{SecretType, prepare};

fn run(args: &[&str], stdin: &str) -> Output {
    run_env(args, stdin, &[])
}

fn run_env(args: &[&str], stdin: &str, env: &[(&str, &str)]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_secrettrace"))
        .args(args)
        .envs(env.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    child.wait_with_output().unwrap()
}

fn lines(out: &Output) -> Vec<Value> {
    String::from_utf8_lossy(&out.stdout).lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

const ENV: &str = "DB_PASSWORD=hunter2hunter2\nREDIS_URL=redis://:r3dis-Passw0rd@cache:6379/0\nretries=5\n";

#[test]
fn digest_from_stdin() {
    let out = run(&["digest", "--type", "password", "--stdin"], "hunter2hunter2\n");
    assert!(out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["digest"], prepare(SecretType::Password, "hunter2hunter2").unwrap().0.to_hex());
    assert_eq!(v["masked"], "••••••••");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("hunter2"));
}

#[test]
fn extract_prints_masked_candidates_without_digests() {
    let out = run(&["extract", "-"], ENV);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    for leak in ["hunter2hunter2", "r3dis-Passw0rd", "\"digest\""] {
        assert!(!stdout.contains(leak), "output contains {leak}");
    }
    let rows = lines(&out);
    let pw = rows.iter().find(|r| r["key"] == "DB_PASSWORD").expect("password candidate");
    assert_eq!(
        (pw["path"].as_str(), pw["type"].as_str(), pw["span"]["line"].as_u64()),
        (Some("-"), Some("password"), Some(1))
    );
    assert!(rows.iter().any(|r| r["detector"] == "url_password" && r["span"]["line"] == 2));
}

#[test]
fn extract_digests_only_on_request_and_filters_confidence() {
    let out = run(&["extract", "--show-digests", "--min-confidence", "medium", "-"], ENV);
    assert!(out.status.success());
    let rows = lines(&out);
    let expected = prepare(SecretType::Password, "hunter2hunter2").unwrap().0.to_hex();
    assert!(rows.iter().any(|r| r["digest"] == expected.as_str()));
    assert!(rows.iter().all(|r| r["confidence"] != "low"));
}

#[test]
fn extract_reports_unreadable_paths() {
    let out = run(&["extract", "/nonexistent/secrettrace-test", "crates"], "");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot open"), "{stderr}");
}

/// A GitHub-token-shaped value built at runtime (keeps the repository clean for gitleaks).
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

#[test]
fn scan_fs_prints_masked_rows_and_a_summary() {
    let dir = tempfile::TempDir::new().unwrap();
    let secret = token(3);
    std::fs::write(dir.path().join(".env"), format!("GITHUB_TOKEN={secret}\nDB_PASSWORD=hunter2hunter2\n")).unwrap();
    std::fs::create_dir(dir.path().join("node_modules")).unwrap();
    std::fs::write(dir.path().join("node_modules/x.js"), format!("'{secret}'")).unwrap();
    let root = dir.path().to_str().unwrap();

    let out = run(&["scan", "fs", root, "--exclude", "node_modules", "-j", "2"], "");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    for leak in [secret.as_str(), "hunter2hunter2", "\"digest\""] {
        assert!(!stdout.contains(leak), "output contains {leak}");
    }
    let rows = lines(&out);
    let gh = rows.iter().find(|r| r["rule"] == "github_token").expect("token row");
    assert_eq!(
        (gh["source"].as_str(), gh["path"].as_str(), gh["root"].as_str()),
        (Some("filesystem"), Some(".env"), Some(root))
    );
    assert!(rows.iter().all(|r| r["path"] == ".env"), "node_modules is excluded");
    assert!(stderr.contains("scanned 1 documents"), "{stderr}");
    assert!(stderr.contains("1 excluded"), "{stderr}");
}

#[cfg(unix)]
#[test]
fn scan_fs_fails_when_files_are_unreadable() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::TempDir::new().unwrap();
    let locked = dir.path().join("locked.env");
    std::fs::write(&locked, "PASSWORD=correct-horse-battery\n").unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&locked).is_ok() {
        return; // root ignores permissions
    }
    let out = run(&["scan", "fs", dir.path().to_str().unwrap()], "");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("locked.env") && stderr.contains("could not be read"), "{stderr}");
    assert!(!stderr.contains("correct-horse"));
}

#[test]
fn scan_git_locates_history_and_ignores_inherited_git_env() {
    let dir = tempfile::TempDir::new().unwrap();
    let repo = dir.path();
    git(repo, &["init", "-q", "-b", "main"]);
    std::fs::write(repo.join("README"), "demo\n").unwrap();
    std::fs::write(repo.join("app.env"), format!("TOKEN={}\n", token(5))).unwrap();
    git(repo, &["add", "-A"]);
    git(repo, &["commit", "-q", "-m", "leak"]);
    git(repo, &["rm", "-q", "app.env"]);
    git(repo, &["commit", "-q", "-m", "fix"]);

    // As if run from a git hook of another repository.
    let poisoned = [("GIT_DIR", "/nonexistent"), ("GIT_INDEX_FILE", "/nonexistent/index")];
    let out = run_env(&["scan", "git", repo.to_str().unwrap(), "--locate", "--min-confidence", "high"], "", &poisoned);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let rows = lines(&out);
    assert_eq!(rows.len(), 1, "{rows:?}");
    let row = &rows[0];
    assert_eq!(
        (row["source"].as_str(), row["path"].as_str(), row["in_head"].as_bool()),
        (Some("git"), Some("app.env"), Some(false))
    );
    let changes: Vec<_> =
        row["occurrences"].as_array().unwrap().iter().map(|o| o["change"].as_str().unwrap()).collect();
    assert_eq!(changes, ["added", "removed"]);
    assert!(stderr.contains("scanned 2 documents"), "{stderr}");

    let out = run(&["scan", "git", repo.to_str().unwrap(), "--rev=--output=/tmp/x"], "");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("invalid revision"));
}
