//! Black-box tests of the `secrettrace` binary.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write as _;
use std::process::{Command, Output, Stdio};

use serde_json::Value;
use st_core::{SecretType, prepare};

fn run(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_secrettrace"))
        .args(args)
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
