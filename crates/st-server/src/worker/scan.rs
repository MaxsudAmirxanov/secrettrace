//! Scanning a mirror: incremental history plus the whole current tree, and turning
//! matched candidates into ingest findings.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::num::NonZeroUsize;
use std::ops::ControlFlow;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Value, json};
use st_core::Digest;
use st_extract::{Candidate, Extractor};
use st_source::{Change, GitOptions, GitRepo, Locator, ObjectId, Occurrence, Report};

use super::JobError;
use crate::ingest::{self, FindingIn};

/// More ref tips than this are not stored: the next scan reads the whole history.
pub const MAX_TIPS: usize = 10_000;
const MAX_ENCODINGS: usize = 8;

/// What a scan of the mirror produced (before matching).
#[derive(Debug)]
pub struct Scanned {
    pub report: Report,
    /// Blobs of the `HEAD` tree and their paths.
    pub head: HashMap<ObjectId, Vec<String>>,
    /// Commit tips at scan time: this scan's start points, the next scan's exclusions.
    pub tips: Vec<ObjectId>,
    pub incremental: bool,
    /// Paths (as stored in locators) of `HEAD` blobs this run did not read: too large,
    /// binary, missing. Their locations keep `in_current_state`.
    pub unread_paths: Vec<String>,
}

/// Incremental state of a source (`sources.scan_state`).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct State {
    pub tips: Vec<ObjectId>,
    /// Registry watermark at the start of the scan that wrote the state.
    pub registry: Option<String>,
}

/// State recorded by the last successful scan (`{"v":1,"tips":[…],"registry":"…"}`);
/// anything unexpected means "no state": a full scan.
#[must_use]
pub fn parse_state(state: &Value) -> State {
    if state.get("v").and_then(Value::as_u64) != Some(1) {
        return State::default();
    }
    let registry = state.get("registry").and_then(Value::as_str).map(str::to_owned);
    let tips = match state.get("tips").and_then(Value::as_array) {
        Some(tips) if tips.len() <= MAX_TIPS => {
            let parsed: Option<Vec<ObjectId>> = tips.iter().map(|t| t.as_str().and_then(ObjectId::parse)).collect();
            parsed.unwrap_or_default()
        }
        _ => Vec::new(),
    };
    State { tips, registry }
}

#[must_use]
pub fn state_json(tips: &[ObjectId], registry: &str) -> Value {
    if tips.len() > MAX_TIPS {
        json!({ "v": 1, "registry": registry })
    } else {
        json!({ "v": 1, "tips": tips, "registry": registry })
    }
}

/// Registry watermark: secret count, newest `created_at` (µs) and pepper versions.
#[must_use]
pub fn watermark(secrets: i64, newest_micros: Option<i64>, pepper_versions: &str) -> String {
    let newest = newest_micros.map_or_else(|| "-".to_owned(), |t| t.to_string());
    format!("{secrets}:{newest}:{pepper_versions}")
}

/// A scan failure as a fixed message: git's or the repository's own text is never kept.
#[must_use]
pub fn source_error(e: &st_source::SourceError) -> JobError {
    use st_source::SourceError as E;
    let message = match e {
        E::Git { command, .. } => format!("scan failed: git {command} failed"),
        E::GitProtocol(command) => format!("scan failed: unexpected output from git {command}"),
        E::GitSpawn(_) => "scan failed: cannot run git".to_owned(),
        E::NotARepository(_) => "scan failed: the mirror is not a git repository".to_owned(),
        _ => "scan failed".to_owned(),
    };
    JobError::retryable(message)
}

/// Blocking: scan the history from the current tips, minus what `old_tips` (those still
/// present) reach, plus every blob of the `HEAD` tree. Every git call is killed once
/// `cancel` is set; the scan then returns `Err(None)`.
pub fn scan_mirror(
    git: &Path,
    mirror: &Path,
    old_tips: &[ObjectId],
    max_blob_bytes: u64,
    threads: NonZeroUsize,
    cancel: &Arc<AtomicBool>,
) -> Result<Scanned, Option<JobError>> {
    let failed = |e: st_source::SourceError| {
        if cancel.load(Ordering::Relaxed) { None } else { Some(source_error(&e)) }
    };
    let repo = GitRepo::open_with(mirror, git).map_err(failed)?.with_cancel(Arc::clone(cancel));
    let tips = repo.ref_tips().map_err(failed)?;
    let mut exclude: Vec<ObjectId> = repo.existing_commits(old_tips).map_err(failed)?.into_iter().collect();
    exclude.sort_unstable();
    // History from exactly the tips recorded for the next scan (not `--all`), plus HEAD.
    let options = GitOptions {
        max_blob_bytes,
        include: tips.clone(),
        exclude,
        current_tree: Some("HEAD".into()),
        ..GitOptions::default()
    };
    let extractor = Extractor::default();
    let mut read: HashSet<ObjectId> = HashSet::new();
    let result = st_source::scan(&extractor, threads, |visit| {
        if tips.is_empty() {
            // No refs, nothing to read (an empty `include` would mean `--all`).
            return Ok(st_source::Stats::default());
        }
        repo.blobs(&options, &mut |doc| {
            if cancel.load(Ordering::Relaxed) {
                return ControlFlow::Break(());
            }
            if let Locator::Git { blob, .. } = &doc.locator {
                read.insert(blob.clone());
            }
            visit(doc)
        })
    });
    if cancel.load(Ordering::Relaxed) {
        return Err(None);
    }
    let report = result.map_err(failed)?;
    let head = repo.head_blobs().map_err(failed)?;
    let mut unread_paths: Vec<String> = head
        .iter()
        .filter(|(blob, _)| !read.contains(*blob))
        .flat_map(|(_, paths)| paths.iter().map(|p| sanitize_path(p)))
        .collect();
    unread_paths.sort_unstable();
    unread_paths.dedup();
    Ok(Scanned { report, head, tips, incremental: !options.exclude.is_empty(), unread_paths })
}

/// Unique digests of every candidate, in first-seen order.
#[must_use]
pub fn unique_digests(report: &Report) -> Vec<Digest> {
    let mut seen = HashSet::new();
    report.documents.iter().flat_map(|d| &d.candidates).map(|c| c.digest).filter(|d| seen.insert(*d)).collect()
}

/// Blobs holding at least one matched digest.
#[must_use]
pub fn matched_blobs(report: &Report, matched: &HashSet<Digest>) -> Vec<ObjectId> {
    let mut blobs: Vec<ObjectId> = report
        .documents
        .iter()
        .filter(|d| d.candidates.iter().any(|c| matched.contains(&c.digest)))
        .filter_map(|d| match &d.locator {
            Locator::Git { blob, .. } => Some(blob.clone()),
            Locator::Filesystem { .. } => None,
        })
        .collect();
    blobs.sort_unstable();
    blobs.dedup();
    blobs
}

/// Findings for matched candidates: one per path of the blob in the `HEAD` tree
/// (`in_current_state`), plus the history path when the blob is not there under it.
#[must_use]
pub fn findings(
    scanned: &Scanned,
    matched: &HashSet<Digest>,
    occurrences: &HashMap<ObjectId, Vec<Occurrence>>,
) -> Vec<FindingIn> {
    let mut out = Vec::new();
    for doc in &scanned.report.documents {
        let Locator::Git { blob, path } = &doc.locator else { continue };
        let head_paths = scanned.head.get(blob).map(Vec::as_slice).unwrap_or_default();
        let mut paths: Vec<(&str, bool)> = head_paths.iter().map(|p| (p.as_str(), true)).collect();
        if !head_paths.iter().any(|p| p == path) {
            paths.push((path, false));
        }
        let occ = occurrences.get(blob).map(Vec::as_slice).unwrap_or_default();
        for candidate in doc.candidates.iter().filter(|c| matched.contains(&c.digest)) {
            for &(p, current) in &paths {
                out.push(finding(candidate, blob, p, current, first_added(occ, p)));
            }
        }
    }
    out
}

fn first_added<'a>(occ: &'a [Occurrence], path: &str) -> Option<&'a ObjectId> {
    let added = || occ.iter().filter(|o| o.change == Change::Added);
    added().find(|o| o.path == path).or_else(|| added().next()).map(|o| &o.commit)
}

fn finding(c: &Candidate, blob: &ObjectId, path: &str, current: bool, commit: Option<&ObjectId>) -> FindingIn {
    let charset = |s: &str, extra: &[u8], lower_only: bool| {
        (1..=64).contains(&s.len())
            && s.bytes().all(|b| {
                b.is_ascii_digit()
                    || b.is_ascii_lowercase()
                    || (!lower_only && b.is_ascii_uppercase())
                    || extra.contains(&b)
            })
    };
    FindingIn {
        digest: c.digest,
        path: sanitize_path(path),
        line: Some(c.span.line).filter(|&l| l > 0),
        column: Some(c.span.column).filter(|&l| l > 0),
        blob: Some(blob.as_str().to_owned()),
        commit: commit.map(|c| c.as_str().to_owned()),
        in_current_state: current,
        detector: detector(c.detector),
        rule: c.rule.filter(|r| charset(r, b"_", true)).map(str::to_owned),
        confidence: match c.confidence {
            st_extract::Confidence::Low => ingest::Confidence::Low,
            st_extract::Confidence::Medium => ingest::Confidence::Medium,
            st_extract::Confidence::High => ingest::Confidence::High,
        },
        key: c.key.as_deref().filter(|k| charset(k, b"_.:-", false)).map(str::to_owned),
        encodings: c
            .encodings
            .iter()
            .take(MAX_ENCODINGS)
            .map(|e| match e {
                st_extract::Encoding::Base64 => ingest::Encoding::Base64,
                st_extract::Encoding::Percent => ingest::Encoding::Percent,
                st_extract::Encoding::JsonString => ingest::Encoding::JsonString,
            })
            .collect(),
    }
}

const fn detector(d: st_extract::Detector) -> ingest::Detector {
    use st_extract::Detector as D;
    match d {
        D::Known => ingest::Detector::Known,
        D::Pem => ingest::Detector::Pem,
        D::SshPublicKey => ingest::Detector::SshPublicKey,
        D::UrlPassword => ingest::Detector::UrlPassword,
        D::Url => ingest::Detector::Url,
        D::KeyValue => ingest::Detector::KeyValue,
        D::AuthHeader => ingest::Detector::AuthHeader,
        D::BasicAuth => ingest::Detector::BasicAuth,
        D::HighEntropy => ingest::Detector::HighEntropy,
    }
}

/// A location path the ingest rules accept: control characters → U+FFFD, at most
/// `MAX_PATH_LEN` bytes (cut at a char boundary), never empty.
#[must_use]
pub fn sanitize_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len().min(ingest::MAX_PATH_LEN));
    for c in path.chars().map(|c| if c.is_control() { '\u{FFFD}' } else { c }) {
        if out.len() + c.len_utf8() > ingest::MAX_PATH_LEN {
            break;
        }
        out.push(c);
    }
    if out.is_empty() {
        out.push('\u{FFFD}');
    }
    out
}

/// st-source counters as job stats.
#[must_use]
pub fn source_stats(s: &st_source::Stats) -> BTreeMap<String, u64> {
    [
        ("documents", s.documents),
        ("bytes", s.bytes),
        ("truncated", s.truncated),
        ("skipped_binary", s.skipped_binary),
        ("skipped_large", s.skipped_large),
        ("skipped_special", s.skipped_special),
        ("skipped_missing", s.skipped_missing),
        ("read_errors", s.read_errors),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trip_and_garbage() {
        let a = ObjectId::parse(&"a".repeat(40)).unwrap_or_else(|| panic!());
        let b = ObjectId::parse(&"b".repeat(64)).unwrap_or_else(|| panic!());
        let state = state_json(&[a.clone(), b.clone()], "3:17:1");
        assert_eq!(parse_state(&state), State { tips: vec![a.clone(), b], registry: Some("3:17:1".into()) });
        assert_eq!(parse_state(&json!({})), State::default());
        assert!(parse_state(&json!({"v": 2, "tips": [a.as_str()]})).tips.is_empty());
        assert!(parse_state(&json!({"v": 1, "tips": [a.as_str(), "HEAD"]})).tips.is_empty(), "one bad tip: full");
        assert!(parse_state(&json!({"v": 1, "tips": "x"})).tips.is_empty());
        assert_eq!(parse_state(&json!({"v": 1, "tips": [a.as_str()]})).registry, None, "pre-watermark state");
        let many: Vec<ObjectId> = (0..=MAX_TIPS).map(|_| a.clone()).collect();
        assert_eq!(state_json(&many, "w"), json!({"v": 1, "registry": "w"}));
    }

    #[test]
    fn watermarks_change_with_the_registry() {
        let base = watermark(3, Some(1_700_000_000_000_000), "1");
        assert_eq!(base, "3:1700000000000000:1");
        assert_ne!(base, watermark(4, Some(1_700_000_000_000_000), "1"), "a secret more");
        assert_ne!(base, watermark(3, Some(1_700_000_000_000_001), "1"), "one deleted, one added");
        assert_ne!(base, watermark(3, Some(1_700_000_000_000_000), "1,2"), "new pepper version");
        assert_eq!(watermark(0, None, "1"), "0:-:1");
        assert_eq!(parse_state(&state_json(&[], &base)).registry.as_deref(), Some(base.as_str()));
    }

    #[test]
    fn scan_errors_keep_no_git_text() {
        let e = st_source::SourceError::Git { command: "rev-list", message: "fatal: evil 'path'".into() };
        assert_eq!(source_error(&e).message, "scan failed: git rev-list failed");
        let e = st_source::SourceError::NotARepository("/data/repos/x.git: fatal …".into());
        assert_eq!(source_error(&e).message, "scan failed: the mirror is not a git repository");
    }

    #[test]
    fn paths_are_made_acceptable() {
        assert_eq!(sanitize_path("config/prod.env"), "config/prod.env");
        assert_eq!(sanitize_path("a\nb\u{7}"), "a\u{FFFD}b\u{FFFD}");
        let long = "é".repeat(600);
        let cut = sanitize_path(&long);
        assert!(cut.len() <= ingest::MAX_PATH_LEN && cut.len() >= ingest::MAX_PATH_LEN - 1);
        assert_eq!(sanitize_path(""), "\u{FFFD}");
    }
}
