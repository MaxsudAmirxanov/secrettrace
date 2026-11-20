//! Sending a local scan to the server: `POST /ingest/scans` → `match` → `findings` →
//! `complete` (the same protocol agents use, see `docs/architecture.md` § 8).
//!
//! Only digests leave the machine, and only for `/match`; locations are sent just for
//! the digests the server reports as registered. The wire types mirror the server's
//! `st_server::ingest` request bodies (the integration test checks them against it).

use std::collections::{BTreeMap, HashSet};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use st_core::Digest;
use st_extract::{Candidate, Confidence, Detector, Encoding};

use crate::client::{ApiError, Auth, Client};

/// Server-side caps on one request (the server also returns its own, possibly lower).
const MAX_DIGESTS_PER_REQUEST: usize = 10_000;
const MAX_FINDINGS_PER_REQUEST: usize = 5_000;
pub const MAX_PATH_LEN: usize = 1024;
const MAX_ENCODINGS: usize = 8;

#[derive(Serialize)]
struct SourceRef<'a> {
    #[serde(rename = "type")]
    source_type: &'a str,
    uri: &'a str,
}

#[derive(Serialize)]
struct ScanStart<'a> {
    source: SourceRef<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    environment: Option<&'a str>,
    full: bool,
}

#[derive(Deserialize)]
struct ScanLimits {
    max_digests_per_request: usize,
    max_findings_per_request: usize,
}

#[derive(Deserialize)]
struct ScanStarted {
    scan_id: String,
    limits: ScanLimits,
}

#[derive(Serialize)]
struct MatchRequest<'a> {
    digests: &'a [Digest],
}

#[derive(Deserialize)]
struct MatchResponse {
    matched: Vec<Digest>,
}

/// One location of a matched candidate: metadata only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingOut {
    pub digest: Digest,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    pub in_current_state: bool,
    pub detector: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    pub confidence: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub encodings: Vec<&'static str>,
}

#[derive(Serialize)]
struct FindingsRequest<'a> {
    findings: &'a [FindingOut],
}

/// Server counters for the submitted findings, summed over requests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct FindingsTotals {
    pub accepted: u64,
    pub ignored: u64,
    pub new_locations: u64,
    pub updated_locations: u64,
    pub violations: u64,
}

#[derive(Serialize)]
struct ScanComplete<'a> {
    status: &'a str,
    stats: &'a BTreeMap<String, u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

#[derive(Deserialize)]
struct ScanCompleted {
    no_longer_present: u64,
}

/// What a scan is about: `git_repo` or `filesystem` plus a credential-free URI.
pub struct Target<'a> {
    pub source_type: &'static str,
    pub uri: &'a str,
    pub environment: Option<&'a str>,
    /// The scan covers the whole current state of the source.
    pub full: bool,
}

/// A started server-side scan.
pub struct Scan<'c> {
    client: &'c Client,
    token: &'c str,
    pub id: String,
    max_digests: usize,
    max_findings: usize,
}

impl<'c> Scan<'c> {
    pub fn start(client: &'c Client, token: &'c str, target: &Target<'_>) -> anyhow::Result<Self> {
        let body = ScanStart {
            source: SourceRef { source_type: target.source_type, uri: target.uri },
            environment: target.environment,
            full: target.full,
        };
        let started: ScanStarted = client
            .post("/ingest/scans", Auth::Bearer(token), &body)
            .map_err(|e| explain(&e, "ingest:profile"))
            .context("cannot start the scan")?
            .body;
        Ok(Self {
            client,
            token,
            id: started.scan_id,
            max_digests: started.limits.max_digests_per_request.clamp(1, MAX_DIGESTS_PER_REQUEST),
            max_findings: started.limits.max_findings_per_request.clamp(1, MAX_FINDINGS_PER_REQUEST),
        })
    }

    /// The registered subset of `digests` (unique, any order).
    pub fn match_digests(&self, digests: &[Digest]) -> anyhow::Result<HashSet<Digest>> {
        let mut matched = HashSet::new();
        for chunk in digests.chunks(self.max_digests) {
            let reply: MatchResponse = self
                .client
                .post(
                    &format!("/ingest/scans/{}/match", self.id),
                    Auth::Bearer(self.token),
                    &MatchRequest { digests: chunk },
                )
                .map_err(|e| explain(&e, "ingest:match"))
                .context("matching digests failed")?
                .body;
            matched.extend(reply.matched);
        }
        Ok(matched)
    }

    pub fn findings(&self, findings: &[FindingOut]) -> anyhow::Result<FindingsTotals> {
        let mut total = FindingsTotals::default();
        for chunk in findings.chunks(self.max_findings) {
            let r: FindingsTotals = self
                .client
                .post(
                    &format!("/ingest/scans/{}/findings", self.id),
                    Auth::Bearer(self.token),
                    &FindingsRequest { findings: chunk },
                )
                .map_err(|e| explain(&e, "ingest:findings"))
                .context("sending findings failed")?
                .body;
            total.accepted += r.accepted;
            total.ignored += r.ignored;
            total.new_locations += r.new_locations;
            total.updated_locations += r.updated_locations;
            total.violations += r.violations;
        }
        Ok(total)
    }

    /// Finish the scan. `error` (a fixed client-side reason, never file contents) marks it
    /// failed; returns how many locations the server marked as no longer present.
    pub fn complete(self, stats: &BTreeMap<String, u64>, error: Option<&str>) -> anyhow::Result<u64> {
        let body = ScanComplete { status: if error.is_some() { "failed" } else { "succeeded" }, stats, error };
        let done: ScanCompleted = self
            .client
            .post(&format!("/ingest/scans/{}/complete", self.id), Auth::Bearer(self.token), &body)
            .map_err(|e| explain(&e, "ingest:profile"))
            .context("cannot complete the scan")?
            .body;
        Ok(done.no_longer_present)
    }
}

/// Add a hint to the common token mistakes.
fn explain(e: &ApiError, scope: &str) -> anyhow::Error {
    let hint = match e.status.map(|s| s.as_u16()) {
        Some(401) => " (the API token is invalid, expired or revoked)",
        Some(403) => match scope {
            "ingest:profile" => " (the token needs the ingest:profile scope)",
            "ingest:match" => " (the token needs the ingest:match scope)",
            _ => " (the token needs the ingest:findings scope)",
        },
        Some(429) => " (rate limit: try again later or ask for a higher ST_INGEST_DIGESTS_PER_HOUR)",
        _ => "",
    };
    anyhow::anyhow!("{e}{hint}")
}

/// Convert a matched candidate into a finding the server accepts: fields outside the
/// server's charsets are dropped rather than failing the whole request.
pub fn finding(
    c: &Candidate,
    path: &str,
    blob: Option<&str>,
    commit: Option<&str>,
    in_current_state: bool,
) -> FindingOut {
    let charset = |s: &str, extra: &[u8], lower_only: bool| {
        (1..=64).contains(&s.len())
            && s.bytes().all(|b| {
                b.is_ascii_digit()
                    || b.is_ascii_lowercase()
                    || (!lower_only && b.is_ascii_uppercase())
                    || extra.contains(&b)
            })
    };
    FindingOut {
        digest: c.digest,
        path: sanitize_path(path),
        line: Some(c.span.line).filter(|&l| l > 0),
        column: Some(c.span.column).filter(|&l| l > 0),
        blob: blob.map(str::to_owned),
        commit: commit.map(str::to_owned),
        in_current_state,
        detector: detector(c.detector),
        rule: c.rule.filter(|r| charset(r, b"_", true)).map(str::to_owned),
        confidence: match c.confidence {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        },
        key: c.key.as_deref().filter(|k| charset(k, b"_.:-", false)).map(str::to_owned),
        encodings: c
            .encodings
            .iter()
            .take(MAX_ENCODINGS)
            .map(|e| match e {
                Encoding::Base64 => "base64",
                Encoding::Percent => "percent",
                Encoding::JsonString => "json_string",
            })
            .collect(),
    }
}

const fn detector(d: Detector) -> &'static str {
    match d {
        Detector::Known => "known",
        Detector::Pem => "pem",
        Detector::SshPublicKey => "ssh_public_key",
        Detector::UrlPassword => "url_password",
        Detector::Url => "url",
        Detector::KeyValue => "key_value",
        Detector::AuthHeader => "auth_header",
        Detector::BasicAuth => "basic_auth",
        Detector::HighEntropy => "high_entropy",
    }
}

/// A path the server accepts: control characters → U+FFFD, at most [`MAX_PATH_LEN`]
/// bytes (cut at a char boundary), never empty.
pub fn sanitize_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len().min(MAX_PATH_LEN));
    for c in path.chars() {
        let c = if c.is_control() { char::REPLACEMENT_CHARACTER } else { c };
        if out.len() + c.len_utf8() > MAX_PATH_LEN {
            break;
        }
        out.push(c);
    }
    if out.is_empty() { "?".to_owned() } else { out }
}

/// A source URI without credentials: userinfo of `scheme://user:pw@host/…` and of
/// scp-like `user:pw@host:path` is removed (the plain `git@` user of scp-like URLs is
/// kept), as are query and fragment.
pub fn strip_credentials(url: &str) -> String {
    let url = url.split(['?', '#']).next().unwrap_or_default();
    if let Some((scheme, rest)) = url.split_once("://") {
        let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
        let host = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
        return format!("{scheme}://{host}{path}");
    }
    match url.split_once('@') {
        Some((user, rest)) if !user.contains('/') => match user.split_once(':') {
            Some((name, _password)) if !name.is_empty() => format!("{name}@{rest}"),
            Some(_) => rest.to_owned(),
            None => url.to_owned(),
        },
        _ => url.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_are_stripped_from_remote_urls() {
        let cases = [
            (
                "https://gitlab-ci-token:glcbt-abc@gitlab.example.com/group/app.git",
                "https://gitlab.example.com/group/app.git",
            ),
            ("https://x-access-token@github.com/acme/app", "https://github.com/acme/app"),
            ("https://github.com/acme/app.git", "https://github.com/acme/app.git"),
            ("https://github.com/acme/app.git?token=abc#frag", "https://github.com/acme/app.git"),
            ("ssh://git@github.com:22/acme/app.git", "ssh://github.com:22/acme/app.git"),
            ("git@github.com:acme/app.git", "git@github.com:acme/app.git"),
            ("deploy:hunter2@host:repo.git", "deploy@host:repo.git"),
            ("/srv/git/app.git", "/srv/git/app.git"),
            ("https://host/path/with@sign", "https://host/path/with@sign"),
        ];
        for (input, want) in cases {
            assert_eq!(strip_credentials(input), want, "{input}");
        }
    }

    #[test]
    fn paths_are_made_acceptable() {
        assert_eq!(sanitize_path("a\nb"), "a\u{fffd}b");
        assert_eq!(sanitize_path(""), "?");
        let long = "é".repeat(MAX_PATH_LEN);
        let cut = sanitize_path(&long);
        assert!(cut.len() <= MAX_PATH_LEN && cut.len() >= MAX_PATH_LEN - 1);
    }
}
