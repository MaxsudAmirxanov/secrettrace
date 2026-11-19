//! Ingest of scan results from agents and CI (API tokens only).
//!
//! A scan is a `scan_jobs` row owned by the token that started it:
//!
//! 1. `start`: find or auto-create the source by `(type, uri)`, open a `running` job;
//! 2. `match_digests`: which of the client's digests are registered (any pepper version);
//! 3. `findings`: locations of matched digests; every digest is matched again, nothing is
//!    stored for unregistered ones; allow rules decide `is_allowed`;
//! 4. `complete`: close the job; a successful full scan clears `in_current_state` of the
//!    source's locations it did not report.
//!
//! `/match` and `/findings` are oracles ("is this digest registered?"), so they share one
//! per-token budget of unique digests and requests, and are audited (counts only). Scan
//! starts are rate-limited too. Digests, fingerprints and contents never reach logs, audit
//! details or error messages; URIs with credentials (userinfo, `?token=`…) are rejected.
//!
//! Known limitation until tokens are bound to sources (stage 13, mTLS CN): any ingest token
//! may report for any source and choose the scan `environment`, so it can make a location
//! fall under an environment-scoped allow rule. A full scan only clears `in_current_state`
//! of rows last reported by the same token, which keeps one token from erasing another's.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::{PgConnection, Postgres, Row as _, Transaction};
use st_core::Digest;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::audit::{self, AuditEvent};
use crate::auth::TokenPrincipal;
use crate::auth::ratelimit::RateLimiter;
use crate::crypto::Pepper;
use crate::error::ApiError;
use crate::model::SourceType;
use crate::policy::{Subject, first_match, load_rules};

pub const MAX_DIGESTS_PER_REQUEST: usize = 10_000;
pub const MAX_FINDINGS_PER_REQUEST: usize = 5_000;
/// Jobs older than this no longer accept data (the worker will fail them).
pub(crate) const JOB_MAX_AGE_HOURS: i32 = 24;
const MAX_URI_LEN: usize = 2048;
pub(crate) const MAX_PATH_LEN: usize = 1024;
const MAX_ENCODINGS: usize = 8;
const MAX_STATS_KEYS: usize = 32;
const MAX_ERROR_LEN: usize = 500;
const SOURCE_NAME_LEN: usize = 200;

// ── limits ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestLimits {
    /// Unique digests one token may submit per hour, `/match` and `/findings` together.
    pub digests_per_hour: u32,
    /// Requests per minute per token, shared by `/match` and `/findings`.
    pub match_requests_per_minute: u32,
    /// New scans per minute per token.
    pub scan_starts_per_minute: u32,
}

impl Default for IngestLimits {
    fn default() -> Self {
        Self { digests_per_hour: 200_000, match_requests_per_minute: 120, scan_starts_per_minute: 30 }
    }
}

/// Per-process ingest limiters, keyed by token id.
#[derive(Debug)]
pub struct IngestLimiter {
    pub limits: IngestLimits,
    digests: RateLimiter,
    match_requests: RateLimiter,
    scan_starts: RateLimiter,
}

impl IngestLimiter {
    #[must_use]
    pub fn new(limits: IngestLimits) -> Self {
        Self {
            limits,
            digests: RateLimiter::new(limits.digests_per_hour, Duration::from_secs(3600)),
            match_requests: RateLimiter::new(limits.match_requests_per_minute, Duration::from_secs(60)),
            scan_starts: RateLimiter::new(limits.scan_starts_per_minute, Duration::from_secs(60)),
        }
    }

    /// Count one `/match` or `/findings` request carrying `unique_digests`; `false` → 429.
    /// Both endpoints answer "is this digest registered?", so they share one budget.
    #[must_use]
    pub fn allow_digests(&self, token_id: Uuid, unique_digests: usize) -> bool {
        let key = token_id.to_string();
        let n = u32::try_from(unique_digests).unwrap_or(u32::MAX);
        self.match_requests.check(&key) && self.digests.check_n(&key, n)
    }

    /// Count one scan start; `false` → 429.
    #[must_use]
    pub fn allow_scan_start(&self, token_id: Uuid) -> bool {
        self.scan_starts.check(&token_id.to_string())
    }
}

impl Default for IngestLimiter {
    fn default() -> Self {
        Self::new(IngestLimits::default())
    }
}

// ── wire types ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceRef {
    #[serde(rename = "type")]
    pub source_type: SourceType,
    /// Repository URL, host path, image reference… Must not contain credentials.
    pub uri: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanStart {
    pub source: SourceRef,
    /// 1-64 chars of `[A-Za-z0-9._-]`; matched exactly by allow rules.
    pub environment: Option<String>,
    /// The scan covers the whole current state of the source: on success, locations it did
    /// not report are marked as no longer present.
    #[serde(default)]
    pub full: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ScanLimits {
    pub max_digests_per_request: usize,
    pub max_findings_per_request: usize,
    pub digests_per_hour: u32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ScanStarted {
    pub scan_id: Uuid,
    pub source_id: Uuid,
    pub limits: ScanLimits,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MatchRequest {
    /// Client-side digests (64 lowercase hex); duplicates are ignored.
    #[schema(value_type = Vec<String>, min_items = 1, max_items = 10000)]
    pub digests: Vec<Digest>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MatchResponse {
    /// The submitted digests that are registered, sorted. Names and ids are never returned.
    pub matched: Vec<String>,
}

/// Detector that produced a candidate (mirrors `st_extract::Detector`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Detector {
    Known,
    Pem,
    SshPublicKey,
    UrlPassword,
    Url,
    KeyValue,
    AuthHeader,
    BasicAuth,
    HighEntropy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    Base64,
    Percent,
    JsonString,
}

/// One location of a candidate. Only metadata: never the value or file contents.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct FindingIn {
    #[schema(value_type = String, pattern = "^[0-9a-f]{64}$")]
    pub digest: Digest,
    /// Path inside the source (relative), 1-1024 bytes.
    pub path: String,
    #[schema(minimum = 1)]
    pub line: Option<u32>,
    #[schema(minimum = 1)]
    pub column: Option<u32>,
    /// Git blob id (40 or 64 lowercase hex).
    pub blob: Option<String>,
    /// Git commit id (40 or 64 lowercase hex).
    pub commit: Option<String>,
    pub in_current_state: bool,
    pub detector: Detector,
    /// Known-format rule id, 1-64 of `[a-z0-9_]`.
    pub rule: Option<String>,
    pub confidence: Confidence,
    /// Name of the key the value was assigned to, 1-64 of `[A-Za-z0-9_.:-]`.
    pub key: Option<String>,
    #[serde(default)]
    pub encodings: Vec<Encoding>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct FindingsRequest {
    #[schema(min_items = 1, max_items = 5000)]
    pub findings: Vec<FindingIn>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct FindingsResponse {
    /// Findings whose digest is registered.
    pub accepted: u64,
    /// Findings whose digest is not registered (nothing stored).
    pub ignored: u64,
    pub new_locations: u64,
    pub updated_locations: u64,
    /// Accepted locations not covered by an allow rule.
    pub violations: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CompletionStatus {
    Succeeded,
    Failed,
}

impl CompletionStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanComplete {
    pub status: CompletionStatus,
    /// Counters only: up to 32 keys of `[a-z0-9_]`, non-negative integers.
    pub stats: Option<BTreeMap<String, u64>>,
    /// Short failure reason (≤ 500 chars). Never file contents.
    pub error: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ScanCompleted {
    pub status: CompletionStatus,
    /// Locations of the source marked as no longer in its current state (full scans).
    pub no_longer_present: u64,
}

// ── validation ──────────────────────────────────────────────────────────────

fn unprocessable(msg: impl Into<String>) -> ApiError {
    ApiError::Unprocessable(msg.into())
}

/// Query/fragment parameter names that carry credentials (`?private_token=…`,
/// `#access_token=…`); a name matches if it equals or ends with one of these.
const CREDENTIAL_PARAMS: &[&str] = &[
    "token",
    "private_token",
    "access_token",
    "auth",
    "password",
    "passwd",
    "pwd",
    "secret",
    "key",
    "apikey",
    "api_key",
    "sig",
    "signature",
    "credential",
    "credentials",
];

/// Would storing this URI store a credential? Errs on the side of rejecting: browsers and
/// URL libraries accept `https:\\u:p@h`, `https:/u:p@h` and `https:///u:p@h` too.
pub(crate) fn has_credentials(uri: &str) -> bool {
    authority_has_credentials(uri) || params_have_credentials(uri)
}

fn authority_has_credentials(uri: &str) -> bool {
    let scheme_end = uri.find(':').filter(|&i| {
        let scheme = &uri[..i];
        scheme.starts_with(|c: char| c.is_ascii_alphabetic())
            && scheme.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    });
    if let Some(i) = scheme_end {
        let after = &uri[i + 1..];
        let host_part = after.trim_start_matches(['/', '\\']);
        if host_part.len() < after.len() {
            // `scheme:` + slashes: an authority follows. A backslash in it is either a
            // separator in disguise or garbage; both are rejected.
            let raw = host_part.split(['/', '?', '#']).next().unwrap_or_default();
            let authority = host_part.split(['/', '\\', '?', '#']).next().unwrap_or_default();
            return authority.contains('@') || raw.contains('\\');
        }
    }
    // No authority (scp-like `user@host:path`): a colon before the `@` is a password.
    // Not userinfo: `registry:5000/img@sha256:…` (a `/` before the `@`) and `redis:7@sha256:…`.
    uri.split_once('@').is_some_and(|(userinfo, rest)| {
        userinfo.contains(':')
            && !userinfo.contains('/')
            && !["sha256:", "sha384:", "sha512:"].iter().any(|d| rest.starts_with(d))
    })
}

fn params_have_credentials(uri: &str) -> bool {
    let Some(i) = uri.find(['?', '#']) else { return false };
    uri[i + 1..].split(['&', ';', '?', '#']).any(|param| {
        let name = param.split('=').next().unwrap_or_default();
        let name = percent_decode_ascii(name).to_ascii_lowercase();
        !name.is_empty() && CREDENTIAL_PARAMS.iter().any(|c| name.ends_with(c))
    })
}

/// `%XX` → byte for ASCII only (enough to see through `private%5Ftoken`).
fn percent_decode_ascii(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        let decoded = (bytes[i] == b'%')
            .then(|| s.get(i + 1..i + 3))
            .flatten()
            .and_then(|h| u8::from_str_radix(h, 16).ok())
            .filter(u8::is_ascii);
        if let Some(b) = decoded {
            out.push(char::from(b));
            i += 3;
        } else {
            out.push(char::from(bytes[i]));
            i += 1;
        }
    }
    out
}

pub(crate) fn validate_uri(uri: &str) -> Result<(), ApiError> {
    if uri.is_empty() || uri.len() > MAX_URI_LEN {
        return Err(unprocessable(format!("source.uri must be 1-{MAX_URI_LEN} bytes")));
    }
    if uri.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(unprocessable("source.uri must not contain whitespace or control characters"));
    }
    if has_credentials(uri) {
        return Err(unprocessable("source.uri must not contain credentials"));
    }
    Ok(())
}

pub(crate) fn validate_environment(env: Option<&str>) -> Result<Option<String>, ApiError> {
    match env {
        None => Ok(None),
        Some(e)
            if (1..=64).contains(&e.len())
                && e.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')) =>
        {
            Ok(Some(e.to_owned()))
        }
        Some(_) => Err(unprocessable("environment must be 1-64 chars of [A-Za-z0-9._-]")),
    }
}

/// Name of an auto-created source: `"{type}:{uri}"`, shortened with a hash suffix.
pub(crate) fn source_name(source_type: SourceType, uri: &str) -> String {
    let name = format!("{}:{uri}", source_type_str(source_type));
    if name.chars().count() <= SOURCE_NAME_LEN {
        return name;
    }
    let hash = hex::encode(Sha256::digest(name.as_bytes()));
    let head: String = name.chars().take(SOURCE_NAME_LEN - 9).collect();
    format!("{head}~{}", &hash[..8])
}

const fn source_type_str(t: SourceType) -> &'static str {
    match t {
        SourceType::GitRepo => "git_repo",
        SourceType::Filesystem => "filesystem",
        SourceType::DockerImage => "docker_image",
        SourceType::K8s => "k8s",
        SourceType::CiLog => "ci_log",
        SourceType::AppLog => "app_log",
        SourceType::Wiki => "wiki",
    }
}

/// Identity of a location: one row per (secret, source, path).
fn locator_key(source_type: SourceType, uri: &str, path: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"secrettrace/location/v1\0");
    for part in [source_type_str(source_type), uri, path] {
        let len = u32::try_from(part.len()).unwrap_or(u32::MAX);
        h.update(len.to_be_bytes());
        h.update(part.as_bytes());
    }
    h.finalize().into()
}

pub(crate) fn is_object_id(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub(crate) fn validate_finding(i: usize, f: &FindingIn) -> Result<(), ApiError> {
    let field = |name: &str, rule: &str| unprocessable(format!("findings[{i}].{name} {rule}"));
    if f.path.is_empty() || f.path.len() > MAX_PATH_LEN || f.path.chars().any(char::is_control) {
        return Err(field("path", "must be 1-1024 bytes without control characters"));
    }
    if f.line == Some(0) || f.column == Some(0) {
        return Err(field("line/column", "must be >= 1"));
    }
    for (name, id) in [("blob", &f.blob), ("commit", &f.commit)] {
        if id.as_deref().is_some_and(|s| !is_object_id(s)) {
            return Err(field(name, "must be 40 or 64 lowercase hex characters"));
        }
    }
    let charset = |s: &str, extra: &[u8], lower_only: bool| {
        (1..=64).contains(&s.len())
            && s.bytes().all(|b| {
                b.is_ascii_digit()
                    || b.is_ascii_lowercase()
                    || (!lower_only && b.is_ascii_uppercase())
                    || extra.contains(&b)
            })
    };
    if f.rule.as_deref().is_some_and(|r| !charset(r, b"_", true)) {
        return Err(field("rule", "must be 1-64 chars of [a-z0-9_]"));
    }
    if f.key.as_deref().is_some_and(|k| !charset(k, b"_.:-", false)) {
        return Err(field("key", "must be 1-64 chars of [A-Za-z0-9_.:-]"));
    }
    if f.encodings.len() > MAX_ENCODINGS {
        return Err(field("encodings", "must have at most 8 entries"));
    }
    Ok(())
}

fn validate_completion(req: &ScanComplete) -> Result<(), ApiError> {
    if let Some(stats) = &req.stats {
        if stats.len() > MAX_STATS_KEYS {
            return Err(unprocessable(format!("stats must have at most {MAX_STATS_KEYS} keys")));
        }
        let bad_key = |k: &String| {
            !(1..=64).contains(&k.len())
                || !k.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        };
        if stats.keys().any(bad_key) {
            return Err(unprocessable("stats keys must be 1-64 chars of [a-z0-9_]"));
        }
    }
    if let Some(e) = &req.error
        && (e.chars().count() > MAX_ERROR_LEN || e.chars().any(char::is_control))
    {
        return Err(unprocessable(format!("error must be at most {MAX_ERROR_LEN} chars without control characters")));
    }
    Ok(())
}

fn locator_json(f: &FindingIn) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("path".into(), json!(f.path));
    if let Some(v) = f.line {
        m.insert("line".into(), json!(v));
    }
    if let Some(v) = f.column {
        m.insert("column".into(), json!(v));
    }
    if let Some(v) = &f.blob {
        m.insert("blob".into(), json!(v));
    }
    if let Some(v) = &f.commit {
        m.insert("commit".into(), json!(v));
    }
    m.insert("detector".into(), json!(f.detector));
    if let Some(v) = &f.rule {
        m.insert("rule".into(), json!(v));
    }
    m.insert("confidence".into(), json!(f.confidence));
    if let Some(v) = &f.key {
        m.insert("key".into(), json!(v));
    }
    if !f.encodings.is_empty() {
        m.insert("encodings".into(), json!(f.encodings));
    }
    Value::Object(m)
}

/// A location to upsert after merging the request's duplicates.
#[derive(Debug, Clone, PartialEq)]
struct Pending {
    secret_id: Uuid,
    key: [u8; 32],
    path: String,
    locator: Value,
    in_current_state: bool,
}

/// Merge findings for the same (secret, location): `in_current_state` is OR-ed and the
/// locator comes from an in-current-state finding if there is one, else the first.
fn merge(items: impl IntoIterator<Item = Pending>) -> Vec<Pending> {
    let mut out: Vec<Pending> = Vec::new();
    let mut index: HashMap<(Uuid, [u8; 32]), usize> = HashMap::new();
    for item in items {
        if let Some(&i) = index.get(&(item.secret_id, item.key)) {
            let existing = &mut out[i];
            if item.in_current_state && !existing.in_current_state {
                existing.locator = item.locator;
                existing.in_current_state = true;
            }
        } else {
            index.insert((item.secret_id, item.key), out.len());
            out.push(item);
        }
    }
    out
}

// ── database ────────────────────────────────────────────────────────────────

/// Registered secret per digest, over every configured pepper version. Secrets of any
/// status match: a leaked revoked or rotated value is still a leak.
pub(crate) async fn registered(
    conn: &mut PgConnection,
    pepper: &Pepper,
    digests: &[Digest],
) -> Result<HashMap<usize, Uuid>, sqlx::Error> {
    let mut idx = Vec::new();
    let mut versions = Vec::new();
    let mut fps = Vec::new();
    for (i, d) in digests.iter().enumerate() {
        for (v, fp) in pepper.fingerprint_all(d) {
            idx.push(i32::try_from(i).unwrap_or(i32::MAX));
            versions.push(i16::try_from(v).unwrap_or(i16::MAX));
            fps.push(fp.as_bytes().to_vec());
        }
    }
    let rows = sqlx::query(
        "SELECT u.idx, s.id FROM UNNEST($1::int4[], $2::int2[], $3::bytea[]) AS u(idx, version, fp)
         JOIN secrets s ON s.pepper_version = u.version AND s.fingerprint = u.fp",
    )
    .bind(&idx)
    .bind(&versions)
    .bind(&fps)
    .fetch_all(conn)
    .await?;
    let mut out = HashMap::new();
    for row in rows {
        let i: i32 = row.try_get("idx")?;
        out.insert(usize::try_from(i).unwrap_or(usize::MAX), row.try_get("id")?);
    }
    Ok(out)
}

/// A running scan, locked for the rest of the transaction (by `lock_job` for API scans,
/// by the worker for its own jobs).
#[derive(Debug)]
pub(crate) struct Job {
    pub(crate) id: Uuid,
    pub(crate) source_id: Uuid,
    pub(crate) source_type: SourceType,
    pub(crate) uri: String,
    pub(crate) environment: Option<String>,
    pub(crate) full_scan: bool,
    pub(crate) started_at: DateTime<Utc>,
}

async fn lock_job(
    conn: &mut PgConnection,
    principal: &TokenPrincipal,
    id: Uuid,
    allow_stale: bool,
) -> Result<Job, ApiError> {
    let row = sqlx::query(
        "SELECT j.id, j.status = 'running' AS running, j.started_at > now() - make_interval(hours => $3) AS fresh,
                j.started_at, j.full_scan, j.environment, s.id AS source_id, s.type AS source_type, s.uri
         FROM scan_jobs j LEFT JOIN sources s ON s.id = j.source_id
         WHERE j.id = $1 AND j.api_token_id = $2
         FOR UPDATE OF j",
    )
    .bind(id)
    .bind(principal.id)
    .bind(JOB_MAX_AGE_HOURS)
    .fetch_optional(conn)
    .await?
    // Someone else's scan looks exactly like a missing one.
    .ok_or(ApiError::NotFound)?;
    let running = row.try_get::<Option<bool>, _>("running")?.unwrap_or(false);
    let fresh = row.try_get::<Option<bool>, _>("fresh")?.unwrap_or(false);
    if !running || !(fresh || allow_stale) {
        return Err(ApiError::Conflict("scan is not running".into()));
    }
    let Some(source_id) = row.try_get::<Option<Uuid>, _>("source_id")? else {
        return Err(ApiError::Conflict("the scan's source was deleted".into()));
    };
    Ok(Job {
        id: row.try_get("id")?,
        source_id,
        source_type: row.try_get("source_type")?,
        uri: row.try_get("uri")?,
        environment: row.try_get("environment")?,
        full_scan: row.try_get("full_scan")?,
        started_at: row.try_get("started_at")?,
    })
}

pub async fn start(
    tx: &mut Transaction<'_, Postgres>,
    principal: &TokenPrincipal,
    limiter: &IngestLimiter,
    req: &ScanStart,
    audit_event: AuditEvent,
) -> Result<ScanStarted, ApiError> {
    validate_uri(&req.source.uri)?;
    let environment = validate_environment(req.environment.as_deref())?;
    if !limiter.allow_scan_start(principal.id) {
        return Err(ApiError::TooManyRequests);
    }
    let name = source_name(req.source.source_type, &req.source.uri);

    let row = sqlx::query(
        "INSERT INTO sources (name, type, uri) VALUES ($1, $2, $3)
         ON CONFLICT (type, uri) DO UPDATE SET uri = EXCLUDED.uri
         RETURNING id, enabled",
    )
    .bind(&name)
    .bind(req.source.source_type)
    .bind(&req.source.uri)
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| {
        if e.as_database_error().and_then(|d| d.constraint()) == Some("sources_name_key") {
            ApiError::Conflict("another source already uses the generated name".into())
        } else {
            e.into()
        }
    })?;
    let source_id: Uuid = row.try_get("id")?;
    if !row.try_get::<bool, _>("enabled")? {
        return Err(ApiError::Conflict("source is disabled".into()));
    }

    let trigger = if principal.kind == "ci" { "ci" } else { "agent" };
    let scan_id: Uuid = sqlx::query_scalar(
        "INSERT INTO scan_jobs (source_id, trigger, status, attempts, started_at, api_token_id, full_scan, environment)
         VALUES ($1, $2, 'running', 1, now(), $3, $4, $5) RETURNING id",
    )
    .bind(source_id)
    .bind(trigger)
    .bind(principal.id)
    .bind(req.full)
    .bind(&environment)
    .fetch_one(&mut **tx)
    .await?;

    let details = json!({
        "source_id": source_id,
        "source_type": req.source.source_type,
        "full": req.full,
    });
    audit::record(tx, &audit_event.target("scan_job", scan_id.to_string()).details(details)).await?;

    Ok(ScanStarted {
        scan_id,
        source_id,
        limits: ScanLimits {
            max_digests_per_request: MAX_DIGESTS_PER_REQUEST,
            max_findings_per_request: MAX_FINDINGS_PER_REQUEST,
            digests_per_hour: limiter.limits.digests_per_hour,
        },
    })
}

pub async fn match_digests(
    tx: &mut Transaction<'_, Postgres>,
    pepper: &Pepper,
    limiter: &IngestLimiter,
    principal: &TokenPrincipal,
    scan_id: Uuid,
    req: &MatchRequest,
    audit_event: AuditEvent,
) -> Result<MatchResponse, ApiError> {
    if req.digests.is_empty() || req.digests.len() > MAX_DIGESTS_PER_REQUEST {
        return Err(unprocessable(format!("digests must have 1-{MAX_DIGESTS_PER_REQUEST} entries")));
    }
    let job = lock_job(tx, principal, scan_id, false).await?;
    let mut seen = HashSet::with_capacity(req.digests.len());
    let unique: Vec<Digest> = req.digests.iter().copied().filter(|d| seen.insert(*d)).collect();
    if !limiter.allow_digests(principal.id, unique.len()) {
        return Err(ApiError::TooManyRequests);
    }

    let found = registered(tx, pepper, &unique).await?;
    let mut matched: Vec<String> = found.keys().filter_map(|&i| unique.get(i)).map(Digest::to_hex).collect();
    matched.sort_unstable();

    let details = json!({ "submitted": unique.len(), "matched": matched.len() });
    audit::record(tx, &audit_event.target("scan_job", job.id.to_string()).details(details)).await?;
    Ok(MatchResponse { matched })
}

pub async fn findings(
    tx: &mut Transaction<'_, Postgres>,
    pepper: &Pepper,
    limiter: &IngestLimiter,
    principal: &TokenPrincipal,
    scan_id: Uuid,
    req: &FindingsRequest,
    audit_event: AuditEvent,
) -> Result<FindingsResponse, ApiError> {
    if req.findings.is_empty() || req.findings.len() > MAX_FINDINGS_PER_REQUEST {
        return Err(unprocessable(format!("findings must have 1-{MAX_FINDINGS_PER_REQUEST} entries")));
    }
    for (i, f) in req.findings.iter().enumerate() {
        validate_finding(i, f)?;
    }
    let job = lock_job(tx, principal, scan_id, false).await?;
    // `/findings` answers "is this digest registered?" as well (accepted vs ignored).
    let unique = req.findings.iter().map(|f| f.digest).collect::<HashSet<_>>().len();
    if !limiter.allow_digests(principal.id, unique) {
        return Err(ApiError::TooManyRequests);
    }
    let out = record_findings(tx, pepper, &job, &req.findings).await?;

    let details = serde_json::to_value(&out).map_err(anyhow::Error::from)?;
    audit::record(tx, &audit_event.target("scan_job", job.id.to_string()).details(details)).await?;
    Ok(out)
}

/// Store the locations of validated findings for a job: every digest is matched again
/// (nothing is stored for unregistered ones), duplicates are merged, allow rules decide
/// `is_allowed`. Shared by `/findings` and the worker; the caller holds the job lock.
pub(crate) async fn record_findings(
    tx: &mut Transaction<'_, Postgres>,
    pepper: &Pepper,
    job: &Job,
    findings: &[FindingIn],
) -> Result<FindingsResponse, ApiError> {
    let mut digest_index: HashMap<Digest, usize> = HashMap::new();
    let mut unique = Vec::new();
    for f in findings {
        digest_index.entry(f.digest).or_insert_with(|| {
            unique.push(f.digest);
            unique.len() - 1
        });
    }
    let found = registered(tx, pepper, &unique).await?;

    let mut out = FindingsResponse::default();
    let mut accepted = Vec::new();
    for f in findings {
        let Some(&secret_id) = digest_index.get(&f.digest).and_then(|i| found.get(i)) else {
            out.ignored += 1;
            continue;
        };
        out.accepted += 1;
        accepted.push(Pending {
            secret_id,
            key: locator_key(job.source_type, &job.uri, &f.path),
            path: f.path.clone(),
            locator: locator_json(f),
            in_current_state: f.in_current_state,
        });
    }
    let mut pending = merge(accepted);
    // One lock order for every request: concurrent upserts cannot deadlock.
    pending.sort_unstable_by(|a, b| (a.secret_id, a.key).cmp(&(b.secret_id, b.key)));
    upsert_locations(tx, job, &pending, &mut out).await?;
    Ok(out)
}

/// Upsert merged locations with their allow-rule verdicts; adds to the response counters.
async fn upsert_locations(
    tx: &mut Transaction<'_, Postgres>,
    job: &Job,
    pending: &[Pending],
    out: &mut FindingsResponse,
) -> Result<(), ApiError> {
    if pending.is_empty() {
        return Ok(());
    }
    let mut secret_ids: Vec<Uuid> = pending.iter().map(|p| p.secret_id).collect::<HashSet<_>>().into_iter().collect();
    secret_ids.sort_unstable();
    // Hold the secrets against a concurrent PATCH of their allow rules (which replaces the
    // rules and re-evaluates locations) until the upsert commits: no stale verdicts, no FK
    // violation on a just-deleted rule.
    sqlx::query("SELECT 1 FROM secrets WHERE id = ANY($1) ORDER BY id FOR SHARE")
        .bind(&secret_ids)
        .execute(&mut **tx)
        .await?;
    let rules = load_rules(tx, &secret_ids).await?;
    let mut ids = Vec::with_capacity(pending.len());
    let mut keys = Vec::with_capacity(pending.len());
    let mut locators = Vec::with_capacity(pending.len());
    let mut current = Vec::with_capacity(pending.len());
    let mut allowed = Vec::with_capacity(pending.len());
    let mut rule_ids: Vec<Option<i64>> = Vec::with_capacity(pending.len());
    for p in pending {
        let subject = Subject {
            source_type: job.source_type,
            uri: &job.uri,
            path: &p.path,
            environment: job.environment.as_deref(),
        };
        let rule = rules.get(&p.secret_id).and_then(|r| first_match(r, &subject));
        ids.push(p.secret_id);
        keys.push(p.key.to_vec());
        locators.push(p.locator.clone());
        current.push(p.in_current_state);
        allowed.push(rule.is_some());
        rule_ids.push(rule);
    }
    let rows = sqlx::query(
        "INSERT INTO locations (secret_id, locator_key, locator, in_current_state, is_allowed, allow_rule_id,
                                source_id, source_type, uri, environment, last_job_id)
         SELECT u.secret_id, u.key, u.locator, u.current, u.allowed, u.rule_id, $7, $8, $9, $10, $11
         FROM UNNEST($1::uuid[], $2::bytea[], $3::jsonb[], $4::bool[], $5::bool[], $6::int8[])
              AS u(secret_id, key, locator, current, allowed, rule_id)
         ON CONFLICT (secret_id, locator_key) DO UPDATE SET
             locator = CASE
                 WHEN EXCLUDED.in_current_state OR NOT locations.in_current_state
                      OR locations.last_job_id IS DISTINCT FROM EXCLUDED.last_job_id
                 THEN EXCLUDED.locator ELSE locations.locator END,
             in_current_state = CASE
                 WHEN locations.last_job_id = EXCLUDED.last_job_id
                 THEN locations.in_current_state OR EXCLUDED.in_current_state
                 ELSE EXCLUDED.in_current_state END,
             is_allowed = EXCLUDED.is_allowed,
             allow_rule_id = EXCLUDED.allow_rule_id,
             source_id = EXCLUDED.source_id,
             source_type = EXCLUDED.source_type,
             uri = EXCLUDED.uri,
             environment = EXCLUDED.environment,
             last_seen = now(),
             last_job_id = EXCLUDED.last_job_id
         RETURNING (xmax = 0) AS inserted, is_allowed",
    )
    .bind(&ids)
    .bind(&keys)
    .bind(&locators)
    .bind(&current)
    .bind(&allowed)
    .bind(&rule_ids)
    .bind(job.source_id)
    .bind(job.source_type)
    .bind(&job.uri)
    .bind(&job.environment)
    .bind(job.id)
    .fetch_all(&mut **tx)
    .await?;
    for row in rows {
        if row.try_get::<bool, _>("inserted")? {
            out.new_locations += 1;
        } else {
            out.updated_locations += 1;
        }
        if !row.try_get::<bool, _>("is_allowed")? {
            out.violations += 1;
        }
    }
    Ok(())
}

pub async fn complete(
    tx: &mut Transaction<'_, Postgres>,
    principal: &TokenPrincipal,
    scan_id: Uuid,
    req: &ScanComplete,
    audit_event: AuditEvent,
) -> Result<ScanCompleted, ApiError> {
    validate_completion(req)?;
    // A stale scan can still be closed as failed, never reported as a success.
    let job = lock_job(tx, principal, scan_id, req.status == CompletionStatus::Failed).await?;
    let stats = serde_json::to_value(req.stats.clone().unwrap_or_default()).map_err(anyhow::Error::from)?;

    sqlx::query(
        "UPDATE scan_jobs SET status = $2::job_status, finished_at = now(), stats = $3, error = $4 WHERE id = $1",
    )
    .bind(job.id)
    .bind(req.status.as_str())
    .bind(&stats)
    .bind(&req.error)
    .execute(&mut **tx)
    .await?;
    sqlx::query("UPDATE sources SET last_scan_at = now() WHERE id = $1").bind(job.source_id).execute(&mut **tx).await?;

    let mut no_longer_present = 0;
    if req.status == CompletionStatus::Succeeded && job.full_scan {
        // Only rows this token's own earlier scans reported, and only if nothing has seen them
        // since this scan started (a concurrent scan may just have reported them).
        no_longer_present = sqlx::query(
            "UPDATE locations l SET in_current_state = false
             FROM scan_jobs pj
             WHERE l.source_id = $1 AND l.in_current_state AND l.last_job_id IS DISTINCT FROM $2
               AND l.last_seen < $3 AND pj.id = l.last_job_id AND pj.api_token_id = $4",
        )
        .bind(job.source_id)
        .bind(job.id)
        .bind(job.started_at)
        .bind(principal.id)
        .execute(&mut **tx)
        .await?
        .rows_affected();
    }

    let details = json!({ "status": req.status, "no_longer_present": no_longer_present });
    audit::record(tx, &audit_event.target("scan_job", job.id.to_string()).details(details)).await?;
    Ok(ScanCompleted { status: req.status, no_longer_present })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(path: &str) -> FindingIn {
        FindingIn {
            digest: Digest::from_bytes([7; 32]),
            path: path.into(),
            line: Some(3),
            column: Some(1),
            blob: None,
            commit: None,
            in_current_state: true,
            detector: Detector::KeyValue,
            rule: None,
            confidence: Confidence::Medium,
            key: Some("DB_PASSWORD".into()),
            encodings: vec![],
        }
    }

    #[test]
    fn credential_bypasses_are_rejected() {
        for uri in [
            "https:///u:p@h/r",
            "https:\\\\u:p@h/r",
            "https:/u:p@h/r",
            "HTTPS://u:p@h",
            "user:pass@host/repo",
            "https://gitlab/x?private_token=abc",
            "https://h/x#access_token=abc",
            "https://h/x?a=1&X-Amz-Signature=abc",
            "https://h/x?private%5Ftoken=abc",
            "https://h\\u@x/r",
            "ssh://git@h/repo",
        ] {
            assert!(has_credentials(uri), "{uri}");
            assert!(validate_uri(uri).is_err(), "{uri}");
        }
        for uri in [
            "git@github.com:org/repo.git",
            "https://h/repo?ref=main",
            "https://h/repo#readme",
            "registry.example:5000/team/app@sha256:0123",
            "redis:7@sha256:0123",
            "nginx:1.27",
            "/srv/data",
            "file:///srv/data",
        ] {
            assert!(!has_credentials(uri), "{uri}");
            assert!(validate_uri(uri).is_ok(), "{uri}");
        }
    }

    #[test]
    fn percent_decoding_of_names() {
        assert_eq!(percent_decode_ascii("private%5Ftoken"), "private_token");
        assert_eq!(percent_decode_ascii("a%zz%"), "a%zz%");
    }

    #[test]
    fn credentials_in_uris() {
        assert!(has_credentials("https://user:pass@git.example/org/repo"));
        assert!(has_credentials("https://ghp_token@github.com/org/repo"));
        assert!(!has_credentials("https://git.example/org/repo@v1"), "@ in the path is fine");
        assert!(!has_credentials("git@github.com:org/repo.git"), "scp-like ssh form has no password");
        assert!(!has_credentials("/srv/data"));
        assert!(validate_uri("https://a:b@x/y").is_err());
        assert!(validate_uri("https://x/a b").is_err());
        assert!(validate_uri("").is_err());
        assert!(validate_uri(&"a".repeat(2049)).is_err());
        assert!(validate_uri("https://git.example/org/repo").is_ok());
    }

    #[test]
    fn environments() {
        assert_eq!(validate_environment(Some("prod-eu.1")).ok().flatten().as_deref(), Some("prod-eu.1"));
        assert!(validate_environment(Some("")).is_err());
        assert!(validate_environment(Some("pr od")).is_err());
        assert!(validate_environment(Some(&"e".repeat(65))).is_err());
        assert!(matches!(validate_environment(None), Ok(None)));
    }

    #[test]
    fn source_names_fit_the_column() {
        assert_eq!(source_name(SourceType::GitRepo, "https://x/y"), "git_repo:https://x/y");
        let long = source_name(SourceType::Filesystem, &format!("/{}", "d".repeat(500)));
        assert_eq!(long.chars().count(), 200);
        assert!(long.starts_with("filesystem:/ddd"));
        assert_ne!(long, source_name(SourceType::Filesystem, &format!("/{}e", "d".repeat(500))));
    }

    #[test]
    fn locator_keys_are_unambiguous() {
        let k = locator_key(SourceType::GitRepo, "u", "p");
        assert_eq!(k, locator_key(SourceType::GitRepo, "u", "p"));
        assert_ne!(k, locator_key(SourceType::Filesystem, "u", "p"));
        // Length prefixes: moving a byte between fields changes the key.
        assert_ne!(locator_key(SourceType::GitRepo, "ab", "c"), locator_key(SourceType::GitRepo, "a", "bc"));
    }

    #[test]
    fn finding_validation() {
        assert!(validate_finding(0, &finding("config/prod.env")).is_ok());
        let bad = |f: FindingIn| validate_finding(4, &f).err().map(|e| e.to_string()).unwrap_or_default();
        assert!(bad(finding("")).contains("findings[4].path"));
        assert!(bad(finding("a\nb")).contains("path"));
        assert!(bad(FindingIn { line: Some(0), ..finding("a") }).contains("line"));
        assert!(bad(FindingIn { blob: Some("ABC".into()), ..finding("a") }).contains("blob"));
        assert!(bad(FindingIn { commit: Some("a".repeat(41)), ..finding("a") }).contains("commit"));
        assert!(validate_finding(0, &FindingIn { blob: Some("a".repeat(64)), ..finding("a") }).is_ok());
        assert!(bad(FindingIn { rule: Some("GitHub".into()), ..finding("a") }).contains("rule"));
        assert!(bad(FindingIn { key: Some("a b".into()), ..finding("a") }).contains("key"));
        assert!(bad(FindingIn { encodings: vec![Encoding::Base64; 9], ..finding("a") }).contains("encodings"));
    }

    #[test]
    fn completion_validation() {
        let ok = ScanComplete { status: CompletionStatus::Succeeded, stats: None, error: None };
        assert!(validate_completion(&ok).is_ok());
        let stats = |k: &str| ScanComplete {
            stats: Some(BTreeMap::from([(k.to_owned(), 1)])),
            ..ScanComplete { status: CompletionStatus::Failed, stats: None, error: None }
        };
        assert!(validate_completion(&stats("documents")).is_ok());
        assert!(validate_completion(&stats("Docs")).is_err());
        let many = ScanComplete {
            status: CompletionStatus::Failed,
            stats: Some((0..33).map(|i| (format!("k{i}"), 1)).collect()),
            error: None,
        };
        assert!(validate_completion(&many).is_err());
        let err = ScanComplete { status: CompletionStatus::Failed, stats: None, error: Some("x\ny".into()) };
        assert!(validate_completion(&err).is_err());
    }

    #[test]
    fn locator_has_no_digest_and_omits_absent_fields() {
        let v = locator_json(&finding("a/b.env"));
        assert_eq!(
            v,
            json!({"path": "a/b.env", "line": 3, "column": 1, "detector": "key_value",
                             "confidence": "medium", "key": "DB_PASSWORD"})
        );
    }

    #[test]
    fn merging_prefers_current_state() {
        let id = Uuid::nil();
        let p = |path: &str, current: bool, line: u32| Pending {
            secret_id: id,
            key: locator_key(SourceType::GitRepo, "u", path),
            path: path.into(),
            locator: json!({ "line": line }),
            in_current_state: current,
        };
        let merged = merge([p("a", false, 1), p("b", false, 2), p("a", true, 3), p("a", false, 4)]);
        assert_eq!(merged.len(), 2);
        assert_eq!((merged[0].in_current_state, &merged[0].locator), (true, &json!({ "line": 3 })));
        assert_eq!(merged[1].locator, json!({ "line": 2 }));
        let other = Pending { secret_id: Uuid::max(), ..p("a", false, 5) };
        assert_eq!(merge([p("a", false, 1), other]).len(), 2, "different secrets stay apart");
    }

    #[test]
    fn match_limiter() {
        let l = IngestLimiter::new(IngestLimits {
            digests_per_hour: 10,
            match_requests_per_minute: 2,
            scan_starts_per_minute: 1,
        });
        let t = Uuid::nil();
        assert!(l.allow_digests(t, 6));
        assert!(!l.allow_digests(t, 6), "digest budget");
        assert!(!l.allow_digests(t, 1), "request budget (3rd request)");
        assert!(l.allow_digests(Uuid::max(), 10), "per token");
        assert!(l.allow_scan_start(t));
        assert!(!l.allow_scan_start(t), "scan starts");
        assert!(l.allow_scan_start(Uuid::max()));
    }
}
