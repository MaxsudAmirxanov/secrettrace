//! Canary tokens: bait whose every use is a leak.
//!
//! - `url`: `<base>/<word>/<id>` — fires when anyone opens the link.
//! - `api_key`: `ak_<40 chars>` next to an endpoint on the canary listener (handed out as
//!   an `.env` snippet) — fires when someone tries the key. It is also registered as a
//!   secret, so a scan that finds it anywhere reports a leak through the usual pipeline.
//!
//! Hits arrive through the edge's canary listener (the only part meant for the internet)
//! as `ANY /_canary` with the original request target in a header. The server looks for
//! well-formed tokens in the path, query, `Authorization` and API-key headers, and finds
//! canaries by `HMAC-SHA256(ST_CANARY_KEY, domain || token)`: neither token values nor
//! plain hashes are stored, so a database dump does not reveal which keys are bait.
//!
//! Every request gets the same answer, hit or not. A hit increments the canary's
//! counter, stores the request metadata (bounded per canary), raises (or bumps) the
//! canary's open alert and logs a warning.

use std::net::IpAddr;

use axum::http::{HeaderMap, Method, Uri};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use hmac::{Hmac, Mac};
use rand::RngCore as _;
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use sha2::Sha256;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;
use zeroize::Zeroizing;

const LOOKUP_DOMAIN: &[u8] = b"secrettrace/canary/v1\0";
/// URL token: 26 chars of lowercase base32 (130 bits; DNS-label-safe for a later DNS canary).
pub const URL_TOKEN_LEN: usize = 26;
pub const API_KEY_PREFIX: &str = "ak_";
/// Base32 chars after [`API_KEY_PREFIX`] (200 bits).
pub const API_KEY_BODY_LEN: usize = 40;
/// Candidates examined per request.
const MAX_CANDIDATES: usize = 16;
/// Hit rows kept per canary per minute and in total; the counter keeps counting.
const HITS_PER_MINUTE: i64 = 10;
const MAX_STORED_HITS: i64 = 10_000;
const PATH_WORDS: &[&str] = &["static", "assets", "images", "download", "files", "media", "s", "cdn"];

/// Header the edge's canary listener sets (`1`); every other listener clears it.
pub const CANARY_HEADER: &str = "x-secrettrace-canary";
/// The request target as the client sent it to the canary listener.
pub const ORIGINAL_URI_HEADER: &str = "x-secrettrace-original-uri";

#[derive(Debug, thiserror::Error)]
#[error("ST_CANARY_KEY must be 32 bytes, base64-encoded")]
pub struct BadCanaryKey;

/// The canary configuration: lookup key and the public base URL of the canary listener.
pub struct CanarySettings {
    key: Zeroizing<[u8; 32]>,
    /// e.g. `https://assets.example.com` (no trailing slash).
    pub base_url: String,
}

impl std::fmt::Debug for CanarySettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CanarySettings").field("base_url", &self.base_url).finish_non_exhaustive()
    }
}

impl CanarySettings {
    pub fn new(key_b64: &SecretString, base_url: &str) -> Result<Self, BadCanaryKey> {
        let bytes = Zeroizing::new(B64.decode(key_b64.expose_secret().trim()).map_err(|_| BadCanaryKey)?);
        let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| BadCanaryKey)?;
        Ok(Self { key: Zeroizing::new(key), base_url: base_url.trim_end_matches('/').to_owned() })
    }

    #[must_use]
    pub fn lookup(&self, token: &str) -> [u8; 32] {
        // HMAC accepts keys of any length; the error branch is unreachable.
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(self.key.as_ref()) else {
            unreachable!("HMAC-SHA256 accepts any key length")
        };
        mac.update(LOOKUP_DOMAIN);
        mac.update(token.as_bytes());
        mac.finalize().into_bytes().into()
    }

    /// The `api_key` canary's fake service endpoint.
    #[must_use]
    pub fn endpoint(&self) -> String {
        format!("{}/v1", self.base_url)
    }
}

fn base32(bytes: &[u8], len: usize) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(len);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 && out.len() < len {
            bits -= 5;
            out.push(char::from(ALPHABET[((acc >> bits) & 31) as usize]));
        }
    }
    out
}

/// A fresh URL token.
#[must_use]
pub fn new_url_token() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; 17]);
    rand::rngs::OsRng.fill_bytes(bytes.as_mut());
    Zeroizing::new(base32(bytes.as_ref(), URL_TOKEN_LEN))
}

/// A fresh fake API key.
#[must_use]
pub fn new_api_key() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; 25]);
    rand::rngs::OsRng.fill_bytes(bytes.as_mut());
    Zeroizing::new(format!("{API_KEY_PREFIX}{}", base32(bytes.as_ref(), API_KEY_BODY_LEN)))
}

/// The link of a URL canary: an innocuous-looking path ending in the token.
#[must_use]
pub fn url_for(settings: &CanarySettings, token: &str) -> String {
    let pick = usize::from(token.as_bytes()[0]) % PATH_WORDS.len();
    format!("{}/{}/{token}", settings.base_url, PATH_WORDS[pick])
}

fn is_b32(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}

fn is_url_token(s: &str) -> bool {
    s.len() == URL_TOKEN_LEN && is_b32(s)
}

fn is_api_key(s: &str) -> bool {
    s.strip_prefix(API_KEY_PREFIX).is_some_and(|b| b.len() == API_KEY_BODY_LEN && is_b32(b))
}

fn is_token(s: &str) -> bool {
    is_url_token(s) || is_api_key(s)
}

/// Where a token was found in the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Path,
    Query,
    Bearer,
    Basic,
    Header,
}

impl Via {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Query => "query",
            Self::Bearer => "bearer",
            Self::Basic => "basic",
            Self::Header => "header",
        }
    }
}

/// Well-formed tokens in a request, first occurrence of each, at most [`MAX_CANDIDATES`].
#[must_use]
pub fn candidates(target: &str, headers: &HeaderMap) -> Vec<(String, Via)> {
    let mut out: Vec<(String, Via)> = Vec::new();
    let mut push = |s: &str, via: Via| {
        let s = s.trim();
        if out.len() < MAX_CANDIDATES && is_token(s) && !out.iter().any(|(t, _)| t == s) {
            out.push((s.to_owned(), via));
        }
    };
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    for segment in path.split('/') {
        // `/images/<token>.png`: the token is the stem.
        push(segment.split('.').next().unwrap_or_default(), Via::Path);
    }
    for pair in query.split('&') {
        let value = pair.split_once('=').map_or(pair, |(_, v)| v);
        push(value, Via::Query);
    }
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    if let Some(auth) = header("authorization") {
        let (scheme, rest) = auth.trim().split_once(' ').unwrap_or((auth, ""));
        if scheme.eq_ignore_ascii_case("bearer") || scheme.eq_ignore_ascii_case("token") {
            push(rest, Via::Bearer);
        } else if scheme.eq_ignore_ascii_case("basic")
            && let Ok(decoded) = B64.decode(rest.trim())
        {
            let decoded = Zeroizing::new(String::from_utf8_lossy(&decoded).into_owned());
            let (user, pass) = decoded.split_once(':').unwrap_or((decoded.as_str(), ""));
            push(user, Via::Basic);
            push(pass, Via::Basic);
        }
    }
    for name in ["x-api-key", "api-key", "x-auth-token", "apikey"] {
        if let Some(v) = header(name) {
            push(v, Via::Header);
        }
    }
    out
}

/// What the hit row keeps of the request: the target with tokens masked, cut to 512.
fn masked_target(target: &str, tokens: &[(String, Via)]) -> String {
    let mut t = target.to_owned();
    for (token, _) in tokens {
        t = t.replace(token.as_str(), "{token}");
    }
    let mut out: String = t.chars().filter(|c| !c.is_control()).take(512).collect();
    if out.is_empty() {
        out.push('/');
    }
    out
}

fn clip(s: Option<&str>, max: usize) -> Option<String> {
    s.map(|v| v.chars().filter(|c| !c.is_control()).take(max).collect::<String>()).filter(|v| !v.is_empty())
}

/// One request reaching the canary listener.
#[derive(Debug)]
pub struct Request<'a> {
    pub method: &'a Method,
    /// Original request target (path and query).
    pub target: &'a str,
    pub headers: &'a HeaderMap,
    pub ip: Option<IpAddr>,
}

/// Record a hit for every enabled canary the request carries. Returns how many fired.
pub async fn record(db: &PgPool, settings: &CanarySettings, req: &Request<'_>) -> Result<usize, sqlx::Error> {
    let found = candidates(req.target, req.headers);
    if found.is_empty() {
        return Ok(0);
    }
    let lookups: Vec<Vec<u8>> = found.iter().map(|(t, _)| settings.lookup(t).to_vec()).collect();
    let mut tx = db.begin().await?;
    let rows: Vec<(Uuid, String, String, Vec<u8>)> = sqlx::query_as(
        "SELECT id, name, kind::text, lookup FROM canaries WHERE lookup = ANY($1) AND enabled ORDER BY id FOR UPDATE",
    )
    .bind(&lookups)
    .fetch_all(&mut *tx)
    .await?;
    let target = masked_target(req.target, &found);
    let host = clip(req.headers.get("x-forwarded-host").and_then(|v| v.to_str().ok()), 255);
    let user_agent = clip(req.headers.get("user-agent").and_then(|v| v.to_str().ok()), 256);
    let method: String = req.method.as_str().chars().take(16).collect();
    for (id, name, kind, lookup) in &rows {
        let via = found.iter().zip(&lookups).find(|(_, l)| l == &lookup).map_or(Via::Path, |((_, v), _)| *v);
        hit(&mut tx, *id, via, req.ip, &method, host.as_deref(), &target, user_agent.as_deref()).await?;
        let context = json!({
            "canary_id": id, "name": name, "kind": kind, "ip": req.ip, "method": method,
            "host": host, "path": target, "user_agent": user_agent, "via": via.as_str(),
        });
        sqlx::query(
            "INSERT INTO alerts (rule, severity, dedup_key, context)
             VALUES ('canary.triggered', 'critical', $1, $2)
             ON CONFLICT (dedup_key) WHERE status IN ('open', 'acknowledged')
             DO UPDATE SET occurrences = alerts.occurrences + 1, context = EXCLUDED.context, updated_at = now()",
        )
        .bind(format!("canary:{id}"))
        .bind(&context)
        .execute(&mut *tx)
        .await?;
        tracing::warn!(
            canary_id = %id, canary = %name, kind = %kind, ip = ?req.ip, via = via.as_str(),
            "canary token triggered"
        );
    }
    tx.commit().await?;
    Ok(rows.len())
}

#[allow(clippy::too_many_arguments)]
async fn hit(
    tx: &mut Transaction<'_, Postgres>,
    canary: Uuid,
    via: Via,
    ip: Option<IpAddr>,
    method: &str,
    host: Option<&str>,
    target: &str,
    user_agent: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE canaries SET hit_count = hit_count + 1, last_hit_at = now() WHERE id = $1")
        .bind(canary)
        .execute(&mut **tx)
        .await?;
    // Bounded storage: a flood of hits only moves the counter.
    let (recent, total): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE at > now() - interval '1 minute'), count(*) FROM canary_hits WHERE canary_id = $1",
    )
    .bind(canary)
    .fetch_one(&mut **tx)
    .await?;
    if recent >= HITS_PER_MINUTE || total >= MAX_STORED_HITS {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO canary_hits (canary_id, ip, method, host, path, user_agent, via)
         VALUES ($1, $2::inet, $3, $4, $5, $6, $7)",
    )
    .bind(canary)
    .bind(ip.map(|i| i.to_string()))
    .bind(method)
    .bind(host)
    .bind(target)
    .bind(user_agent)
    .bind(via.as_str())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// The original request target sent by the edge, or the URI as received.
#[must_use]
pub fn original_target(headers: &HeaderMap, uri: &Uri) -> String {
    headers
        .get(ORIGINAL_URI_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.starts_with('/'))
        .map_or_else(|| uri.path_and_query().map_or("/", |p| p.as_str()).to_owned(), str::to_owned)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use axum::http::HeaderValue;

    use super::*;

    fn settings() -> CanarySettings {
        CanarySettings::new(&SecretString::from(B64.encode([5u8; 32])), "https://assets.example.com/").unwrap()
    }

    #[test]
    fn tokens_have_the_documented_shape() {
        let t = new_url_token();
        assert!(is_url_token(&t), "{}", t.as_str());
        let k = new_api_key();
        assert!(is_api_key(&k), "{}", k.as_str());
        assert_ne!(*new_url_token(), *t);
        let s = settings();
        let url = url_for(&s, &t);
        assert!(url.starts_with("https://assets.example.com/") && url.ends_with(t.as_str()), "{url}");
        assert_eq!(s.endpoint(), "https://assets.example.com/v1");
        assert!(CanarySettings::new(&SecretString::from("c2hvcnQ="), "x").is_err());
    }

    #[test]
    fn lookup_is_keyed() {
        let a = settings();
        let b = CanarySettings::new(&SecretString::from(B64.encode([6u8; 32])), "x").unwrap();
        assert_ne!(a.lookup("abc"), b.lookup("abc"));
        assert_eq!(a.lookup("abc"), settings().lookup("abc"));
    }

    #[test]
    fn candidates_from_every_place() {
        let url = "abcdefghijklmnopqrstuvwxyz";
        let key = format!("ak_{}", "a".repeat(40));
        let mut h = HeaderMap::new();
        h.insert("authorization", HeaderValue::from_str(&format!("Bearer {key}")).unwrap());
        let found = candidates(&format!("/images/{url}.png?x=1&k={url}"), &h);
        assert_eq!(found, [(url.to_owned(), Via::Path), (key.clone(), Via::Bearer)]);

        let mut h = HeaderMap::new();
        let basic = B64.encode(format!("user:{key}"));
        h.insert("authorization", HeaderValue::from_str(&format!("Basic {basic}")).unwrap());
        assert_eq!(candidates("/", &h), [(key.clone(), Via::Basic)]);
        let mut h = HeaderMap::new();
        h.insert("x-api-key", HeaderValue::from_str(&key).unwrap());
        assert_eq!(candidates("/v1/charges?q=1", &h), [(key.clone(), Via::Header)]);
        assert_eq!(candidates(&format!("/v1?api_key={key}"), &HeaderMap::new()), [(key, Via::Query)]);
        // Wrong shapes are not even hashed.
        assert!(candidates("/abcdefghijklmnopqrstuvwxy1/ak_short", &HeaderMap::new()).is_empty());
        let many: String = (0..40).map(|i| ["/", &base32(&[i; 17], URL_TOKEN_LEN)].concat()).collect();
        assert_eq!(candidates(&many, &HeaderMap::new()).len(), MAX_CANDIDATES);
    }

    #[test]
    fn stored_target_hides_the_token() {
        let t = "abcdefghijklmnopqrstuvwxyz";
        let found = vec![(t.to_owned(), Via::Path)];
        assert_eq!(masked_target(&format!("/s/{t}?a=\u{1b}b"), &found), "/s/{token}?a=b");
        assert_eq!(masked_target(&"x".repeat(600), &[]).len(), 512);
    }
}
