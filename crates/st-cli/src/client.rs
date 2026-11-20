//! HTTP client for the SecretTrace API.
//!
//! - Plain `http://` is accepted only for loopback hosts (or with `--allow-http`): the
//!   requests carry tokens, passwords and digests.
//! - Redirects are never followed, so a bearer token or cookie is never replayed elsewhere.
//! - Server error text (RFC 7807 `detail`) is shown with control characters removed and
//!   cut to a fixed length; response bodies are read with a size limit.
//! - Requests that may not have reached the server (connection failures, 502/503) are
//!   retried with backoff, everything else fails at once.

use std::fmt;
use std::io::Read as _;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, bail};
use clap::Args;
use serde::Serialize;
use serde::de::DeserializeOwned;
use ureq::http::{Response, StatusCode, Uri};
use ureq::tls::{Certificate, ClientCert, PrivateKey, RootCerts, TlsConfig};
use ureq::{Agent, Body};
use zeroize::Zeroizing;

const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_DETAIL_CHARS: usize = 300;
const ATTEMPTS: u32 = 4;

/// Connection options shared by every command that talks to the server.
#[derive(Args, Clone)]
pub struct ServerArgs {
    /// Server base URL, e.g. `https://secrettrace.example.com`. Deliberately not read from
    /// the environment: sending data to a server is always explicit on the command line.
    #[arg(long, value_name = "URL")]
    pub server: Option<String>,
    /// PEM file with the CA certificate(s) to trust instead of the built-in web roots.
    #[arg(long, env = "SECRETTRACE_CA_CERT", value_name = "FILE")]
    pub ca_cert: Option<PathBuf>,
    /// PEM client certificate (chain) for the mTLS ingest endpoint (`https://host:8443`).
    #[arg(long, env = "SECRETTRACE_CLIENT_CERT", value_name = "FILE", requires = "client_key")]
    pub client_cert: Option<PathBuf>,
    /// PEM private key of --client-cert.
    #[arg(long, env = "SECRETTRACE_CLIENT_KEY", value_name = "FILE", requires = "client_cert")]
    pub client_key: Option<PathBuf>,
    /// Allow plain `http://` to a non-loopback host (tokens and digests travel unencrypted).
    #[arg(long)]
    pub allow_http: bool,
    /// Per-request timeout in seconds.
    #[arg(long, value_name = "SECS", default_value_t = 120)]
    pub timeout: u64,
}

/// A failed API call. `status` is set when the server answered.
#[derive(Debug)]
pub struct ApiError {
    pub status: Option<StatusCode>,
    pub message: String,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.status {
            Some(s) => write!(f, "server returned {}: {}", s.as_u16(), self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for ApiError {}

#[derive(Debug)]
pub struct Client {
    agent: Agent,
    base: String,
}

/// How a request authenticates.
#[derive(Clone, Copy)]
pub enum Auth<'a> {
    None,
    Bearer(&'a str),
    /// Session cookie (`name=value`) and its CSRF token.
    Session {
        cookie: &'a str,
        csrf: &'a str,
    },
}

/// A decoded response plus the headers callers need.
#[derive(Debug)]
pub struct Reply<T> {
    pub body: T,
    pub set_cookie: Option<String>,
}

impl Client {
    pub fn new(args: &ServerArgs) -> anyhow::Result<Self> {
        let raw = args.server.as_deref().context("no server given: pass --server URL")?;
        let base = base_url(raw, args.allow_http)?;
        let roots = match &args.ca_cert {
            Some(path) => RootCerts::Specific(Arc::new(read_certs(path)?)),
            None => RootCerts::WebPki,
        };
        let client_cert = match (&args.client_cert, &args.client_key) {
            (Some(cert), Some(key)) => {
                if !base.starts_with("https://") {
                    bail!("--client-cert needs an https:// server");
                }
                let chain = read_certs(cert)?;
                let key_pem =
                    Zeroizing::new(std::fs::read(key).with_context(|| format!("cannot read {}", key.display()))?);
                let key =
                    PrivateKey::from_pem(&key_pem).with_context(|| format!("{}: no PEM private key", key.display()))?;
                Some(ClientCert::new_with_certs(&chain, key))
            }
            _ => None,
        };
        let agent = Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_global(Some(Duration::from_secs(args.timeout.max(1))))
            .user_agent(concat!("secrettrace/", env!("CARGO_PKG_VERSION")))
            .tls_config(TlsConfig::builder().root_certs(roots).client_cert(client_cert).build())
            .build()
            .new_agent();
        Ok(Self { agent, base })
    }

    /// The base URL requests go to (for messages).
    pub fn base(&self) -> &str {
        &self.base
    }

    /// `POST {base}/api/v1{path}` with a JSON body; a 2xx JSON response is decoded.
    pub fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        auth: Auth<'_>,
        body: &impl Serialize,
    ) -> Result<Reply<T>, ApiError> {
        let mut response = self.send(path, auth, Some(body))?;
        let set_cookie = response
            .headers()
            .get(ureq::http::header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .map(str::to_owned);
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            .read_json::<T>()
            .map_err(|e| ApiError { status: None, message: format!("unexpected response from the server: {e}") })?;
        Ok(Reply { body, set_cookie })
    }

    /// `POST` without a body whose response body is ignored (`204`, logout).
    pub fn post_empty(&self, path: &str, auth: Auth<'_>) -> Result<(), ApiError> {
        self.send::<()>(path, auth, None).map(drop)
    }

    fn send<B: Serialize>(&self, path: &str, auth: Auth<'_>, body: Option<&B>) -> Result<Response<Body>, ApiError> {
        let url = format!("{}/api/v1{path}", self.base);
        let json = body
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|e| ApiError { status: None, message: format!("cannot encode request: {e}") })?
            .map(Zeroizing::new);
        let mut attempt = 0;
        loop {
            attempt += 1;
            let mut req = self.agent.post(&url).header("accept", "application/json");
            match auth {
                Auth::None => {}
                Auth::Bearer(token) => req = req.header("authorization", format!("Bearer {token}")),
                Auth::Session { cookie, csrf } => req = req.header("cookie", cookie).header("x-csrf-token", csrf),
            }
            let result = match &json {
                Some(bytes) => req.header("content-type", "application/json").send(&bytes[..]),
                None => req.send_empty(),
            };
            let retry = match result {
                Ok(response) if response.status().is_success() => return Ok(response),
                Ok(response)
                    if matches!(response.status(), StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE) =>
                {
                    problem(response)
                }
                Ok(response) => return Err(problem(response)),
                Err(e) if retryable(&e) => transport(&self.base, &e),
                Err(e) => return Err(transport(&self.base, &e)),
            };
            if attempt >= ATTEMPTS {
                return Err(retry);
            }
            let wait = Duration::from_secs(1 << (attempt - 1));
            eprintln!("secrettrace: {retry}; retrying in {}s", wait.as_secs());
            std::thread::sleep(wait);
        }
    }
}

/// Every certificate in a PEM file.
fn read_certs(path: &std::path::Path) -> anyhow::Result<Vec<Certificate<'static>>> {
    let pem = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let certs: Vec<Certificate<'static>> = ureq::tls::parse_pem(&pem)
        .filter_map(|item| match item {
            Ok(ureq::tls::PemItem::Certificate(c)) => Some(Ok(c)),
            Ok(_) => None,
            Err(e) => Some(Err(e)),
        })
        .collect::<Result<_, _>>()
        .with_context(|| format!("{}: invalid PEM", path.display()))?;
    if certs.is_empty() {
        bail!("{}: no certificates found", path.display());
    }
    Ok(certs)
}

/// Failures where the request most likely never reached the application.
fn retryable(e: &ureq::Error) -> bool {
    match e {
        ureq::Error::ConnectionFailed | ureq::Error::HostNotFound => true,
        ureq::Error::Io(io) => matches!(
            io.kind(),
            std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::NotConnected
        ),
        ureq::Error::Timeout(t) => matches!(t, ureq::Timeout::Resolve | ureq::Timeout::Connect),
        _ => false,
    }
}

fn transport(base: &str, e: &ureq::Error) -> ApiError {
    ApiError { status: None, message: format!("cannot reach {base}: {e}") }
}

/// The RFC 7807 `detail` (or `title`) of an error response, made safe to print.
fn problem(mut response: Response<Body>) -> ApiError {
    let status = response.status();
    let mut text = String::new();
    // Error bodies are small; anything longer is cut.
    let _ = response.body_mut().as_reader().take(64 * 1024).read_to_string(&mut text);
    let parsed: Option<serde_json::Value> = serde_json::from_str(&text).ok();
    let field = |name: &str| parsed.as_ref().and_then(|v| v.get(name)).and_then(|v| v.as_str()).map(str::to_owned);
    let message = field("detail")
        .or_else(|| field("title"))
        .unwrap_or_else(|| status.canonical_reason().unwrap_or("error").to_owned());
    ApiError { status: Some(status), message: printable(&message) }
}

/// Server text without control characters, at most [`MAX_DETAIL_CHARS`].
fn printable(s: &str) -> String {
    let mut out: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).take(MAX_DETAIL_CHARS).collect();
    if s.chars().count() > MAX_DETAIL_CHARS {
        out.push('…');
    }
    out
}

/// Validate a server URL: http(s), a host, no userinfo/query/fragment; `http` only for
/// loopback unless allowed. Returns it without a trailing slash.
fn base_url(raw: &str, allow_http: bool) -> anyhow::Result<String> {
    let raw = raw.trim().trim_end_matches('/');
    if raw.contains(['?', '#']) {
        bail!("server URL must not contain a query or fragment");
    }
    let uri: Uri = raw.parse().with_context(|| format!("invalid server URL {raw:?}"))?;
    let authority = uri.authority().context("server URL needs a scheme and host, e.g. https://host")?;
    if authority.as_str().contains('@') {
        bail!("server URL must not contain credentials");
    }
    match uri.scheme_str() {
        Some("https") => {}
        Some("http") if allow_http || is_loopback(authority.host()) => {}
        Some("http") => bail!("refusing plain http to {}: use https (or --allow-http)", authority.host()),
        _ => bail!("server URL must start with https:// or http://"),
    }
    Ok(raw.to_owned())
}

fn is_loopback(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost") || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Read an API token from `SECRETTRACE_TOKEN` or a file (never from argv).
pub fn read_token(file: Option<&std::path::Path>) -> anyhow::Result<Zeroizing<String>> {
    let raw = match file {
        Some(path) => {
            let mut buf = Zeroizing::new(String::new());
            std::fs::File::open(path)
                .and_then(|f| f.take(4096).read_to_string(&mut buf))
                .with_context(|| format!("cannot read token file {}", path.display()))?;
            buf
        }
        None => Zeroizing::new(
            std::env::var("SECRETTRACE_TOKEN")
                .ok()
                .filter(|t| !t.is_empty())
                .context("no API token: set SECRETTRACE_TOKEN or pass --token-file")?,
        ),
    };
    let token = Zeroizing::new(raw.trim().to_owned());
    // `stk_` + 8 hex id + `_` + 43 base64url chars, as issued by the server.
    let well_formed = token.len() == 56
        && token.starts_with("stk_")
        && token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if !well_formed {
        bail!("the API token is malformed (expected stk_<id>_<secret>)");
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn server_urls() {
        assert_eq!(base_url("https://st.example.com/", false).unwrap(), "https://st.example.com");
        assert_eq!(base_url("https://st.example.com/prefix", false).unwrap(), "https://st.example.com/prefix");
        assert_eq!(base_url("http://127.0.0.1:8080", false).unwrap(), "http://127.0.0.1:8080");
        assert_eq!(base_url("http://localhost:8080", false).unwrap(), "http://localhost:8080");
        assert_eq!(base_url("http://[::1]:8080", false).unwrap(), "http://[::1]:8080");
        assert!(base_url("http://st.example.com", false).is_err());
        assert!(base_url("http://st.example.com", true).is_ok());
        assert!(base_url("https://user:pw@st.example.com", false).is_err());
        assert!(base_url("https://st.example.com/?x=1", false).is_err());
        assert!(base_url("ftp://st.example.com", false).is_err());
        assert!(base_url("st.example.com", false).is_err());
        // 127.0.0.1.example.com is not loopback.
        assert!(base_url("http://127.0.0.1.example.com", false).is_err());
    }

    #[test]
    fn server_text_is_sanitized() {
        assert_eq!(printable("a\u{1b}[31mb\nc"), "a [31mb c");
        let long = "x".repeat(MAX_DETAIL_CHARS + 10);
        assert_eq!(printable(&long).chars().count(), MAX_DETAIL_CHARS + 1);
    }
}
