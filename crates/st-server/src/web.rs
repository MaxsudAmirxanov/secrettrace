//! The web UI: a built single-page application served from memory.
//!
//! `ST_WEB_DIR` points at the build output (`web/dist`). Every file is read once at
//! startup, so requests never touch the filesystem (no traversal, no symlink games) and a
//! broken build fails the start instead of the first page load.
//!
//! Routing: a request for a known file gets that file; any other `GET` outside `/api/`
//! and the probes gets `index.html` (client-side routes such as `/secrets/…`).
//!
//! Headers: a strict Content Security Policy (scripts and styles from this origin only,
//! no inline code, no framing), no referrer, and long caching for content-hashed
//! `/assets/*` files only.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use axum::body::{Body, Bytes};
use axum::http::{HeaderValue, Method, StatusCode, Uri, header};
use axum::response::Response;

/// Upper bounds for what is loaded into memory.
const MAX_FILES: usize = 2_000;
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DEPTH: usize = 8;

/// CSP of UI pages. `img-src data:` is for the TOTP enrollment QR code, which is drawn
/// locally and never fetched from anywhere.
pub const UI_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
     font-src 'self'; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; \
     frame-ancestors 'none'";
/// CSP of API responses (JSON is never rendered as a document).
pub const API_CSP: &str = "default-src 'none'; frame-ancestors 'none'";

#[derive(Debug, thiserror::Error)]
pub enum WebError {
    #[error("cannot read web directory {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("web directory has no index.html")]
    NoIndex,
    #[error("web directory is too large (more than {MAX_FILES} files or {MAX_TOTAL_BYTES} bytes)")]
    TooLarge,
}

#[derive(Debug, Clone)]
struct Asset {
    body: Bytes,
    content_type: &'static str,
    immutable: bool,
}

/// Files of the built UI, keyed by URL path (`/index.html`, `/assets/app-1a2b.js`).
#[derive(Debug, Clone)]
pub struct WebAssets {
    files: HashMap<String, Asset>,
}

impl WebAssets {
    /// Load every regular file under `dir`. Symlinks and hidden files are skipped.
    pub fn load(dir: &Path) -> Result<Self, WebError> {
        let mut files = HashMap::new();
        let mut total = 0_u64;
        walk(dir, dir, 0, &mut files, &mut total)?;
        if !files.contains_key("/index.html") {
            return Err(WebError::NoIndex);
        }
        Ok(Self { files })
    }

    /// Build from in-memory files (tests).
    #[must_use]
    pub fn from_files<'a>(entries: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> Self {
        let files = entries
            .into_iter()
            .map(|(path, body)| {
                let path = format!("/{}", path.trim_start_matches('/'));
                let asset = asset_for(&path, Bytes::copy_from_slice(body));
                (path, asset)
            })
            .collect();
        Self { files }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Response for a request the API router did not match, or `None` if the UI does not
    /// own this path (the caller answers 404).
    #[must_use]
    pub fn respond(&self, method: &Method, uri: &Uri) -> Option<Response> {
        if method != Method::GET && method != Method::HEAD {
            return None;
        }
        let path = uri.path();
        if path == "/api" || path.starts_with("/api/") || path == "/healthz" || path == "/readyz" {
            return None;
        }
        let (asset, is_file) = match self.files.get(path) {
            Some(a) => (a, true),
            // A missing file under /assets/ is a stale or broken link, not a page.
            None if path.starts_with("/assets/") => return None,
            None => (self.files.get("/index.html")?, false),
        };
        let mut resp = if method == Method::HEAD {
            Response::new(Body::empty())
        } else {
            Response::new(Body::from(asset.body.clone()))
        };
        *resp.status_mut() = StatusCode::OK;
        let h = resp.headers_mut();
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static(asset.content_type));
        let cache = if is_file && asset.immutable { "public, max-age=31536000, immutable" } else { "no-cache" };
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
        h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(UI_CSP));
        Some(resp)
    }
}

fn walk(
    root: &Path,
    dir: &Path,
    depth: usize,
    files: &mut HashMap<String, Asset>,
    total: &mut u64,
) -> Result<(), WebError> {
    if depth > MAX_DEPTH {
        return Ok(());
    }
    let io = |source| WebError::Io { path: dir.to_path_buf(), source };
    let mut entries: Vec<_> = std::fs::read_dir(dir).map_err(io)?.collect::<Result<_, _>>().map_err(io)?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        // symlink_metadata: a symlink is neither followed nor served.
        let meta = std::fs::symlink_metadata(&path).map_err(|source| WebError::Io { path: path.clone(), source })?;
        if meta.is_dir() {
            walk(root, &path, depth + 1, files, total)?;
            continue;
        }
        if !meta.is_file() {
            continue;
        }
        *total += meta.len();
        if files.len() >= MAX_FILES || *total > MAX_TOTAL_BYTES {
            return Err(WebError::TooLarge);
        }
        let Some(url) = url_path(root, &path) else { continue };
        let body = std::fs::read(&path).map_err(|source| WebError::Io { path: path.clone(), source })?;
        let asset = asset_for(&url, Bytes::from(body));
        files.insert(url, asset);
    }
    Ok(())
}

fn url_path(root: &Path, file: &Path) -> Option<String> {
    let rel = file.strip_prefix(root).ok()?;
    let mut url = String::new();
    for c in rel.components() {
        let Component::Normal(part) = c else { return None };
        let part = part.to_str()?;
        if !part.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')) {
            return None;
        }
        url.push('/');
        url.push_str(part);
    }
    Some(url)
}

fn asset_for(url: &str, body: Bytes) -> Asset {
    let ext = url.rsplit_once('.').map_or("", |(_, e)| e);
    let content_type = match ext {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "webmanifest" => "application/manifest+json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    };
    // Vite puts content-hashed files under /assets/; everything else may change in place.
    Asset { body, content_type, immutable: url.starts_with("/assets/") }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn assets() -> WebAssets {
        WebAssets::from_files([
            ("index.html", b"<html>app</html>".as_slice()),
            ("assets/app-1a2b.js", b"console.log(1)".as_slice()),
            ("favicon.svg", b"<svg/>".as_slice()),
        ])
    }

    fn get(a: &WebAssets, path: &str) -> Option<Response> {
        a.respond(&Method::GET, &path.parse().unwrap())
    }

    #[test]
    fn serves_files_with_types_and_cache() {
        let a = assets();
        let js = get(&a, "/assets/app-1a2b.js").unwrap();
        assert_eq!(js.headers()[header::CONTENT_TYPE], "text/javascript; charset=utf-8");
        assert_eq!(js.headers()[header::CACHE_CONTROL], "public, max-age=31536000, immutable");
        assert_eq!(js.headers()[header::CONTENT_SECURITY_POLICY], UI_CSP);
        let icon = get(&a, "/favicon.svg").unwrap();
        assert_eq!(icon.headers()[header::CACHE_CONTROL], "no-cache");
    }

    #[test]
    fn spa_fallback_but_not_for_api_assets_or_writes() {
        let a = assets();
        let page = get(&a, "/secrets/123").unwrap();
        assert_eq!(page.headers()[header::CONTENT_TYPE], "text/html; charset=utf-8");
        assert_eq!(page.headers()[header::CACHE_CONTROL], "no-cache");
        assert!(get(&a, "/api/v1/nope").is_none());
        assert!(get(&a, "/api").is_none());
        assert!(get(&a, "/healthz").is_none());
        assert!(get(&a, "/assets/missing.js").is_none());
        assert!(a.respond(&Method::POST, &"/secrets".parse().unwrap()).is_none());
    }

    #[test]
    fn loads_directory_and_skips_symlinks_and_hidden() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<html/>").unwrap();
        std::fs::create_dir(dir.path().join("assets")).unwrap();
        std::fs::write(dir.path().join("assets/a.css"), "body{}").unwrap();
        std::fs::write(dir.path().join(".env"), "SECRET=1").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc/passwd", dir.path().join("passwd")).unwrap();
        let a = WebAssets::load(dir.path()).unwrap();
        assert_eq!(a.len(), 2);
        assert!(a.files.contains_key("/assets/a.css"));
        assert!(!a.files.contains_key("/.env"));
        assert!(!a.files.contains_key("/passwd"));
    }

    #[test]
    fn requires_index() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(WebAssets::load(dir.path()), Err(WebError::NoIndex)));
    }
}
