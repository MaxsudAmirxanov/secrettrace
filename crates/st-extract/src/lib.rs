//! Candidate extraction for SecretTrace scanners.
//!
//! Finds secret-shaped values in text, normalizes and digests them **locally** with
//! `st-core`, and returns [`Candidate`]s that carry only the digest, a policy-compliant
//! mask and the location — never the plaintext. The digests are later matched against
//! the registry on the server; nothing here needs the pepper or the network.
//!
//! Detectors, in priority order (on the same digest and overlapping span the first wins):
//!
//! 1. known vendor formats (`AKIA…`, `ghp_…`, `xoxb-…`, JWT, …);
//! 2. PEM blocks and OpenSSH public keys;
//! 3. URL userinfo (`postgres://user:password@host/db`), password and whole URL;
//! 4. values of sensitive keys (`password=`, `"api_key":`, `--token`, XML, `.netrc`,
//!    `Authorization:` headers);
//! 5. escaped JSON strings, re-scanned after unescaping;
//! 6. random-looking tokens, and base64 blobs re-scanned after decoding.
//!
//! Decoding (base64, `%XX`, JSON escapes) nests up to [`Config::max_depth`] levels, e.g.
//! a Kubernetes Secret whose base64 value is a JSON document with a password inside.
//! All work is linear in the input: the `regex` crate has no backtracking, and
//! candidate count and decoded volume are capped.

mod candidate;
mod decode;
mod entropy;
mod known;
mod kv;
mod lines;
mod pem;
mod url;

use std::collections::HashMap;
use std::ops::Range;

use st_core::{Digest, derive_hints, digest_normalized, mask, normalize};

use candidate::Hit;
pub use candidate::{Candidate, Confidence, Detector, Encoding, Span};
pub use entropy::{looks_random, shannon_entropy};
pub use kv::{classify_key, is_placeholder};

/// Largest encoded blob that is decoded and re-scanned.
pub(crate) const MAX_DECODE_BYTES: usize = 1024 * 1024;

/// Ids of the known-format rules, for documentation and tests.
#[must_use]
pub fn known_rules() -> Vec<&'static str> {
    known::RULES.iter().map(|r| r.id).collect()
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Longer input is cut (at a char boundary) and the result marked truncated.
    pub max_input_bytes: usize,
    /// Stop recording after this many candidates per document.
    pub max_candidates: usize,
    /// Nesting limit for decoders (base64 inside JSON inside base64 …).
    pub max_depth: usize,
    /// Report random-looking tokens without context.
    pub entropy: bool,
    /// Minimum length of a context-free token.
    pub min_entropy_len: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_input_bytes: 16 * 1024 * 1024,
            max_candidates: 10_000,
            max_depth: 3,
            entropy: true,
            min_entropy_len: 16,
        }
    }
}

#[derive(Debug, Default)]
pub struct Extraction {
    /// Sorted by position.
    pub candidates: Vec<Candidate>,
    /// A limit was hit (input size, candidate count or decode budget); results are partial.
    pub truncated: bool,
}

/// Heuristic used by sources to skip binary files: a NUL byte near the start.
#[must_use]
pub fn looks_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8000).any(|&b| b == 0)
}

#[derive(Debug, Clone, Default)]
pub struct Extractor {
    config: Config,
}

impl Extractor {
    #[must_use]
    pub const fn new(config: Config) -> Self {
        Self { config }
    }

    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Extract candidates from one document.
    #[must_use]
    pub fn extract(&self, text: &str) -> Extraction {
        let mut truncated = false;
        let text = if text.len() > self.config.max_input_bytes {
            truncated = true;
            let mut end = self.config.max_input_bytes;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            &text[..end]
        } else {
            text
        };

        let lines = lines::LineIndex::new(text);
        let mut sink = Sink {
            lines: &lines,
            out: Vec::new(),
            seen: HashMap::new(),
            truncated,
            decode_budget: text.len().saturating_mul(4).max(MAX_DECODE_BYTES),
        };
        self.scan(text, &Frame::default(), &mut sink);

        let mut candidates = sink.out;
        candidates.sort_by_key(|c| (c.span.start, c.span.end));
        Extraction { candidates, truncated: sink.truncated }
    }

    fn scan(&self, text: &str, frame: &Frame, sink: &mut Sink<'_>) {
        let mut em = Emitter { ex: self, sink, frame };
        known::scan(text, &mut em);
        pem::scan(text, &mut em);
        url::scan(text, &mut em);
        kv::scan(text, &mut em);
        decode::scan_json_strings(text, &mut em);
        entropy::scan(text, &mut em);
    }
}

/// Where offsets of the text being scanned map to in the original document.
#[derive(Debug, Default)]
struct Frame {
    /// `None` at the top level; otherwise the span of the outermost encoded container.
    outer: Option<Range<usize>>,
    encodings: Vec<Encoding>,
}

impl Frame {
    fn map(&self, range: Range<usize>) -> Range<usize> {
        self.outer.clone().unwrap_or(range)
    }

    fn child(&self, range: Range<usize>, encoding: Encoding) -> Self {
        let mut encodings = self.encodings.clone();
        encodings.push(encoding);
        Self { outer: Some(self.map(range)), encodings }
    }
}

#[derive(Debug)]
struct Sink<'s> {
    lines: &'s lines::LineIndex,
    out: Vec<Candidate>,
    /// Digest → spans already reported, for de-duplication across detectors.
    seen: HashMap<Digest, Vec<Range<usize>>>,
    truncated: bool,
    decode_budget: usize,
}

/// Detectors report hits through this; it normalizes, digests, de-duplicates and
/// drives recursive decoding.
#[derive(Debug)]
pub(crate) struct Emitter<'e, 's> {
    ex: &'e Extractor,
    sink: &'e mut Sink<'s>,
    frame: &'e Frame,
}

impl Emitter<'_, '_> {
    pub const fn config(&self) -> &Config {
        &self.ex.config
    }

    fn full(&self) -> bool {
        self.sink.out.len() >= self.ex.config.max_candidates
    }

    pub fn can_decode(&self) -> bool {
        self.frame.encodings.len() < self.ex.config.max_depth && !self.full()
    }

    /// Normalize and record one value. Values rejected by `st_core::normalize` (too
    /// short, multi-line, malformed PEM) are dropped silently.
    pub fn emit(&mut self, hit: &Hit<'_>, raw: &str) -> bool {
        let Ok(canonical) = normalize(hit.ty, raw) else { return false };
        let digest = digest_normalized(&canonical);
        let range = self.frame.map(hit.range.clone());

        let spans = self.sink.seen.entry(digest).or_default();
        if spans.iter().any(|r| r.start < range.end && range.start < r.end) {
            return false;
        }
        if self.sink.out.len() >= self.ex.config.max_candidates {
            self.sink.truncated = true;
            return false;
        }
        spans.push(range.clone());

        let masked = mask(&derive_hints(hit.ty, &canonical));
        drop(canonical);
        let (line, column) = self.sink.lines.position(range.start);
        let mut encodings = self.frame.encodings.clone();
        encodings.extend(hit.encoding);
        self.sink.out.push(Candidate {
            digest,
            secret_type: hit.ty,
            detector: hit.detector,
            rule: hit.rule,
            confidence: hit.confidence,
            span: Span { start: range.start, end: range.end, line, column },
            encodings,
            key: hit.key.filter(|k| safe_key_label(k)).map(str::to_owned),
            masked,
        });
        true
    }

    /// Emit a configuration value together with its `%XX`- and base64-decoded forms.
    pub fn emit_value(&mut self, hit: &Hit<'_>, raw: &str) {
        self.emit(hit, raw);
        if raw.contains('%')
            && let Some(decoded) = decode::percent(raw)
        {
            self.emit(&hit.with_encoding(Encoding::Percent), &decoded);
        }
        if self.can_decode()
            && let Some(decoded) = decode::base64_text(raw.trim(), 8)
        {
            self.decoded(hit, Encoding::Base64, &decoded);
        }
    }

    /// A decoded value: record it, its Basic-auth password if it is `user:pass`, and
    /// re-scan it as a document.
    pub fn decoded(&mut self, hit: &Hit<'_>, encoding: Encoding, text: &str) {
        if !self.can_decode() || !self.spend(text.len()) {
            return;
        }
        let child = self.frame.child(hit.range.clone(), encoding);
        let mut inner = Emitter { ex: self.ex, sink: &mut *self.sink, frame: &child };
        inner.emit(&Hit { encoding: None, ..hit.clone() }, text);
        if let Some(pass) = decode::basic_auth_password(text) {
            inner.emit(&Hit::new(hit.range.clone(), st_core::SecretType::Password, Detector::BasicAuth), pass);
        }
        self.ex.scan(text, &child, &mut *self.sink);
    }

    /// Re-scan decoded text as a document without recording the text itself.
    pub fn recurse(&mut self, range: Range<usize>, encoding: Encoding, text: &str) {
        if !self.can_decode() || !self.spend(text.len()) {
            return;
        }
        let child = self.frame.child(range, encoding);
        self.ex.scan(text, &child, &mut *self.sink);
    }

    fn spend(&mut self, bytes: usize) -> bool {
        if let Some(left) = self.sink.decode_budget.checked_sub(bytes) {
            self.sink.decode_budget = left;
            true
        } else {
            self.sink.truncated = true;
            false
        }
    }
}

/// Key names go into reports; make sure a "key" is not itself a credential.
fn safe_key_label(key: &str) -> bool {
    key.len() <= 64
        && key.bytes().all(|b| b.is_ascii_graphic())
        && st_core::known_prefix(key).is_none()
        && !looks_random(key, 16)
}
