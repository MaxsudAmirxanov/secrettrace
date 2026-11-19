use serde::Serialize;
use st_core::{Digest, SecretType};

/// A secret-shaped value found in text. Holds **no plaintext**: only the client-side
/// digest (sent to the server for matching), a policy-compliant mask and the location.
#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    /// Digest of the canonical value. Not serialized: digests of weak passwords are
    /// brute-forceable, so callers decide explicitly where they go.
    #[serde(skip)]
    pub digest: Digest,
    #[serde(rename = "type")]
    pub secret_type: SecretType,
    pub detector: Detector,
    /// Rule id for [`Detector::Known`] (e.g. `aws_access_key_id`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<&'static str>,
    pub confidence: Confidence,
    pub span: Span,
    /// Decoding steps applied before the value was found, outermost first.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub encodings: Vec<Encoding>,
    /// Name of the configuration key the value was assigned to (only sensitive names
    /// such as `DB_PASSWORD`, and never anything that itself looks like a secret).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Built from [`st_core::Hints`] only, e.g. `ghp_…Q2X7` or `••••••••`.
    pub masked: String,
}

/// Location in the scanned text. For values found inside an encoded container
/// (base64, JSON string), the span covers the container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Span {
    /// Byte offsets into the scanned text.
    pub start: usize,
    pub end: usize,
    /// 1-based line.
    pub line: u32,
    /// 1-based column, in bytes.
    pub column: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Detector {
    /// A vendor format with a fixed structure (`AKIA…`, `ghp_…`, JWT, …).
    Known,
    /// A PEM block (private key, certificate).
    Pem,
    /// An OpenSSH public key line.
    SshPublicKey,
    /// The password part of `scheme://user:password@host`.
    UrlPassword,
    /// A whole URL carrying credentials (connection string).
    Url,
    /// A value assigned to a sensitive key (`password=`, `"api_key":`, `--token`, XML element).
    KeyValue,
    /// `Authorization: Bearer …` / `Basic …`.
    AuthHeader,
    /// The password of a decoded `user:password` pair (HTTP Basic, Docker `auth`).
    BasicAuth,
    /// A random-looking token without further context.
    HighEntropy,
}

impl Detector {
    #[must_use]
    pub const fn default_confidence(self) -> Confidence {
        match self {
            Self::Known | Self::Pem => Confidence::High,
            Self::UrlPassword | Self::Url | Self::KeyValue | Self::AuthHeader | Self::BasicAuth => Confidence::Medium,
            Self::SshPublicKey | Self::HighEntropy => Confidence::Low,
        }
    }
}

/// How likely the candidate is a credential *on its own*, i.e. without matching the
/// registry. Matching registered secrets uses every candidate regardless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    Base64,
    /// `%XX` URL encoding.
    Percent,
    /// JSON / shell double-quoted string escapes (`\"`, `\n`, `\uXXXX`).
    JsonString,
}

/// Internal description of a hit before it is normalized and digested.
#[derive(Debug, Clone)]
pub(crate) struct Hit<'k> {
    pub range: std::ops::Range<usize>,
    pub ty: SecretType,
    pub detector: Detector,
    pub rule: Option<&'static str>,
    pub key: Option<&'k str>,
    pub encoding: Option<Encoding>,
    pub confidence: Confidence,
}

impl<'k> Hit<'k> {
    pub fn new(range: std::ops::Range<usize>, ty: SecretType, detector: Detector) -> Self {
        Self { range, ty, detector, rule: None, key: None, encoding: None, confidence: detector.default_confidence() }
    }

    pub const fn rule(mut self, rule: &'static str) -> Self {
        self.rule = Some(rule);
        self
    }

    pub const fn key(mut self, key: &'k str) -> Self {
        self.key = Some(key);
        self
    }

    pub const fn confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn with_encoding(&self, encoding: Encoding) -> Self {
        Self { encoding: Some(encoding), ..self.clone() }
    }

    pub fn at(&self, range: std::ops::Range<usize>) -> Self {
        Self { range, ..self.clone() }
    }
}
