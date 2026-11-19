//! Recognition hints stored next to a fingerprint.
//!
//! Hints let scanners cut exact windows out of text (`AKIA` + 16 chars) and let the UI
//! show `AKIA…Q2X7`. They also leak part of the value, so the policy is strict:
//!
//! * a prefix is stored **only** if it is a public, structural vendor prefix from
//!   [`KNOWN_PREFIXES`] (it carries no entropy);
//! * the length is stored only together with such a prefix;
//! * a 4-char suffix is stored only when the value is at least
//!   [`SUFFIX_MIN_LEN`] chars long, leaving ≥ 20 secret chars;
//! * low-entropy types (passwords, connection strings) never get hints.
//!
//! The server re-validates client-supplied hints with [`validate_hints`].

use serde::{Deserialize, Serialize};

use crate::SecretType;

/// Public, fixed prefixes of well-known credential formats. Longest first so the
/// most specific prefix wins.
pub const KNOWN_PREFIXES: &[&str] = &[
    "github_pat_",
    "sk-ant-api",
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "rk_test_",
    "sk-proj-",
    "xoxb-",
    "xoxp-",
    "xapp-",
    "glpat-",
    "glptt-",
    "pypi-",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "npm_",
    "AKIA",
    "ASIA",
    "AIza",
    "hvs.",
    "hf_",
    "SG.",
];

/// Minimum length (chars) before a 4-char suffix may be stored.
pub const SUFFIX_MIN_LEN: usize = 24;
pub const SUFFIX_LEN: usize = 4;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct Hints {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suffix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,
}

impl Hints {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.prefix.is_none() && self.suffix.is_none() && self.length.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HintsError {
    #[error("hints are not allowed for low-entropy secret types")]
    LowEntropyType,
    #[error("prefix is not a known public vendor prefix")]
    UnknownPrefix,
    #[error("length and suffix hints require a known prefix")]
    MissingPrefix,
    #[error("length hint is required together with a prefix")]
    MissingLength,
    #[error("length hint is shorter than the prefix or out of range")]
    BadLength,
    #[error("suffix must be exactly {SUFFIX_LEN} characters and requires length >= {SUFFIX_MIN_LEN}")]
    BadSuffix,
}

/// Return the known vendor prefix `value` starts with, if any.
#[must_use]
pub fn known_prefix(value: &str) -> Option<&'static str> {
    KNOWN_PREFIXES.iter().copied().find(|p| value.starts_with(p))
}

/// Derive policy-compliant hints from a canonical value.
#[must_use]
pub fn derive_hints(secret_type: SecretType, canonical: &str) -> Hints {
    if secret_type.is_low_entropy() {
        return Hints::default();
    }
    let Some(prefix) = known_prefix(canonical) else {
        return Hints::default();
    };
    let len = canonical.chars().count();
    let suffix = (len >= SUFFIX_MIN_LEN).then(|| {
        let chars: Vec<char> = canonical.chars().collect();
        chars[len - SUFFIX_LEN..].iter().collect()
    });
    Hints { prefix: Some(prefix.to_owned()), suffix, length: u32::try_from(len).ok() }
}

/// Validate hints received from an untrusted client.
pub fn validate_hints(secret_type: SecretType, hints: &Hints) -> Result<(), HintsError> {
    if hints.is_empty() {
        return Ok(());
    }
    if secret_type.is_low_entropy() {
        return Err(HintsError::LowEntropyType);
    }
    let Some(prefix) = hints.prefix.as_deref() else {
        return Err(HintsError::MissingPrefix);
    };
    if !KNOWN_PREFIXES.contains(&prefix) {
        return Err(HintsError::UnknownPrefix);
    }
    let Some(length) = hints.length else {
        return Err(HintsError::MissingLength);
    };
    let length = usize::try_from(length).map_err(|_| HintsError::BadLength)?;
    if length <= prefix.len() || length > crate::MAX_SECRET_LEN {
        return Err(HintsError::BadLength);
    }
    if let Some(suffix) = hints.suffix.as_deref()
        && (suffix.chars().count() != SUFFIX_LEN || length < SUFFIX_MIN_LEN || suffix.chars().any(char::is_control))
    {
        return Err(HintsError::BadSuffix);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_key_gets_prefix_and_length_but_no_suffix() {
        let h = derive_hints(SecretType::ApiKey, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(h.prefix.as_deref(), Some("AKIA"));
        assert_eq!(h.length, Some(20));
        assert_eq!(h.suffix, None, "20 chars is below SUFFIX_MIN_LEN");
        assert_eq!(validate_hints(SecretType::ApiKey, &h), Ok(()));
    }

    #[test]
    fn long_token_gets_suffix() {
        let v = "ghp_0123456789abcdefghijABCDEFGHIJ0123";
        let h = derive_hints(SecretType::Token, v);
        assert_eq!(h.prefix.as_deref(), Some("ghp_"));
        assert_eq!(h.suffix.as_deref(), Some("0123"));
        assert_eq!(validate_hints(SecretType::Token, &h), Ok(()));
    }

    #[test]
    fn most_specific_prefix_wins() {
        assert_eq!(known_prefix("github_pat_11AAA"), Some("github_pat_"));
        assert_eq!(known_prefix("sk-ant-api03-xyz"), Some("sk-ant-api"));
    }

    #[test]
    fn passwords_never_get_hints() {
        let h = derive_hints(SecretType::Password, "AKIAlooks-like-aws-but-is-a-password");
        assert!(h.is_empty());
        let forged = Hints { prefix: Some("AKIA".into()), suffix: None, length: Some(30) };
        assert_eq!(validate_hints(SecretType::Password, &forged), Err(HintsError::LowEntropyType));
    }

    #[test]
    fn unknown_values_get_no_hints() {
        assert!(derive_hints(SecretType::Token, "random-internal-token-123456789").is_empty());
    }

    #[test]
    fn rejects_forged_client_hints() {
        let t = SecretType::ApiKey;
        let arbitrary = Hints { prefix: Some("Sup3".into()), suffix: None, length: Some(30) };
        assert_eq!(validate_hints(t, &arbitrary), Err(HintsError::UnknownPrefix));

        let no_prefix = Hints { prefix: None, suffix: Some("abcd".into()), length: Some(40) };
        assert_eq!(validate_hints(t, &no_prefix), Err(HintsError::MissingPrefix));

        let short_suffix = Hints { prefix: Some("AKIA".into()), suffix: Some("ABCD".into()), length: Some(20) };
        assert_eq!(validate_hints(t, &short_suffix), Err(HintsError::BadSuffix));

        let long_suffix = Hints { prefix: Some("ghp_".into()), suffix: Some("ABCDEFG".into()), length: Some(40) };
        assert_eq!(validate_hints(t, &long_suffix), Err(HintsError::BadSuffix));

        let no_len = Hints { prefix: Some("AKIA".into()), suffix: None, length: None };
        assert_eq!(validate_hints(t, &no_len), Err(HintsError::MissingLength));

        let bad_len = Hints { prefix: Some("AKIA".into()), suffix: None, length: Some(3) };
        assert_eq!(validate_hints(t, &bad_len), Err(HintsError::BadLength));
    }

    #[test]
    fn rejects_unknown_json_fields() {
        let r: Result<Hints, _> = serde_json::from_str(r#"{"prefix":"AKIA","value":"x"}"#);
        assert!(r.is_err());
    }
}
