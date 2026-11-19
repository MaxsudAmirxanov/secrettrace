//! Client-side digest of a canonical secret value.
//!
//! `digest = SHA-256(DIGEST_DOMAIN || canonical_utf8)`
//!
//! The digest is what leaves the client (over mTLS). It is *not* stored: the server
//! turns it into a fingerprint with a keyed HMAC whose pepper never leaves the server.
//! A digest of a weak password is brute-forceable, so digests must be treated as
//! sensitive: never logged, never put in URLs.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq;

/// Domain separation tag. Changing it invalidates every registered fingerprint.
pub const DIGEST_DOMAIN: &[u8] = b"secrettrace/v1\0";

/// 32-byte SHA-256 digest of a canonical secret value.
#[derive(Clone, Copy, Eq)]
pub struct Digest([u8; 32]);

impl Digest {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl PartialEq for Digest {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl std::hash::Hash for Digest {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

/// Debug output is deliberately truncated so digests do not end up in logs verbatim.
impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({}…)", hex::encode(&self.0[..2]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("digest must be 64 lowercase hex characters")]
pub struct DigestParseError;

impl FromStr for Digest {
    type Err = DigestParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(DigestParseError);
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).map_err(|_| DigestParseError)?;
        Ok(Self(out))
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Digest an already-normalized value. Use [`crate::prepare`] for raw input.
#[must_use]
pub fn digest_normalized(canonical: &str) -> Digest {
    let mut h = Sha256::new();
    h.update(DIGEST_DOMAIN);
    h.update(canonical.as_bytes());
    Digest(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip_and_strict_parsing() {
        let d = digest_normalized("AKIAIOSFODNN7EXAMPLE");
        assert_eq!(d.to_hex().parse::<Digest>(), Ok(d));
        assert!(d.to_hex().to_uppercase().parse::<Digest>().is_err());
        assert!("abc".parse::<Digest>().is_err());
        assert!("zz".repeat(32).parse::<Digest>().is_err());
    }

    #[test]
    fn domain_separated_from_plain_sha256() {
        let plain: [u8; 32] = Sha256::digest(b"AKIAIOSFODNN7EXAMPLE").into();
        assert_ne!(digest_normalized("AKIAIOSFODNN7EXAMPLE").as_bytes(), &plain);
    }

    #[test]
    fn debug_is_truncated() {
        let d = digest_normalized("secret-value");
        let dbg = format!("{d:?}");
        assert!(dbg.len() < 20, "{dbg}");
        assert!(!dbg.contains(&d.to_hex()));
    }

    #[test]
    fn serde_as_hex_string() {
        let d = digest_normalized("secret-value");
        let json = serde_json::to_string(&d).unwrap_or_default();
        assert_eq!(json, format!("\"{}\"", d.to_hex()));
        let back: Digest = serde_json::from_str(&json).unwrap_or(Digest::from_bytes([0; 32]));
        assert_eq!(back, d);
    }
}
