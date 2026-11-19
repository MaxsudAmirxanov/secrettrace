//! Server-side pepper and fingerprints.
//!
//! `fingerprint = HMAC-SHA256(pepper_v, FP_DOMAIN || client_digest)`
//!
//! The pepper lives outside the database (env / Docker secret; Vault Transit later),
//! so a database dump alone does not allow offline guessing of weak secrets.
//!
//! Peppers are versioned. A fingerprint cannot be recomputed without the plaintext,
//! so rotation works by issuing new fingerprints with the new version while matching
//! against every configured version until old secrets are rotated out.

use std::collections::BTreeMap;
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use hmac::{Hmac, Mac};
use rand::RngCore as _;
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;
use st_core::Digest;
use zeroize::Zeroizing;

const FP_DOMAIN: &[u8] = b"secrettrace/fp/v1\0";
pub const MIN_KEY_BYTES: usize = 32;

/// Keyed fingerprint stored in `secrets.fingerprint`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Construct from database bytes.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        <[u8; 32]>::try_from(bytes).ok().map(Self)
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({}…)", hex::encode(&self.0[..2]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PepperError {
    #[error("no pepper keys configured")]
    Empty,
    #[error("entry #{0} must look like `<version>:<base64>`")]
    Syntax(usize),
    #[error("entry #{0}: version must be an integer in 1..=32767")]
    Version(usize),
    #[error("entry #{0}: key is not valid base64")]
    Base64(usize),
    #[error("entry #{0}: key must be at least {MIN_KEY_BYTES} bytes")]
    KeyTooShort(usize),
    #[error("duplicate pepper version {0}")]
    Duplicate(u16),
    #[error("current pepper version {0} is not configured")]
    UnknownCurrent(u16),
}

/// Set of pepper keys by version. `Debug` lists versions only.
pub struct Pepper {
    keys: BTreeMap<u16, Zeroizing<Vec<u8>>>,
    current: u16,
}

impl fmt::Debug for Pepper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pepper")
            .field("versions", &self.keys.keys().collect::<Vec<_>>())
            .field("current", &self.current)
            .finish()
    }
}

impl Pepper {
    /// Parse `1:<base64>,2:<base64>` (commas or newlines). `current` defaults to the
    /// highest version.
    pub fn parse(spec: &SecretString, current: Option<u16>) -> Result<Self, PepperError> {
        let mut keys = BTreeMap::new();
        let entries =
            spec.expose_secret().split([',', '\n']).map(str::trim).filter(|e| !e.is_empty() && !e.starts_with('#'));

        for (idx, entry) in entries.enumerate() {
            let n = idx + 1;
            let (version, key_b64) = entry.split_once(':').ok_or(PepperError::Syntax(n))?;
            let version: u16 = version.trim().parse().map_err(|_| PepperError::Version(n))?;
            if version == 0 || version > 32767 {
                return Err(PepperError::Version(n));
            }
            let key = Zeroizing::new(B64.decode(key_b64.trim()).map_err(|_| PepperError::Base64(n))?);
            if key.len() < MIN_KEY_BYTES {
                return Err(PepperError::KeyTooShort(n));
            }
            if keys.insert(version, key).is_some() {
                return Err(PepperError::Duplicate(version));
            }
        }

        let max = *keys.keys().next_back().ok_or(PepperError::Empty)?;
        let current = current.unwrap_or(max);
        if !keys.contains_key(&current) {
            return Err(PepperError::UnknownCurrent(current));
        }
        Ok(Self { keys, current })
    }

    #[must_use]
    pub const fn current_version(&self) -> u16 {
        self.current
    }

    pub fn versions(&self) -> impl Iterator<Item = u16> + '_ {
        self.keys.keys().copied()
    }

    /// Fingerprint with a specific pepper version, if configured.
    #[must_use]
    pub fn fingerprint(&self, version: u16, digest: &Digest) -> Option<Fingerprint> {
        self.keys.get(&version).map(|key| hmac(key, digest))
    }

    /// Fingerprint for registering a new secret.
    #[must_use]
    pub fn fingerprint_current(&self, digest: &Digest) -> (u16, Fingerprint) {
        let key = &self.keys[&self.current];
        (self.current, hmac(key, digest))
    }

    /// Fingerprints under every configured version (for matching scan candidates).
    #[must_use]
    pub fn fingerprint_all(&self, digest: &Digest) -> Vec<(u16, Fingerprint)> {
        self.keys.iter().map(|(v, k)| (*v, hmac(k, digest))).collect()
    }
}

fn hmac(key: &[u8], digest: &Digest) -> Fingerprint {
    // HMAC accepts keys of any length; the error branch is unreachable.
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else { unreachable!("HMAC-SHA256 accepts any key length") };
    mac.update(FP_DOMAIN);
    mac.update(digest.as_bytes());
    Fingerprint(mac.finalize().into_bytes().into())
}

/// Generate a fresh random key, base64-encoded (`gen-pepper` admin command).
#[must_use]
pub fn generate_key() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; MIN_KEY_BYTES]);
    rand::rngs::OsRng.fill_bytes(bytes.as_mut());
    Zeroizing::new(B64.encode(bytes.as_ref()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use st_core::digest_normalized;

    use super::*;

    fn spec(s: &str) -> SecretString {
        SecretString::from(s.to_owned())
    }

    fn key(byte: u8) -> String {
        B64.encode([byte; 32])
    }

    #[test]
    fn parses_versions_and_defaults_current_to_max() {
        let p = Pepper::parse(&spec(&format!("1:{}\n# comment\n3:{}", key(1), key(3))), None).unwrap();
        assert_eq!(p.current_version(), 3);
        assert_eq!(p.versions().collect::<Vec<_>>(), [1, 3]);
        let p = Pepper::parse(&spec(&format!("1:{},3:{}", key(1), key(3))), Some(1)).unwrap();
        assert_eq!(p.current_version(), 1);
    }

    #[test]
    fn parse_errors() {
        let k = key(1);
        let cases: [(String, Option<u16>, PepperError); 7] = [
            (String::new(), None, PepperError::Empty),
            ("nocolon".into(), None, PepperError::Syntax(1)),
            (format!("0:{k}"), None, PepperError::Version(1)),
            ("1:%%%".into(), None, PepperError::Base64(1)),
            (format!("1:{}", B64.encode([0u8; 16])), None, PepperError::KeyTooShort(1)),
            (format!("1:{k},1:{k}"), None, PepperError::Duplicate(1)),
            (format!("1:{k}"), Some(2), PepperError::UnknownCurrent(2)),
        ];
        for (s, cur, expected) in cases {
            assert_eq!(Pepper::parse(&spec(&s), cur).unwrap_err(), expected, "spec {s:?}");
        }
    }

    #[test]
    fn fingerprints_depend_on_key_and_version() {
        let p = Pepper::parse(&spec(&format!("1:{},2:{}", key(1), key(2))), None).unwrap();
        let d = digest_normalized("AKIAIOSFODNN7EXAMPLE");
        let (v, fp) = p.fingerprint_current(&d);
        assert_eq!(v, 2);
        assert_eq!(p.fingerprint(2, &d), Some(fp));
        assert_ne!(p.fingerprint(1, &d), Some(fp));
        assert_eq!(p.fingerprint(9, &d), None);
        assert_eq!(p.fingerprint_all(&d).len(), 2);
        // Deterministic.
        assert_eq!(p.fingerprint_current(&d), p.fingerprint_current(&d));
        // Different values → different fingerprints.
        assert_ne!(p.fingerprint_current(&digest_normalized("other-secret")).1, fp);
    }

    /// Known-answer test computed with Python's `hmac` module. Any change here
    /// silently invalidates every stored fingerprint, so it must be deliberate.
    #[test]
    fn known_answer() {
        let p = Pepper::parse(&spec(&format!("1:{}", key(1))), None).unwrap();
        let fp = p.fingerprint(1, &digest_normalized("AKIAIOSFODNN7EXAMPLE")).unwrap();
        assert_eq!(hex::encode(fp.as_bytes()), "380fb931b97934dcbb8fa28e65e44d4e94b5607fc9264dc52e0019c533690073");
    }

    #[test]
    fn debug_hides_keys() {
        let k = key(7);
        let p = Pepper::parse(&spec(&format!("1:{k}")), None).unwrap();
        let dbg = format!("{p:?}");
        assert!(!dbg.contains(&k), "{dbg}");
        assert!(dbg.contains("versions"));
    }

    #[test]
    fn generated_keys_are_valid_and_unique() {
        let a = generate_key();
        let b = generate_key();
        assert_ne!(*a, *b);
        assert!(Pepper::parse(&spec(&format!("1:{}", a.as_str())), None).is_ok());
    }
}
