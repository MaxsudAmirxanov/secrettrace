//! Random-looking tokens and base64 blobs without surrounding context.

use std::sync::LazyLock;

use regex::Regex;
use st_core::SecretType;

use crate::candidate::{Detector, Encoding, Hit};
use crate::{Emitter, MAX_DECODE_BYTES, decode};

/// Longest token considered a single secret; longer runs are only decoded.
pub const MAX_TOKEN_LEN: usize = 1024;

/// Shannon entropy in bits per byte.
#[must_use]
pub fn shannon_entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[usize::from(b)] += 1;
    }
    let Ok(len) = u32::try_from(s.len()) else { return 0.0 };
    if len == 0 {
        return 0.0;
    }
    let len = f64::from(len);
    counts.iter().filter(|&&c| c > 0).map(|&c| f64::from(c) / len).map(|p| -p * p.log2()).sum()
}

/// Heuristic for "this could be a generated credential": long enough, mixes letters
/// and digits, and has enough entropy for its alphabet.
#[must_use]
pub fn looks_random(token: &str, min_len: usize) -> bool {
    let t = token.trim_end_matches('=');
    if t.len() < min_len || t.len() > MAX_TOKEN_LEN {
        return false;
    }
    let digits = t.bytes().any(|b| b.is_ascii_digit());
    let letters = t.bytes().any(|b| b.is_ascii_alphabetic());
    if !(digits && letters) {
        return false;
    }
    let h = shannon_entropy(t);
    if t.bytes().all(|b| b.is_ascii_hexdigit()) { t.len() >= 20 && h >= 3.0 } else { h >= 3.5 }
}

/// Runs of base64/base64url/hex characters with up to two `=` of padding.
#[allow(clippy::expect_used)] // static pattern, exercised by tests
static TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/_\-]{16,}={0,2}").expect("valid token pattern"));

pub(crate) fn scan(text: &str, em: &mut Emitter<'_, '_>) {
    let min_len = em.config().min_entropy_len;
    for m in TOKEN.find_iter(text) {
        let token = m.as_str();
        if token.len() > MAX_DECODE_BYTES {
            continue;
        }
        let hit = Hit::new(m.range(), SecretType::Other, Detector::HighEntropy);
        if em.config().entropy && token.len() <= MAX_TOKEN_LEN {
            if looks_random(token, min_len) {
                em.emit(&hit, token);
            }
            // Secrets embedded in URL paths (`/services/T0/B0/<secret>`).
            if token.contains('/') {
                let mut offset = m.start();
                for segment in token.split('/') {
                    if segment.len() < token.len() && looks_random(segment, min_len) {
                        em.emit(&hit.at(offset..offset + segment.len()), segment);
                    }
                    offset += segment.len() + 1;
                }
            }
        }
        if em.can_decode()
            && let Some(decoded) = decode::base64_text(token, min_len)
        {
            em.decoded(&hit, Encoding::Base64, &decoded);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_values() {
        assert!(shannon_entropy("").abs() < f64::EPSILON);
        assert!(shannon_entropy("aaaa").abs() < f64::EPSILON);
        assert!((shannon_entropy("abcd") - 2.0).abs() < 1e-9);
    }

    #[test]
    fn randomness_heuristic() {
        assert!(looks_random("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", 16));
        assert!(looks_random("3f9a1c0e7b2d4a6f8e0c1b3d5f7a9c2e", 16));
        assert!(!looks_random("getUserAccountSettings", 16), "no digits");
        assert!(!looks_random("1234567890123456789", 16), "no letters");
        assert!(!looks_random("aaaaaaaa11111111", 16), "low entropy");
        assert!(!looks_random("deadbeef00000000", 16), "short hex");
        assert!(!looks_random("Ab3", 16));
    }
}
