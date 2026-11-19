//! TOTP (RFC 6238, HMAC-SHA1, 30 s, 6 digits) — the parameters every authenticator
//! app supports. Verification accepts ±1 step of clock drift and returns the matched
//! step so callers can reject reuse of a code (`users.totp_last_step`).

use std::fmt::Write as _;

use hmac::{Hmac, Mac};
use rand::RngCore as _;
use sha1::Sha1;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const STEP_SECS: i64 = 30;
pub const DIGITS: u32 = 6;
pub const SECRET_BYTES: usize = 20;
const DRIFT_STEPS: i64 = 1;

#[must_use]
pub fn generate_secret() -> Zeroizing<Vec<u8>> {
    let mut s = Zeroizing::new(vec![0u8; SECRET_BYTES]);
    rand::rngs::OsRng.fill_bytes(&mut s);
    s
}

#[must_use]
pub const fn step_at(unix_secs: i64) -> i64 {
    unix_secs.div_euclid(STEP_SECS)
}

/// HOTP value (RFC 4226) for a time step, as a zero-padded string.
#[must_use]
pub fn code_at_step(secret: &[u8], step: i64) -> String {
    let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(secret) else { unreachable!("HMAC accepts any key length") };
    mac.update(&step.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let offset = usize::from(h[h.len() - 1] & 0x0f);
    let bin = u32::from_be_bytes([h[offset] & 0x7f, h[offset + 1], h[offset + 2], h[offset + 3]]);
    format!("{:0width$}", bin % 10u32.pow(DIGITS), width = DIGITS as usize)
}

/// Verify `code` at `unix_secs`. Returns the matching step, or `None`.
/// Steps `<= last_used_step` are rejected (replay protection).
#[must_use]
pub fn verify(secret: &[u8], code: &str, unix_secs: i64, last_used_step: Option<i64>) -> Option<i64> {
    let code = code.trim();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let now = step_at(unix_secs);
    // Check every candidate without early exit to keep timing uniform.
    let mut matched = None;
    for step in (now - DRIFT_STEPS)..=(now + DRIFT_STEPS) {
        let ok: bool = code_at_step(secret, step).as_bytes().ct_eq(code.as_bytes()).into();
        if ok && last_used_step.is_none_or(|last| step > last) && matched.is_none() {
            matched = Some(step);
        }
    }
    matched
}

/// RFC 4648 base32 without padding, as used in `otpauth://` URIs.
#[must_use]
pub fn base32(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u64 = 0;
    let mut bits = 0u32;
    for &byte in data {
        buffer = (buffer << 8) | u64::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

/// Provisioning URI understood by authenticator apps (rendered as QR in the UI).
#[must_use]
pub fn otpauth_uri(issuer: &str, account: &str, secret: &[u8]) -> String {
    let issuer_enc = percent_encode(issuer);
    format!(
        "otpauth://totp/{issuer_enc}:{}?secret={}&issuer={issuer_enc}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        percent_encode(account),
        base32(secret),
    )
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SEED: &[u8] = b"12345678901234567890";

    /// RFC 6238 Appendix B (SHA1), truncated to 6 digits.
    #[test]
    fn rfc6238_vectors() {
        for (t, expected) in [
            (59, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000, "353130"),
        ] {
            assert_eq!(code_at_step(RFC_SEED, step_at(t)), expected, "t={t}");
        }
    }

    #[test]
    fn verify_window_and_replay() {
        let t = 1_234_567_890;
        let code = code_at_step(RFC_SEED, step_at(t));
        assert_eq!(verify(RFC_SEED, &code, t, None), Some(step_at(t)));
        // Accepted one step later (drift), rejected two steps later.
        assert_eq!(verify(RFC_SEED, &code, t + 30, None), Some(step_at(t)));
        assert_eq!(verify(RFC_SEED, &code, t + 90, None), None);
        // Replay of the same step is rejected.
        assert_eq!(verify(RFC_SEED, &code, t, Some(step_at(t))), None);
        // Garbage.
        assert_eq!(verify(RFC_SEED, "12345", t, None), None);
        assert_eq!(verify(RFC_SEED, "12a456", t, None), None);
    }

    #[test]
    fn base32_rfc4648() {
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32(RFC_SEED), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }

    #[test]
    fn otpauth_uri_encodes_parts() {
        let uri = otpauth_uri("SecretTrace", "alice@corp", RFC_SEED);
        assert_eq!(
            uri,
            "otpauth://totp/SecretTrace:alice%40corp?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=SecretTrace&algorithm=SHA1&digits=6&period=30"
        );
    }
}
