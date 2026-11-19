//! Decoders that unwrap values hidden behind an encoding layer.
//!
//! Every decoder returns `None` unless decoding actually changed something and the
//! result is printable text, so random tokens do not turn into binary noise.
//! Decoded plaintext lives in [`Zeroizing`] buffers.

use std::sync::LazyLock;

use base64::Engine as _;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use regex::Regex;
use zeroize::Zeroizing;

use crate::candidate::Encoding;
use crate::{Emitter, MAX_DECODE_BYTES};

const B64_CONFIG: GeneralPurposeConfig =
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent);
const B64_STD: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, B64_CONFIG);
const B64_URL: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, B64_CONFIG);

/// Decode standard or URL-safe base64 (padding optional) into printable UTF-8 text.
pub(crate) fn base64_text(s: &str, min_len: usize) -> Option<Zeroizing<String>> {
    let body = s.trim_end_matches('=');
    if body.len() < min_len || s.len() > MAX_DECODE_BYTES || s.len() - body.len() > 2 || body.len() % 4 == 1 {
        return None;
    }
    let std = body.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/');
    let url = body.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    let engine = match (std, url) {
        (true, _) => &B64_STD,
        (false, true) => &B64_URL,
        (false, false) => return None,
    };
    let bytes = Zeroizing::new(engine.decode(s).ok()?);
    let text = std::str::from_utf8(&bytes).ok()?;
    is_printable(text).then(|| Zeroizing::new(text.to_owned()))
}

/// Decode `%XX` sequences. Returns `None` if there were none or the result is not UTF-8.
pub(crate) fn percent(s: &str) -> Option<Zeroizing<String>> {
    let b = s.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(b.len()));
    let mut changed = false;
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let (Some(h), Some(l)) = (b.get(i + 1).and_then(|&c| hex(c)), b.get(i + 2).and_then(|&c| hex(c)))
        {
            out.push(h << 4 | l);
            changed = true;
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    if !changed {
        return None;
    }
    let text = std::str::from_utf8(&out).ok()?;
    is_printable(text).then(|| Zeroizing::new(text.to_owned()))
}

/// Undo JSON (and shell double-quote) escapes of a string body without its quotes.
pub(crate) fn json_unescape(s: &str) -> Option<Zeroizing<String>> {
    if !s.contains('\\') {
        return None;
    }
    let mut out = Zeroizing::new(String::with_capacity(s.len()));
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next()? {
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'b' => out.push('\u{8}'),
            'f' => out.push('\u{c}'),
            'u' => {
                let hi = hex4(&mut chars)?;
                let code = if (0xD800..0xDC00).contains(&hi) {
                    // Surrogate pair: expect `\uDC00..\uDFFF` next.
                    let mut ahead = chars.clone();
                    if ahead.next() == Some('\\') && ahead.next() == Some('u') {
                        match hex4(&mut ahead) {
                            Some(lo) if (0xDC00..0xE000).contains(&lo) => {
                                chars = ahead;
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            }
                            _ => 0xFFFD,
                        }
                    } else {
                        0xFFFD
                    }
                } else {
                    hi
                };
                out.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
            }
            // `\"`, `\\`, `\/` (JSON) and `\$`, `` \` ``, `\'` (shell): drop the backslash.
            e @ ('"' | '\\' | '/' | '$' | '`' | '\'') => out.push(e),
            other => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    Some(out)
}

/// `user:password` (a decoded HTTP Basic credential or Docker `auth`) → `password`.
pub(crate) fn basic_auth_password(text: &str) -> Option<&str> {
    let t = text.trim();
    if t.contains(char::is_whitespace) {
        return None;
    }
    let (user, pass) = t.split_once(':')?;
    (!user.is_empty() && user.len() <= 256 && !pass.is_empty() && pass.len() <= 512).then_some(pass)
}

pub(crate) fn is_printable(text: &str) -> bool {
    !text.is_empty() && text.chars().all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
}

const fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn hex4(chars: &mut std::str::Chars<'_>) -> Option<u32> {
    (0..4).try_fold(0u32, |acc, _| Some(acc << 4 | chars.next()?.to_digit(16)?))
}

/// Double-quoted string literals on one line.
#[allow(clippy::expect_used)] // static pattern, exercised by tests
static JSON_STRING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""((?:[^"\\\n]|\\.)*)""#).expect("valid JSON string pattern"));

/// Re-scan the unescaped body of every escaped string literal (nested JSON,
/// `\"password\":\"…\"` in logs, values after a `\n`).
pub(crate) fn scan_json_strings(text: &str, em: &mut Emitter<'_, '_>) {
    if !em.can_decode() || !text.contains('\\') {
        return;
    }
    for caps in JSON_STRING.captures_iter(text) {
        let Some(body) = caps.get(1) else { continue };
        if body.len() < 8 || body.len() > MAX_DECODE_BYTES {
            continue;
        }
        if let Some(unescaped) = json_unescape(body.as_str()) {
            em.recurse(body.range(), Encoding::JsonString, &unescaped);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(z: Option<Zeroizing<String>>) -> Option<String> {
        z.map(|v| v.as_str().to_owned())
    }

    #[test]
    fn base64_variants() {
        assert_eq!(s(base64_text("aHVudGVyMmh1bnRlcjI=", 8)).as_deref(), Some("hunter2hunter2"));
        assert_eq!(s(base64_text("aHVudGVyMmh1bnRlcjI", 8)).as_deref(), Some("hunter2hunter2"));
        // URL-safe alphabet: "??>>??" encodes with '-' / '_'.
        assert_eq!(s(base64_text("Pz8-Pj8_", 8)).as_deref(), Some("??>>??"));
        // Binary output, too short, bad charset, bad length.
        assert_eq!(s(base64_text("AAECAwQFBgcICQoL", 8)), None);
        assert_eq!(s(base64_text("aGk=", 8)), None);
        assert_eq!(s(base64_text("not base64!!", 8)), None);
        assert_eq!(s(base64_text("aHVudGVyM", 8)), None);
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(s(percent("p%40ss%2Fw0rd")).as_deref(), Some("p@ss/w0rd"));
        assert_eq!(s(percent("100%")), None);
        assert_eq!(s(percent("%zz%4")), None);
        assert_eq!(s(percent("%00abc")), None);
        assert_eq!(s(percent("%FF%FE")), None);
    }

    #[test]
    fn json_unescaping() {
        assert_eq!(s(json_unescape(r#"{\"password\":\"x\"}"#)).as_deref(), Some(r#"{"password":"x"}"#));
        assert_eq!(s(json_unescape(r"a\nb\tc\\d\/e")).as_deref(), Some("a\nb\tc\\d/e"));
        assert_eq!(s(json_unescape(concat!(r"\u", "0041", r"\u", "d83d", r"\u", "de00"))).as_deref(), Some("A😀"));
        assert_eq!(s(json_unescape(r"\ud83d")).as_deref(), Some("\u{FFFD}"));
        assert_eq!(s(json_unescape(r"p\$ss\q")).as_deref(), Some(r"p$ss\q"));
        assert_eq!(s(json_unescape("plain")), None);
        assert_eq!(s(json_unescape(r"\u12")), None);
        assert_eq!(s(json_unescape("trailing\\")), None);
    }

    #[test]
    fn basic_auth() {
        assert_eq!(basic_auth_password("deploy:s3cr3t:with:colons"), Some("s3cr3t:with:colons"));
        assert_eq!(basic_auth_password(":nouser"), None);
        assert_eq!(basic_auth_password("user:"), None);
        assert_eq!(basic_auth_password("two words:x"), None);
    }
}
