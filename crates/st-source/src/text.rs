//! Bytes → text without leaving unzeroized copies of the content on the heap.
//!
//! Every output `String` is allocated once at its exact final size: growing a buffer
//! frees the old allocation without wiping it.

use std::char::{REPLACEMENT_CHARACTER, decode_utf16};

use serde::Serialize;
use st_extract::looks_binary;
use zeroize::Zeroizing;

/// How the bytes were turned into text. Spans refer to the decoded text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TextEncoding {
    Utf8,
    /// Invalid sequences were replaced with U+FFFD (Latin-1 configs, cut-off files).
    Utf8Lossy,
    /// UTF-16 with a byte-order mark (Windows editors and tools, `.reg` exports).
    Utf16Le,
    Utf16Be,
}

/// Decode file content, or `None` for binary data.
#[must_use]
pub fn decode_text(mut bytes: Zeroizing<Vec<u8>>) -> Option<(Zeroizing<String>, TextEncoding)> {
    let utf16 = if let Some(body) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        Some((utf16(body, u16::from_le_bytes), TextEncoding::Utf16Le))
    } else {
        bytes.strip_prefix(&[0xFE, 0xFF]).map(|body| (utf16(body, u16::from_be_bytes), TextEncoding::Utf16Be))
    };
    if let Some((text, encoding)) = utf16 {
        // A BOM followed by NULs in the text is a binary format that happens to start with FF FE.
        return (!text.chars().take(4000).any(|c| c == '\0')).then_some((text, encoding));
    }
    if looks_binary(&bytes) {
        return None;
    }
    // Move the buffer into the String instead of copying it.
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(text) => Some((Zeroizing::new(text), TextEncoding::Utf8)),
        Err(e) => {
            let bytes = Zeroizing::new(e.into_bytes());
            Some((lossy(&bytes), TextEncoding::Utf8Lossy))
        }
    }
}

fn lossy(bytes: &[u8]) -> Zeroizing<String> {
    let len = bytes
        .utf8_chunks()
        .map(|c| c.valid().len() + if c.invalid().is_empty() { 0 } else { REPLACEMENT_CHARACTER.len_utf8() })
        .sum();
    let mut out = Zeroizing::new(String::with_capacity(len));
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        if !chunk.invalid().is_empty() {
            out.push(REPLACEMENT_CHARACTER);
        }
    }
    out
}

fn utf16(body: &[u8], unit: fn([u8; 2]) -> u16) -> Zeroizing<String> {
    let units = || body.chunks_exact(2).map(|c| unit([c[0], c[1]]));
    let chars = || decode_utf16(units()).map(|r| r.unwrap_or(REPLACEMENT_CHARACTER));
    let odd = body.len() % 2 == 1;
    let len = chars().map(char::len_utf8).sum::<usize>() + if odd { REPLACEMENT_CHARACTER.len_utf8() } else { 0 };
    let mut out = Zeroizing::new(String::with_capacity(len));
    out.extend(chars());
    if odd {
        out.push(REPLACEMENT_CHARACTER);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(bytes: &[u8]) -> Option<(String, TextEncoding)> {
        decode_text(Zeroizing::new(bytes.to_vec())).map(|(t, e)| (t.to_string(), e))
    }

    #[test]
    fn encodings() {
        assert_eq!(decode(b"a=1\n"), Some(("a=1\n".into(), TextEncoding::Utf8)));
        assert_eq!(decode(b"p=caf\xe9!"), Some(("p=caf\u{FFFD}!".into(), TextEncoding::Utf8Lossy)));
        assert_eq!(decode(b"\xff\xfek\x00=\x00v\x00"), Some(("k=v".into(), TextEncoding::Utf16Le)));
        assert_eq!(decode(b"\xfe\xff\x00k\x00=\x00v"), Some(("k=v".into(), TextEncoding::Utf16Be)));
        assert_eq!(decode(b"\xff\xfek\x00="), Some(("k\u{FFFD}".into(), TextEncoding::Utf16Le)), "odd length");
        assert_eq!(decode(b"\x7fELF\x02\x01\x00\x00"), None);
        assert_eq!(decode(b"\xff\xfe\x00\x00\x00\x00"), None, "BOM-prefixed binary");
    }

    #[test]
    fn exact_capacity() {
        let (text, _) = decode_text(Zeroizing::new(b"x\xff\xfey".to_vec())).unwrap_or_else(|| unreachable!());
        assert_eq!(text.len(), text.capacity());
        let (text, _) =
            decode_text(Zeroizing::new(b"\xff\xfe=\xd8\x00\xde!\x00".to_vec())).unwrap_or_else(|| unreachable!());
        assert_eq!(&*text, "\u{1F600}!");
        assert_eq!(text.len(), text.capacity());
    }
}
