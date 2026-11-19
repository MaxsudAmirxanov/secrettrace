//! Canonicalization of secret values.
//!
//! The same function is applied at registration time and to every scan candidate,
//! so a secret is recognised regardless of incidental formatting:
//!
//! * surrounding ASCII whitespace is removed;
//! * PEM blocks (certificates, private keys) are reduced to their base64 body,
//!   so line wrapping, `\r\n` and JSON-escaped `\n` do not matter;
//! * OpenSSH public keys (`ssh-ed25519 AAAA… comment`) are reduced to the key blob.
//!
//! Only the first PEM block of a chain is used.

use zeroize::Zeroizing;

/// Shortest value accepted for registration and scanning (in characters).
pub const MIN_SECRET_LEN: usize = 6;
/// Longest canonical value accepted (in bytes).
pub const MAX_SECRET_LEN: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NormalizeError {
    #[error("value is empty after normalization")]
    Empty,
    #[error("value is shorter than {MIN_SECRET_LEN} characters")]
    TooShort,
    #[error("value is longer than {MAX_SECRET_LEN} bytes")]
    TooLong,
    #[error("value contains a NUL byte")]
    ContainsNul,
    #[error("value contains a line break; only key material may span several lines")]
    MultiLine,
    #[error("malformed PEM block")]
    MalformedPem,
}

use crate::SecretType;

/// Produce the canonical form of `raw` for the given secret type.
pub fn normalize(secret_type: SecretType, raw: &str) -> Result<Zeroizing<String>, NormalizeError> {
    if raw.contains('\0') {
        return Err(NormalizeError::ContainsNul);
    }
    if raw.len() > MAX_SECRET_LEN * 2 {
        // Hard cap before any allocation; PEM bodies shrink, plain values do not.
        return Err(NormalizeError::TooLong);
    }

    let canonical = if secret_type.is_key_material() && raw.contains("-----BEGIN ") {
        pem_body(raw)?
    } else if let Some(blob) = (secret_type == SecretType::SshKey).then(|| openssh_public_blob(raw)).flatten() {
        blob
    } else {
        let trimmed = trim(raw);
        if trimmed.contains(['\n', '\r']) {
            return Err(NormalizeError::MultiLine);
        }
        Zeroizing::new(trimmed.to_owned())
    };

    check_len(&canonical)?;
    Ok(canonical)
}

fn trim(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_ascii_whitespace())
}

fn check_len(s: &str) -> Result<(), NormalizeError> {
    if s.is_empty() {
        return Err(NormalizeError::Empty);
    }
    if s.len() > MAX_SECRET_LEN {
        return Err(NormalizeError::TooLong);
    }
    if s.chars().count() < MIN_SECRET_LEN {
        return Err(NormalizeError::TooShort);
    }
    Ok(())
}

/// Extract the base64 body of the first PEM block.
fn pem_body(raw: &str) -> Result<Zeroizing<String>, NormalizeError> {
    // Undo JSON / shell style escaping that commonly wraps PEM in env files and manifests.
    let unescaped = Zeroizing::new(raw.replace("\\r\\n", "\n").replace("\\n", "\n"));

    let mut lines = unescaped.lines().map(trim);
    if !lines.by_ref().any(|l| l.starts_with("-----BEGIN ") && l.ends_with("-----")) {
        return Err(NormalizeError::MalformedPem);
    }

    let mut body = Zeroizing::new(String::new());
    let mut closed = false;
    for line in lines {
        if line.starts_with("-----END ") {
            closed = true;
            break;
        }
        // Encapsulated headers of legacy encrypted keys (Proc-Type, DEK-Info).
        if line.is_empty() || line.contains(':') {
            continue;
        }
        if !line.bytes().all(is_base64_byte) {
            return Err(NormalizeError::MalformedPem);
        }
        body.push_str(line);
    }

    if !closed || body.is_empty() {
        return Err(NormalizeError::MalformedPem);
    }
    Ok(body)
}

/// `ssh-ed25519 AAAAC3Nza… user@host` → `AAAAC3Nza…`
fn openssh_public_blob(raw: &str) -> Option<Zeroizing<String>> {
    let mut parts = trim(raw).split_ascii_whitespace();
    let algo = parts.next()?;
    let blob = parts.next()?;
    let known_algo = algo.starts_with("ssh-")
        || algo.starts_with("ecdsa-sha2-")
        || algo.starts_with("sk-ssh-")
        || algo.starts_with("sk-ecdsa-");
    (known_algo && blob.starts_with("AAAA") && blob.bytes().all(is_base64_byte))
        .then(|| Zeroizing::new(blob.to_owned()))
}

const fn is_base64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(t: SecretType, v: &str) -> Result<String, NormalizeError> {
        normalize(t, v).map(|z| z.as_str().to_owned())
    }

    #[test]
    fn trims_ascii_whitespace() {
        assert_eq!(norm(SecretType::Token, "  abcdef123\n").as_deref(), Ok("abcdef123"));
    }

    #[test]
    fn rejects_bad_values() {
        assert_eq!(norm(SecretType::Password, "   "), Err(NormalizeError::Empty));
        assert_eq!(norm(SecretType::Password, "abc"), Err(NormalizeError::TooShort));
        assert_eq!(norm(SecretType::Password, "abc\0defgh"), Err(NormalizeError::ContainsNul));
        assert_eq!(norm(SecretType::Token, "abcdef\nghijk"), Err(NormalizeError::MultiLine));
        let huge = "a".repeat(MAX_SECRET_LEN + 1);
        assert_eq!(norm(SecretType::Token, &huge), Err(NormalizeError::TooLong));
    }

    #[test]
    fn short_check_counts_chars_not_bytes() {
        // 6 Cyrillic chars = 12 bytes: accepted.
        assert!(norm(SecretType::Password, "пароль").is_ok());
        // 5 chars rejected even though it is 10 bytes.
        assert_eq!(norm(SecretType::Password, "парол"), Err(NormalizeError::TooShort));
    }

    const PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4w\nggE6AgEAAkEAq7BFUpkGp3+XQorKIXQEz9==\n-----END PRIVATE KEY-----\n";

    #[test]
    fn pem_formatting_is_irrelevant() {
        let expected = "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAq7BFUpkGp3+XQorKIXQEz9==";
        let crlf = PEM.replace('\n', "\r\n");
        let escaped = PEM.replace('\n', "\\n");
        let indented = PEM.lines().map(|l| ["    ", l, "\n"].concat()).collect::<String>();
        for v in [PEM, crlf.as_str(), escaped.as_str(), indented.as_str()] {
            assert_eq!(norm(SecretType::PrivateKey, v).as_deref(), Ok(expected), "input: {v:?}");
        }
    }

    #[test]
    fn pem_skips_encapsulated_headers_and_uses_first_block() {
        let v = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00FF\n\nAAAABBBBCCCC\n-----END RSA PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nZZZZZZZZ\n-----END CERTIFICATE-----";
        assert_eq!(norm(SecretType::PrivateKey, v).as_deref(), Ok("AAAABBBBCCCC"));
    }

    #[test]
    fn pem_errors() {
        let unclosed = "-----BEGIN CERTIFICATE-----\nAAAABBBB\n";
        assert_eq!(norm(SecretType::Certificate, unclosed), Err(NormalizeError::MalformedPem));
        let garbage = "-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----";
        assert_eq!(norm(SecretType::Certificate, garbage), Err(NormalizeError::MalformedPem));
    }

    #[test]
    fn pem_is_not_special_for_non_key_types() {
        assert_eq!(norm(SecretType::Token, PEM), Err(NormalizeError::MultiLine));
    }

    #[test]
    fn openssh_public_key_reduced_to_blob() {
        let v = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq user@laptop";
        assert_eq!(norm(SecretType::SshKey, v).as_deref(), Ok("AAAAC3NzaC1lZDI1NTE5AAAAIGq"));
        // Comment changes do not change the canonical form.
        let v2 = "ssh-ed25519   AAAAC3NzaC1lZDI1NTE5AAAAIGq   other comment";
        assert_eq!(norm(SecretType::SshKey, v2).as_deref(), Ok("AAAAC3NzaC1lZDI1NTE5AAAAIGq"));
    }
}
