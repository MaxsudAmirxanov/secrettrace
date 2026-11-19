//! PEM blocks and OpenSSH public keys.
//!
//! The block is handed to `st_core::normalize` as is, which reduces it to the base64
//! body, so indentation (YAML), `\r\n` and JSON-escaped `\n` give the same digest.

use std::sync::LazyLock;

use regex::Regex;
use st_core::SecretType;

use crate::Emitter;
use crate::candidate::{Confidence, Detector, Hit};

/// Upper bound for a single PEM block (large RSA keys and certificates are ~3–7 KiB).
const MAX_BLOCK: usize = 64 * 1024;

#[allow(clippy::expect_used)] // static patterns, exercised by tests
static BEGIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"-----BEGIN ([A-Z0-9][A-Z0-9 ]{0,62})-----").expect("valid PEM pattern"));

#[allow(clippy::expect_used)]
static END: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"-----END ([A-Z0-9][A-Z0-9 ]{0,62})-----").expect("valid PEM pattern"));

#[allow(clippy::expect_used)]
static SSH_PUBLIC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-nistp(?:256|384|521)|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)[ \t]+AAAA[A-Za-z0-9+/]{16,}={0,3}",
    )
    .expect("valid OpenSSH pattern")
});

fn label_type(label: &str) -> (SecretType, Confidence) {
    if label.contains("PRIVATE KEY") {
        let ty = if label.contains("OPENSSH") { SecretType::SshKey } else { SecretType::PrivateKey };
        (ty, Confidence::High)
    } else {
        // Certificates, public keys, CSRs: tracked for propagation, not secret by themselves.
        (SecretType::Certificate, Confidence::Low)
    }
}

pub(crate) fn scan(text: &str, em: &mut Emitter<'_, '_>) {
    if text.contains("-----BEGIN ") {
        // Blocks do not nest, so a BEGIN pairs with the next END (one pass, no rescans:
        // searching forward from every BEGIN would be quadratic on adversarial input).
        let ends: Vec<_> = END.captures_iter(text).filter_map(|c| Some((c.get(0)?, c.get(1)?))).collect();
        for caps in BEGIN.captures_iter(text) {
            let (Some(whole), Some(label)) = (caps.get(0), caps.get(1)) else { continue };
            let next = ends.partition_point(|(m, _)| m.start() < whole.end());
            let Some((end, end_label)) = ends.get(next) else { break };
            if end_label.as_str() != label.as_str() || end.end() - whole.start() > MAX_BLOCK {
                continue;
            }
            let (ty, confidence) = label_type(label.as_str());
            let range = whole.start()..end.end();
            em.emit(&Hit::new(range.clone(), ty, Detector::Pem).confidence(confidence), &text[range]);
        }
    }
    for m in SSH_PUBLIC.find_iter(text) {
        em.emit(&Hit::new(m.range(), SecretType::SshKey, Detector::SshPublicKey), m.as_str());
    }
}
