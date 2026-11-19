//! Opaque bearer secrets: session cookies, CSRF tokens, API tokens.
//!
//! Only SHA-256 hashes are stored. Tokens carry 256 bits of randomness, so a plain
//! (unsalted, fast) hash is sufficient — there is nothing to brute-force.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use rand::RngCore as _;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const API_TOKEN_PREFIX: &str = "stk_";
const CSRF_DOMAIN: &[u8] = b"secrettrace/csrf/v1\0";

/// Known API token scopes. Tokens are for machines (agents, CI); humans use sessions.
pub const API_SCOPES: &[&str] = &["ingest:profile", "ingest:match", "ingest:findings"];

#[must_use]
pub fn random_token() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(bytes.as_mut());
    Zeroizing::new(B64URL.encode(bytes.as_ref()))
}

#[must_use]
pub fn hash_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// CSRF token bound to a session: `base64url(SHA-256(domain || session_token))`.
/// Knowing it does not reveal the session token; it can be recomputed from the
/// cookie, so nothing is stored.
#[must_use]
pub fn csrf_for_session(session_token: &str) -> String {
    let mut h = Sha256::new();
    h.update(CSRF_DOMAIN);
    h.update(session_token.as_bytes());
    B64URL.encode(h.finalize())
}

#[must_use]
pub fn csrf_matches(session_token: &str, presented: &str) -> bool {
    csrf_for_session(session_token).as_bytes().ct_eq(presented.as_bytes()).into()
}

/// A freshly generated API token. `token` is shown to the user exactly once.
#[derive(Debug)]
pub struct NewApiToken {
    pub token: Zeroizing<String>,
    /// Public identifier, e.g. `stk_3f9a1c0b`, safe to display and log.
    pub prefix: String,
    pub hash: [u8; 32],
}

#[must_use]
pub fn new_api_token() -> NewApiToken {
    let mut id = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut id);
    let prefix = format!("{API_TOKEN_PREFIX}{}", hex::encode(id));
    let token = Zeroizing::new(format!("{prefix}_{}", random_token().as_str()));
    let hash = hash_token(&token);
    NewApiToken { token, prefix, hash }
}

/// Cheap syntactic check before touching the database.
#[must_use]
pub fn looks_like_api_token(s: &str) -> bool {
    s.len() == API_TOKEN_PREFIX.len() + 8 + 1 + 43
        && s.starts_with(API_TOKEN_PREFIX)
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_tokens_are_long_and_unique() {
        let a = random_token();
        assert_eq!(a.len(), 43);
        assert_ne!(*a, *random_token());
    }

    #[test]
    fn csrf_is_bound_to_session() {
        let s1 = random_token();
        let s2 = random_token();
        let c1 = csrf_for_session(&s1);
        assert!(csrf_matches(&s1, &c1));
        assert!(!csrf_matches(&s2, &c1));
        assert!(!csrf_matches(&s1, ""));
        assert_ne!(c1, *s1);
    }

    #[test]
    fn api_token_format() {
        let t = new_api_token();
        assert!(t.token.starts_with(&t.prefix));
        assert!(looks_like_api_token(&t.token), "{}", t.prefix);
        assert_eq!(t.hash, hash_token(&t.token));
        assert!(!looks_like_api_token("stk_short"));
        assert!(!looks_like_api_token("Bearer something"));
    }
}
