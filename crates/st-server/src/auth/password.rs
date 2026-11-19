//! Password hashing (argon2id, OWASP 2024 parameters) and policy.
//!
//! Hashing is CPU-bound (~tens of ms); async callers must use the `*_blocking`
//! wrappers which run on the blocking thread pool.

use std::sync::OnceLock;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

pub const MIN_PASSWORD_CHARS: usize = 12;
/// Upper bound protects against hashing-cost denial of service with huge inputs.
pub const MAX_PASSWORD_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PasswordPolicyError {
    #[error("password must be at least {MIN_PASSWORD_CHARS} characters")]
    TooShort,
    #[error("password must be at most {MAX_PASSWORD_BYTES} bytes")]
    TooLong,
    #[error("password must not contain the username")]
    ContainsUsername,
    #[error("password must not consist of a single repeated character")]
    Repetitive,
}

fn argon2() -> Argon2<'static> {
    // m = 19 MiB, t = 2, p = 1 (OWASP Password Storage Cheat Sheet, argon2id).
    let params = Params::new(19 * 1024, 2, 1, None).unwrap_or_default();
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub fn check_policy(username: &str, password: &str) -> Result<(), PasswordPolicyError> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(PasswordPolicyError::TooLong);
    }
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(PasswordPolicyError::TooShort);
    }
    if !username.is_empty() && password.to_lowercase().contains(&username.to_lowercase()) {
        return Err(PasswordPolicyError::ContainsUsername);
    }
    let mut chars = password.chars();
    if let Some(first) = chars.next()
        && chars.all(|c| c == first)
    {
        return Err(PasswordPolicyError::Repetitive);
    }
    Ok(())
}

/// Hash a password into a PHC string.
pub fn hash(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    argon2()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("argon2 hashing failed: {e}"))
}

/// Verify against a stored PHC string. Unknown/corrupt hashes verify as `false`.
#[must_use]
pub fn verify(password: &str, phc: &str) -> bool {
    if password.len() > MAX_PASSWORD_BYTES {
        return false;
    }
    PasswordHash::new(phc).is_ok_and(|parsed| argon2().verify_password(password.as_bytes(), &parsed).is_ok())
}

/// Hash used when the username does not exist, so the response time does not reveal
/// whether an account exists.
fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| hash("dummy-password-for-timing-equalization").unwrap_or_default())
}

pub async fn hash_blocking(password: Zeroizing<String>) -> anyhow::Result<String> {
    tokio::task::spawn_blocking(move || hash(&password)).await?
}

/// Verify on the blocking pool. `phc = None` (unknown user) burns the same CPU time
/// and returns `false`.
pub async fn verify_blocking(password: Zeroizing<String>, phc: Option<String>) -> anyhow::Result<bool> {
    Ok(tokio::task::spawn_blocking(move || {
        if let Some(phc) = phc {
            verify(&password, &phc)
        } else {
            let _ = verify(&password, dummy_hash());
            false
        }
    })
    .await?)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn hash_and_verify() {
        let h = hash("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{h}");
        assert!(verify("correct horse battery", &h));
        assert!(!verify("correct horse batterY", &h));
        assert!(!verify("anything", "not-a-phc-string"));
        assert_ne!(h, hash("correct horse battery").unwrap(), "salt must be random");
    }

    #[test]
    fn policy() {
        assert_eq!(check_policy("alice", "short"), Err(PasswordPolicyError::TooShort));
        assert_eq!(check_policy("alice", "my-ALICE-password"), Err(PasswordPolicyError::ContainsUsername));
        assert_eq!(check_policy("bob", "aaaaaaaaaaaaaaa"), Err(PasswordPolicyError::Repetitive));
        assert_eq!(check_policy("bob", &"x1".repeat(200)), Err(PasswordPolicyError::TooLong));
        assert_eq!(check_policy("bob", "пароль-надёжный"), Ok(()));
    }

    #[tokio::test]
    async fn unknown_user_path_returns_false() {
        assert!(!verify_blocking(Zeroizing::new("whatever-password".into()), None).await.unwrap());
    }
}
