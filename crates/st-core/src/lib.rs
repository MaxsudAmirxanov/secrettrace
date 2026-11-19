//! SecretTrace core primitives.
//!
//! Everything in this crate runs on the *client* side as well (CLI, agents, CI),
//! so it must never need the server pepper. The pipeline is:
//!
//! ```text
//! raw value ──normalize──▶ canonical form ──digest──▶ SHA-256 (sent over mTLS)
//!                                     server: HMAC-SHA256(pepper_v, digest) = fingerprint
//! ```
//!
//! Plaintext values are only ever held in [`zeroize::Zeroizing`] buffers.

pub mod digest;
pub mod hints;
pub mod masking;
pub mod normalize;
pub mod secret_type;

pub use digest::{DIGEST_DOMAIN, Digest, DigestParseError, digest_normalized};
pub use hints::{Hints, HintsError, derive_hints, known_prefix, validate_hints};
pub use masking::mask;
pub use normalize::{MAX_SECRET_LEN, MIN_SECRET_LEN, NormalizeError, normalize};
pub use secret_type::SecretType;

/// Convenience: normalize a raw value for the given type and compute its digest and hints.
///
/// The normalized plaintext is zeroized before returning.
pub fn prepare(secret_type: SecretType, raw: &str) -> Result<(Digest, Hints), NormalizeError> {
    let canonical = normalize(secret_type, raw)?;
    let digest = digest_normalized(&canonical);
    let hints = derive_hints(secret_type, &canonical);
    Ok((digest, hints))
}
