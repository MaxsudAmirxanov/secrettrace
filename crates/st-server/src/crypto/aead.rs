//! Application-level encryption for small sensitive fields stored in the DB
//! (currently: TOTP seeds). AES-256-GCM with a random 96-bit nonce; the caller's
//! context (e.g. the user id) is bound as associated data, so a ciphertext copied to
//! another row does not decrypt.
//!
//! Format: `version (1 byte) || nonce (12) || ciphertext+tag`.

use std::fmt;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use rand::RngCore as _;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

const FORMAT_V1: u8 = 1;
const NONCE_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AeadError {
    #[error("data key must be base64 of exactly 32 bytes")]
    BadKey,
    #[error("ciphertext is malformed or was not produced with this key/context")]
    Decrypt,
    #[error("encryption failed")]
    Encrypt,
}

pub struct DataKey {
    cipher: Aes256Gcm,
}

impl fmt::Debug for DataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DataKey(<redacted>)")
    }
}

impl DataKey {
    pub fn parse(b64: &SecretString) -> Result<Self, AeadError> {
        let bytes = Zeroizing::new(B64.decode(b64.expose_secret().trim()).map_err(|_| AeadError::BadKey)?);
        if bytes.len() != 32 {
            return Err(AeadError::BadKey);
        }
        let cipher = Aes256Gcm::new_from_slice(&bytes).map_err(|_| AeadError::BadKey)?;
        Ok(Self { cipher })
    }

    pub fn encrypt(&self, plaintext: &[u8], context: &[u8]) -> Result<Vec<u8>, AeadError> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ct = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: context })
            .map_err(|_| AeadError::Encrypt)?;
        let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
        out.push(FORMAT_V1);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn decrypt(&self, blob: &[u8], context: &[u8]) -> Result<Zeroizing<Vec<u8>>, AeadError> {
        let (&version, rest) = blob.split_first().ok_or(AeadError::Decrypt)?;
        if version != FORMAT_V1 || rest.len() < NONCE_LEN + 16 {
            return Err(AeadError::Decrypt);
        }
        let (nonce, ct) = rest.split_at(NONCE_LEN);
        self.cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: context })
            .map(Zeroizing::new)
            .map_err(|_| AeadError::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn key(b: u8) -> DataKey {
        DataKey::parse(&SecretString::from(B64.encode([b; 32]))).unwrap()
    }

    #[test]
    fn roundtrip_and_context_binding() {
        let k = key(1);
        let ct = k.encrypt(b"totp-seed", b"user-1").unwrap();
        assert_eq!(k.decrypt(&ct, b"user-1").unwrap().as_slice(), b"totp-seed");
        assert_eq!(k.decrypt(&ct, b"user-2").unwrap_err(), AeadError::Decrypt);
        assert_eq!(key(2).decrypt(&ct, b"user-1").unwrap_err(), AeadError::Decrypt);
        // Fresh nonce each time.
        assert_ne!(ct, k.encrypt(b"totp-seed", b"user-1").unwrap());
    }

    #[test]
    fn tampering_is_detected() {
        let k = key(1);
        let mut ct = k.encrypt(b"totp-seed", b"ctx").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 1;
        assert_eq!(k.decrypt(&ct, b"ctx").unwrap_err(), AeadError::Decrypt);
        assert_eq!(k.decrypt(&[], b"ctx").unwrap_err(), AeadError::Decrypt);
        assert_eq!(k.decrypt(&[9, 1, 2], b"ctx").unwrap_err(), AeadError::Decrypt);
    }

    #[test]
    fn rejects_bad_keys_and_hides_debug() {
        assert!(DataKey::parse(&SecretString::from(B64.encode([0u8; 16]))).is_err());
        assert!(DataKey::parse(&SecretString::from("not base64!".to_owned())).is_err());
        assert_eq!(format!("{:?}", key(1)), "DataKey(<redacted>)");
    }
}
