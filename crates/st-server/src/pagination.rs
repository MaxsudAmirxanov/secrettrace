//! Keyset (cursor) pagination over `(created_at DESC, id DESC)`.
//! Cursors are opaque to clients: `base64url("<unix micros>.<uuid>")`.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::ApiError;

pub const DEFAULT_LIMIT: i64 = 50;
pub const MAX_LIMIT: i64 = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    pub created_at: DateTime<Utc>,
    pub id: Uuid,
}

impl Cursor {
    #[must_use]
    pub fn encode(&self) -> String {
        B64URL.encode(format!("{}.{}", self.created_at.timestamp_micros(), self.id))
    }

    pub fn decode(s: &str) -> Result<Self, ApiError> {
        let bad = || ApiError::BadRequest("invalid cursor".into());
        if s.len() > 128 {
            return Err(bad());
        }
        let raw = B64URL.decode(s).map_err(|_| bad())?;
        let raw = std::str::from_utf8(&raw).map_err(|_| bad())?;
        let (micros, id) = raw.split_once('.').ok_or_else(bad)?;
        let created_at = DateTime::from_timestamp_micros(micros.parse().map_err(|_| bad())?).ok_or_else(bad)?;
        Ok(Self { created_at, id: id.parse().map_err(|_| bad())? })
    }
}

/// Clamp a client-supplied limit into `1..=MAX_LIMIT`.
pub fn limit(requested: Option<i64>) -> Result<i64, ApiError> {
    match requested {
        None => Ok(DEFAULT_LIMIT),
        Some(n) if (1..=MAX_LIMIT).contains(&n) => Ok(n),
        Some(_) => Err(ApiError::BadRequest(format!("limit must be 1..={MAX_LIMIT}"))),
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct Page<T> {
    pub items: Vec<T>,
    /// Pass as `cursor` to fetch the next page; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn cursor_roundtrip_and_rejects_garbage() {
        let c =
            Cursor { created_at: DateTime::from_timestamp_micros(1_700_000_000_123_456).unwrap(), id: Uuid::new_v4() };
        assert_eq!(Cursor::decode(&c.encode()).unwrap(), c);
        for bad in ["", "!!!", &B64URL.encode("123"), &B64URL.encode("x.y"), &"A".repeat(200)] {
            assert!(Cursor::decode(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn limits() {
        assert_eq!(limit(None).unwrap(), 50);
        assert_eq!(limit(Some(200)).unwrap(), 200);
        assert!(limit(Some(0)).is_err());
        assert!(limit(Some(201)).is_err());
    }
}
