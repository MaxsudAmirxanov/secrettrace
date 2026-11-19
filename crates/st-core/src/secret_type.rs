use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Kind of a registered secret. Mirrors the `secret_type` Postgres ENUM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type))]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "secret_type", rename_all = "snake_case"))]
pub enum SecretType {
    ApiKey,
    Password,
    Token,
    Certificate,
    PrivateKey,
    SshKey,
    DbConnectionString,
    Other,
}

impl SecretType {
    pub const ALL: [Self; 8] = [
        Self::ApiKey,
        Self::Password,
        Self::Token,
        Self::Certificate,
        Self::PrivateKey,
        Self::SshKey,
        Self::DbConnectionString,
        Self::Other,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::Password => "password",
            Self::Token => "token",
            Self::Certificate => "certificate",
            Self::PrivateKey => "private_key",
            Self::SshKey => "ssh_key",
            Self::DbConnectionString => "db_connection_string",
            Self::Other => "other",
        }
    }

    /// Key material whose textual form (PEM, OpenSSH) varies with formatting.
    #[must_use]
    pub const fn is_key_material(self) -> bool {
        matches!(self, Self::Certificate | Self::PrivateKey | Self::SshKey)
    }

    /// Types whose values are typically chosen by humans and may have low entropy.
    /// No hints are ever stored for these.
    #[must_use]
    pub const fn is_low_entropy(self) -> bool {
        matches!(self, Self::Password | Self::DbConnectionString)
    }
}

impl fmt::Display for SecretType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unknown secret type: {0}")]
pub struct UnknownSecretType(String);

impl FromStr for SecretType {
    type Err = UnknownSecretType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL.into_iter().find(|t| t.as_str() == s).ok_or_else(|| UnknownSecretType(s.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_str() {
        for t in SecretType::ALL {
            assert_eq!(t.as_str().parse::<SecretType>().ok(), Some(t));
            let json = serde_json::to_string(&t).unwrap_or_default();
            assert_eq!(json, format!("\"{}\"", t.as_str()));
        }
        assert!("nope".parse::<SecretType>().is_err());
    }
}
