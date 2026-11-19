//! Shared enums mirroring Postgres ENUM types.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type, ToSchema)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "secret_status", rename_all = "snake_case")]
pub enum SecretStatus {
    Active,
    Expired,
    Revoked,
    Rotated,
}

impl SecretStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Rotated => "rotated",
        }
    }

    /// `revoked` and `rotated` are final: the value must never be trusted again.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Revoked | Self::Rotated)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type, ToSchema)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "source_type", rename_all = "snake_case")]
pub enum SourceType {
    GitRepo,
    Filesystem,
    DockerImage,
    K8s,
    CiLog,
    AppLog,
    Wiki,
}
