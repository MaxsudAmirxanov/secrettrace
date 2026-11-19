use serde::{Deserialize, Serialize};

/// Role of a human user. Declaration order defines privilege: `Viewer < Operator < Admin`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[serde(rename_all = "lowercase")]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
pub enum Role {
    /// Read-only access to the registry, locations and alerts.
    Viewer,
    /// Manage secrets, sources, scans and alerts.
    Operator,
    /// Everything, including API tokens, channels and the audit log.
    Admin,
}

impl Role {
    #[must_use]
    pub fn allows(self, required: Self) -> bool {
        self >= required
    }
}

impl std::str::FromStr for Role {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "viewer" => Ok(Self::Viewer),
            "operator" => Ok(Self::Operator),
            "admin" => Ok(Self::Admin),
            other => Err(format!("unknown role {other:?} (expected viewer|operator|admin)")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hierarchy() {
        assert!(Role::Admin.allows(Role::Operator));
        assert!(Role::Operator.allows(Role::Operator));
        assert!(!Role::Viewer.allows(Role::Operator));
        assert!(!Role::Operator.allows(Role::Admin));
    }
}
