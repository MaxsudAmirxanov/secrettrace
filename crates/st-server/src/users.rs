//! User accounts: creation, lookup, lockout bookkeeping.

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, Postgres, Transaction};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::audit::{self, AuditEvent};
use crate::auth::{LOCKOUT, MAX_FAILED_ATTEMPTS, Role, password};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRow {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
    pub role: Role,
    pub totp_secret_enc: Option<Vec<u8>>,
    pub mfa_enabled: bool,
    pub is_active: bool,
    pub failed_logins: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub totp_last_step: Option<i64>,
}

impl UserRow {
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked_until.is_some_and(|t| t > Utc::now())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CreateUserError {
    #[error("username must be 1-64 characters of [A-Za-z0-9._@-]")]
    InvalidUsername,
    #[error(transparent)]
    Policy(#[from] password::PasswordPolicyError),
    #[error("username already exists")]
    Exists,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error(transparent)]
    Audit(#[from] audit::AuditError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[must_use]
pub fn valid_username(u: &str) -> bool {
    (1..=64).contains(&u.len())
        && u.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'@' | b'-'))
}

const SELECT_USER: &str = "SELECT id, username::text AS username, password_hash, role, totp_secret_enc, mfa_enabled,
        is_active, failed_logins, locked_until, totp_last_step FROM users";

pub async fn find_by_username(conn: &mut PgConnection, username: &str) -> Result<Option<UserRow>, sqlx::Error> {
    sqlx::query_as(&format!("{SELECT_USER} WHERE username = $1")).bind(username).fetch_optional(conn).await
}

pub async fn find_by_id_for_update(conn: &mut PgConnection, id: Uuid) -> Result<Option<UserRow>, sqlx::Error> {
    sqlx::query_as(&format!("{SELECT_USER} WHERE id = $1 FOR UPDATE")).bind(id).fetch_optional(conn).await
}

/// Create a user (admin CLI). Returns the new id. The action is audited in the same transaction.
pub async fn create(
    tx: &mut Transaction<'_, Postgres>,
    username: &str,
    password: Zeroizing<String>,
    role: Role,
    audit_event: AuditEvent,
) -> Result<Uuid, CreateUserError> {
    if !valid_username(username) {
        return Err(CreateUserError::InvalidUsername);
    }
    password::check_policy(username, &password)?;
    let phc = password::hash_blocking(password).await?;

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)
         ON CONFLICT (username) DO NOTHING RETURNING id",
    )
    .bind(username)
    .bind(&phc)
    .bind(role)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(CreateUserError::Exists)?;

    let event =
        audit_event.target("user", id.to_string()).details(serde_json::json!({ "username": username, "role": role }));
    audit::record(tx, &event).await?;
    Ok(id)
}

/// Count a failed password/TOTP attempt; lock the account once the limit is reached.
/// Returns `true` if the account is now locked.
pub async fn register_failure(conn: &mut PgConnection, id: Uuid) -> Result<bool, sqlx::Error> {
    let lock_secs = LOCKOUT.as_secs_f64();
    let locked: bool = sqlx::query_scalar(
        // An active lock is never extended (otherwise an attacker could keep a victim
        // locked forever); after an expired lock the counter starts over.
        "UPDATE users SET
            failed_logins = CASE
                WHEN locked_until > now() THEN failed_logins + 1
                WHEN locked_until IS NOT NULL THEN 1
                ELSE failed_logins + 1 END,
            locked_until = CASE
                WHEN locked_until > now() THEN locked_until
                WHEN (CASE WHEN locked_until IS NOT NULL THEN 1 ELSE failed_logins + 1 END) >= $2
                    THEN now() + make_interval(secs => $3)
                ELSE NULL END
         WHERE id = $1
         RETURNING locked_until IS NOT NULL AND locked_until > now()",
    )
    .bind(id)
    .bind(MAX_FAILED_ATTEMPTS)
    .bind(lock_secs)
    .fetch_one(conn)
    .await?;
    Ok(locked)
}

pub async fn reset_failures(conn: &mut PgConnection, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1").bind(id).execute(conn).await?;
    Ok(())
}

/// Remove the TOTP enrollment and all sessions (admin CLI `reset-mfa`).
pub async fn reset_mfa(conn: &mut PgConnection, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET totp_secret_enc = NULL, mfa_enabled = false, totp_last_step = NULL WHERE id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    crate::auth::session::delete_all_for_user(conn, id).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames() {
        assert!(valid_username("alice"));
        assert!(valid_username("ops.bot-1@corp"));
        assert!(!valid_username(""));
        assert!(!valid_username("with space"));
        assert!(!valid_username("кириллица"));
        assert!(!valid_username(&"a".repeat(65)));
    }
}
