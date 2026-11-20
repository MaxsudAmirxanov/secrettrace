//! Server-side sessions. The cookie holds a random token; the DB holds its SHA-256.

use std::net::IpAddr;
use std::time::Duration;

use axum::http::{HeaderMap, HeaderValue, header};
use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{AuthSettings, PRE_MFA_TTL, Role, tokens};

#[derive(Debug)]
pub struct NewSession {
    pub token: Zeroizing<String>,
    pub csrf_token: String,
    pub expires_at: DateTime<Utc>,
    pub max_age: Duration,
}

/// Session joined with the owning user, as loaded on each request.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SessionRecord {
    pub token_hash: Vec<u8>,
    pub user_id: Uuid,
    pub username: String,
    pub role: Role,
    pub mfa_passed: bool,
    pub mfa_enabled: bool,
    pub expires_at: DateTime<Utc>,
}

pub async fn create(
    conn: &mut PgConnection,
    user_id: Uuid,
    mfa_passed: bool,
    ip: Option<IpAddr>,
    user_agent: Option<&str>,
    settings: &AuthSettings,
) -> Result<NewSession, sqlx::Error> {
    let token = tokens::random_token();
    let max_age = if mfa_passed { settings.session_ttl } else { PRE_MFA_TTL };
    let expires_at = Utc::now() + chrono::Duration::from_std(max_age).unwrap_or(chrono::Duration::hours(12));
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, mfa_passed, ip, user_agent, expires_at)
         VALUES ($1, $2, $3, $4::inet, $5, $6)",
    )
    .bind(tokens::hash_token(&token).as_slice())
    .bind(user_id)
    .bind(mfa_passed)
    .bind(ip.map(|i| i.to_string()))
    .bind(user_agent)
    .bind(expires_at)
    .execute(conn)
    .await?;
    let csrf_token = tokens::csrf_for_session(&token);
    Ok(NewSession { token, csrf_token, expires_at, max_age })
}

/// Load a live session: not expired, not idle for too long, owner active.
/// Refreshes `last_seen_at` at most once a minute.
pub async fn lookup(pool: &PgPool, token: &str, idle: Duration) -> Result<Option<SessionRecord>, sqlx::Error> {
    let hash = tokens::hash_token(token);
    let record: Option<SessionRecord> = sqlx::query_as(
        "SELECT s.token_hash, s.user_id, u.username::text AS username, u.role, s.mfa_passed, u.mfa_enabled, s.expires_at
         FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = $1
           AND s.expires_at > now()
           AND s.last_seen_at > now() - make_interval(secs => $2)
           AND u.is_active
           AND (u.locked_until IS NULL OR u.locked_until <= now())",
    )
    .bind(hash.as_slice())
    .bind(idle.as_secs_f64())
    .fetch_optional(pool)
    .await?;

    if record.is_some() {
        sqlx::query(
            "UPDATE sessions SET last_seen_at = now()
             WHERE token_hash = $1 AND last_seen_at < now() - interval '60 seconds'",
        )
        .bind(hash.as_slice())
        .execute(pool)
        .await?;
    }
    Ok(record)
}

pub async fn delete(conn: &mut PgConnection, token_hash: &[u8]) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM sessions WHERE token_hash = $1").bind(token_hash).execute(conn).await?;
    Ok(())
}

pub async fn delete_all_for_user(conn: &mut PgConnection, user_id: Uuid) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query("DELETE FROM sessions WHERE user_id = $1").bind(user_id).execute(conn).await?.rows_affected())
}

/// End every session of the user except the one with `keep_hash` (password change).
pub async fn delete_others(conn: &mut PgConnection, user_id: Uuid, keep_hash: &[u8]) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2")
        .bind(user_id)
        .bind(keep_hash)
        .execute(conn)
        .await?
        .rows_affected())
}

pub async fn delete_expired(conn: &mut PgConnection) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query("DELETE FROM sessions WHERE expires_at <= now()").execute(conn).await?.rows_affected())
}

/// `Set-Cookie` value for a new session.
#[must_use]
pub fn set_cookie(settings: &AuthSettings, session: &NewSession) -> HeaderValue {
    cookie_header(settings, &session.token, session.max_age.as_secs())
}

/// `Set-Cookie` value that removes the session cookie.
#[must_use]
pub fn clear_cookie(settings: &AuthSettings) -> HeaderValue {
    cookie_header(settings, "", 0)
}

fn cookie_header(settings: &AuthSettings, value: &str, max_age: u64) -> HeaderValue {
    let secure = if settings.cookie_secure { "; Secure" } else { "" };
    let cookie =
        format!("{}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}", settings.cookie_name());
    // Token alphabet is base64url, so the value is always a valid header.
    HeaderValue::from_str(&cookie).unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// Extract the session token from the `Cookie` header(s).
#[must_use]
pub fn token_from_headers<'a>(headers: &'a HeaderMap, cookie_name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, value)| *name == cookie_name && !value.is_empty())
        .map(|(_, value)| value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(secure: bool) -> AuthSettings {
        AuthSettings {
            session_ttl: Duration::from_secs(3600),
            session_idle: Duration::from_secs(600),
            cookie_secure: secure,
            totp_issuer: "SecretTrace".into(),
            trusted_proxies: vec![],
            require_client_cert: false,
        }
    }

    #[test]
    fn cookie_attributes() {
        let s = NewSession {
            token: Zeroizing::new("tok".into()),
            csrf_token: String::new(),
            expires_at: Utc::now(),
            max_age: Duration::from_secs(3600),
        };
        let prod = set_cookie(&settings(true), &s);
        assert_eq!(prod, "__Host-st_session=tok; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600; Secure");
        let dev = set_cookie(&settings(false), &s);
        assert_eq!(dev, "st_session=tok; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600");
        assert_eq!(clear_cookie(&settings(false)), "st_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    }

    #[test]
    fn parses_cookie_header() {
        let mut h = HeaderMap::new();
        h.append(header::COOKIE, HeaderValue::from_static("theme=dark; st_session=abc"));
        h.append(header::COOKIE, HeaderValue::from_static("other=1"));
        assert_eq!(token_from_headers(&h, "st_session"), Some("abc"));
        assert_eq!(token_from_headers(&h, "__Host-st_session"), None);
        let mut empty = HeaderMap::new();
        empty.append(header::COOKIE, HeaderValue::from_static("st_session="));
        assert_eq!(token_from_headers(&empty, "st_session"), None);
    }
}
