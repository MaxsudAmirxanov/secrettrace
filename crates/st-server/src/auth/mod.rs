//! Authentication and authorization.
//!
//! Humans: password (argon2id) → short-lived pre-MFA session → TOTP → full session.
//! The session token is rotated after MFA (session fixation). Cookies are
//! `HttpOnly; SameSite=Strict` (+ `Secure` and the `__Host-` prefix in production);
//! state-changing requests additionally need `X-CSRF-Token`.
//!
//! Machines (agents, CI): `Authorization: Bearer stk_…` API tokens with scopes;
//! mTLS client certificates are added at the edge in a later stage.

pub mod extract;
pub mod password;
pub mod ratelimit;
pub mod role;
pub mod session;
pub mod tokens;
pub mod totp;

use std::net::IpAddr;
use std::time::Duration;

pub use extract::{CLIENT_CN_HEADER, CurrentUser, FromTrustedProxy, RequestMeta, SessionAuth, TokenPrincipal};
pub use role::Role;

/// Failed password/TOTP attempts before the account is locked.
pub const MAX_FAILED_ATTEMPTS: i32 = 5;
pub const LOCKOUT: Duration = Duration::from_secs(15 * 60);
/// Lifetime of the session between password and TOTP.
pub const PRE_MFA_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone)]
pub struct AuthSettings {
    pub session_ttl: Duration,
    pub session_idle: Duration,
    pub cookie_secure: bool,
    pub totp_issuer: String,
    /// Reverse proxies whose `X-Forwarded-For` and client-certificate header are trusted.
    pub trusted_proxies: Vec<IpAddr>,
    /// Every API token must be bound to a client certificate (`cert_cn`) and arrive through
    /// the mTLS proxy with it. Bound tokens are checked either way.
    pub require_client_cert: bool,
}

impl AuthSettings {
    #[must_use]
    pub const fn cookie_name(&self) -> &'static str {
        // `__Host-` cookies must be Secure, Path=/ and have no Domain: they cannot be
        // set or overwritten by a sibling subdomain.
        if self.cookie_secure { "__Host-st_session" } else { "st_session" }
    }
}
