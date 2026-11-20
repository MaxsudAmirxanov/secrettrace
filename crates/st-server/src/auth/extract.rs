//! Axum extractors for request metadata and authenticated principals.

use std::net::{IpAddr, SocketAddr};

use axum::extract::connect_info::MockConnectInfo;
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{Method, header};
use uuid::Uuid;

use super::session::{self, SessionRecord};
use super::{Role, tokens};
use crate::app::AppState;
use crate::audit::{ActorType, AuditEvent};
use crate::error::ApiError;
use crate::model::SourceType;

const MAX_USER_AGENT: usize = 256;

/// Address of the TCP peer (`MockConnectInfo` in tests).
fn peer_ip(parts: &Parts) -> Option<IpAddr> {
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
        .or_else(|| parts.extensions.get::<MockConnectInfo<SocketAddr>>().map(|c| c.0.ip()))
}

/// Whether the TCP peer is one of `ST_TRUSTED_PROXIES` (the edge).
#[derive(Debug, Clone, Copy)]
pub struct FromTrustedProxy(pub bool);

impl FromRequestParts<AppState> for FromTrustedProxy {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        Ok(Self(peer_ip(parts).is_some_and(|p| state.auth.trusted_proxies.contains(&p))))
    }
}

/// Header the mTLS proxy sets to the CN of the client certificate it verified. Only read
/// from `trusted_proxies`; the proxy's other listeners clear it.
pub const CLIENT_CN_HEADER: &str = "x-secrettrace-client-cn";

/// The verified client-certificate CN, if the request came through a trusted proxy that
/// sent one. Anything else (direct connections, malformed values) is "no certificate".
fn client_cn(parts: &Parts, trusted_proxies: &[IpAddr]) -> Option<String> {
    let peer = peer_ip(parts)?;
    if !trusted_proxies.contains(&peer) {
        return None;
    }
    let mut values = parts.headers.get_all(CLIENT_CN_HEADER).iter();
    let (first, second) = (values.next(), values.next());
    // Exactly one value: a repeated header means something upstream is confused.
    let cn = first.filter(|_| second.is_none())?.to_str().ok()?;
    tokens::valid_cert_cn(cn).then(|| cn.to_owned())
}

/// Client address, request id and user agent for auditing.
#[derive(Debug, Clone)]
pub struct RequestMeta {
    pub ip: Option<IpAddr>,
    pub request_id: Option<String>,
    pub user_agent: Option<String>,
}

impl RequestMeta {
    fn from_parts(parts: &Parts, trusted_proxies: &[IpAddr]) -> Self {
        let ip = match peer_ip(parts) {
            // Behind a trusted proxy: the right-most X-Forwarded-For entry is the one
            // the proxy itself appended, i.e. the address it saw.
            Some(p) if trusted_proxies.contains(&p) => parts
                .headers
                .get_all("x-forwarded-for")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(','))
                .filter_map(|s| s.trim().parse::<IpAddr>().ok())
                .next_back()
                .or(Some(p)),
            other => other,
        };
        let header_str = |name| parts.headers.get(name).and_then(|v| v.to_str().ok());
        Self {
            ip,
            request_id: header_str("x-request-id").map(str::to_owned),
            user_agent: header_str(header::USER_AGENT.as_str()).map(|ua| ua.chars().take(MAX_USER_AGENT).collect()),
        }
    }

    /// Audit event attributed to a user.
    #[must_use]
    pub fn user_event(&self, user_id: Uuid, action: &str) -> AuditEvent {
        self.event(ActorType::User, user_id.to_string(), action)
    }

    #[must_use]
    pub fn event(&self, actor_type: ActorType, actor_id: String, action: &str) -> AuditEvent {
        AuditEvent {
            actor_type,
            actor_id,
            action: action.to_owned(),
            target_type: None,
            target_id: None,
            ip: self.ip,
            request_id: self.request_id.clone(),
            details: serde_json::Value::Object(serde_json::Map::new()),
        }
    }
}

impl FromRequestParts<AppState> for RequestMeta {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        Ok(Self::from_parts(parts, &state.auth.trusted_proxies))
    }
}

/// Any live session, including the short pre-MFA one. Enforces CSRF on
/// state-changing methods.
#[derive(Debug, Clone)]
pub struct SessionAuth {
    pub session: SessionRecord,
    pub csrf_token: String,
}

impl FromRequestParts<AppState> for SessionAuth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let token =
            session::token_from_headers(&parts.headers, state.auth.cookie_name()).ok_or(ApiError::Unauthorized)?;
        let record = session::lookup(&state.db, token, state.auth.session_idle).await?.ok_or(ApiError::Unauthorized)?;

        if !matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS) {
            let presented = parts.headers.get("x-csrf-token").and_then(|v| v.to_str().ok()).unwrap_or_default();
            if !tokens::csrf_matches(token, presented) {
                return Err(ApiError::Forbidden);
            }
        }
        Ok(Self { csrf_token: tokens::csrf_for_session(token), session: record })
    }
}

/// A fully authenticated (password + TOTP) user.
#[derive(Debug, Clone)]
pub struct CurrentUser {
    pub id: Uuid,
    pub username: String,
    pub role: Role,
    pub session: SessionAuth,
}

impl CurrentUser {
    pub fn require(&self, role: Role) -> Result<(), ApiError> {
        if self.role.allows(role) { Ok(()) } else { Err(ApiError::Forbidden) }
    }
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let auth = SessionAuth::from_request_parts(parts, state).await?;
        if !auth.session.mfa_passed {
            return Err(ApiError::Unauthorized);
        }
        Ok(Self {
            id: auth.session.user_id,
            username: auth.session.username.clone(),
            role: auth.session.role,
            session: auth,
        })
    }
}

/// A machine client authenticated with an API token.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TokenPrincipal {
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    pub token_prefix: String,
    pub scopes: Vec<String>,
    pub cert_cn: Option<String>,
    /// Bindings: the token may only report this source type, URIs matching this glob,
    /// and only under this environment.
    pub source_type: Option<SourceType>,
    pub source_uri_pattern: Option<String>,
    pub environment: Option<String>,
}

impl TokenPrincipal {
    pub fn require_scope(&self, scope: &str) -> Result<(), ApiError> {
        if self.scopes.iter().any(|s| s == scope) { Ok(()) } else { Err(ApiError::Forbidden) }
    }
}

impl FromRequestParts<AppState> for TokenPrincipal {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim)
            .filter(|t| tokens::looks_like_api_token(t))
            .ok_or(ApiError::Unauthorized)?;

        let hash = tokens::hash_token(token);
        let cn = client_cn(parts, &state.auth.trusted_proxies);
        // A bound token needs its certificate; with `require_client_cert` every token must
        // be bound. Checked in the same statement, so a refused request is not "last use".
        let principal: Option<TokenPrincipal> = sqlx::query_as(
            "UPDATE api_tokens SET last_used_at = now()
             WHERE token_hash = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())
               AND (cert_cn IS NULL OR cert_cn = $2) AND (cert_cn IS NOT NULL OR NOT $3)
             RETURNING id, name, kind, token_prefix, scopes, cert_cn, source_type, source_uri_pattern, environment",
        )
        .bind(hash.as_slice())
        .bind(cn.as_deref())
        .bind(state.auth.require_client_cert)
        .fetch_optional(&state.db)
        .await?;
        if let Some(p) = principal {
            return Ok(p);
        }
        // Refused: say why in the server log (never to the client), for operators chasing a 401.
        let live: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT token_prefix, cert_cn FROM api_tokens
             WHERE token_hash = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())",
        )
        .bind(hash.as_slice())
        .fetch_optional(&state.db)
        .await?;
        if let Some((prefix, bound)) = live {
            let reason = match (&bound, &cn) {
                (None, _) => "the server requires tokens bound to a client certificate",
                (Some(_), None) => "no verified client certificate (use the mTLS endpoint)",
                (Some(_), Some(_)) => "client certificate CN does not match the token",
            };
            tracing::warn!(token = %prefix, presented_cn = cn.as_deref().unwrap_or("-"), reason, "API token refused");
        }
        Err(ApiError::Unauthorized)
    }
}
