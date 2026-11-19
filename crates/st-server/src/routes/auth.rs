//! `/api/v1/auth/*` — login, TOTP enrollment/verification, logout, current user.
//!
//! All failures return the same generic 401 so responses do not reveal whether an
//! account exists, is locked or disabled; the precise reason goes to the audit log.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::app::AppState;
use crate::audit;
use crate::auth::session::{self, NewSession};
use crate::auth::{CurrentUser, RequestMeta, Role, SessionAuth, password, totp};
use crate::error::{ApiError, ApiResult, Problem};
use crate::extract::ApiJson;
use crate::users;

// Debug is safe: SecretString redacts itself.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    username: String,
    #[schema(value_type = String, format = Password)]
    password: SecretString,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LoginResponse {
    pub mfa_required: bool,
    pub mfa_enrolled: bool,
    pub csrf_token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EnrollResponse {
    pub otpauth_uri: String,
    pub secret: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    #[schema(value_type = String, example = "123456")]
    code: SecretString,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MeResponse {
    pub id: Uuid,
    pub username: String,
    pub role: Role,
    pub csrf_token: String,
}

fn with_cookie(state: &AppState, new: &NewSession, status: StatusCode, body: impl Serialize) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, session::set_cookie(&state.auth, new));
    (status, headers, Json(body)).into_response()
}

/// `POST /auth/login` — step 1: password. Issues a 5-minute pre-MFA session.
#[utoipa::path(post, path = "/api/v1/auth/login", tag = "auth", request_body = LoginRequest,
    responses((status = 200, description = "Password accepted; pre-MFA session cookie set", body = LoginResponse),
              (status = 401, body = Problem, content_type = "application/problem+json"), (status = 429, body = Problem, content_type = "application/problem+json")))]
pub async fn login(
    State(state): State<AppState>,
    meta: RequestMeta,
    ApiJson(req): ApiJson<LoginRequest>,
) -> ApiResult<Response> {
    let username = req.username.trim();
    if !users::valid_username(username) || req.password.expose_secret().len() > password::MAX_PASSWORD_BYTES {
        return Err(ApiError::Unauthorized);
    }
    let ip_key = format!("ip:{}", meta.ip.map_or_else(|| "unknown".into(), |ip| ip.to_string()));
    let user_key = format!("user:{}", username.to_lowercase());
    if !state.limiters.login_per_ip.check(&ip_key) || !state.limiters.login_per_user.check(&user_key) {
        return Err(ApiError::TooManyRequests);
    }

    let mut conn = state.db.acquire().await?;
    let user = users::find_by_username(&mut conn, username).await?;
    drop(conn);
    let pw = Zeroizing::new(req.password.expose_secret().to_owned());
    let password_ok = password::verify_blocking(pw, user.as_ref().map(|u| u.password_hash.clone())).await?;

    let mut tx = state.db.begin().await?;
    let Some(user) = user else {
        // The attempted username is not logged: users sometimes type a password into it.
        let ev = meta.event(audit::ActorType::User, "unknown".into(), "auth.login.failed");
        audit::record(&mut tx, &ev.details(json!({ "reason": "unknown_user" }))).await?;
        tx.commit().await?;
        return Err(ApiError::Unauthorized);
    };

    let reason = if !user.is_active {
        Some("disabled")
    } else if user.is_locked() {
        Some("locked")
    } else if !password_ok {
        Some("bad_password")
    } else {
        None
    };
    if let Some(reason) = reason {
        let now_locked =
            if reason == "bad_password" { users::register_failure(&mut tx, user.id).await? } else { false };
        let ev = meta.user_event(user.id, "auth.login.failed");
        audit::record(&mut tx, &ev.details(json!({ "reason": reason, "locked": now_locked }))).await?;
        tx.commit().await?;
        if now_locked {
            tracing::warn!(user_id = %user.id, "account locked after repeated failures");
        }
        return Err(ApiError::Unauthorized);
    }

    session::delete_expired(&mut tx).await?;
    let new = session::create(&mut tx, user.id, false, meta.ip, meta.user_agent.as_deref(), &state.auth).await?;
    audit::record(&mut tx, &meta.user_event(user.id, "auth.login.password_ok")).await?;
    tx.commit().await?;

    let body = LoginResponse { mfa_required: true, mfa_enrolled: user.mfa_enabled, csrf_token: new.csrf_token.clone() };
    Ok(with_cookie(&state, &new, StatusCode::OK, body))
}

/// `POST /auth/mfa/enroll` — first login only: create a TOTP seed (stored encrypted,
/// activated by the first successful `verify`). Re-enrollment requires an admin reset.
#[utoipa::path(post, path = "/api/v1/auth/mfa/enroll", tag = "auth",
    responses((status = 200, body = EnrollResponse), (status = 401, body = Problem, content_type = "application/problem+json"), (status = 409, description = "Already enrolled", body = Problem, content_type = "application/problem+json")),
    security(("session" = [], "csrf" = [])))]
pub async fn mfa_enroll(State(state): State<AppState>, meta: RequestMeta, auth: SessionAuth) -> ApiResult<Response> {
    if auth.session.mfa_passed || auth.session.mfa_enabled {
        return Err(ApiError::Conflict("MFA is already enrolled".into()));
    }
    let user_id = auth.session.user_id;
    let seed = totp::generate_secret();
    let encrypted = state.data_key.encrypt(&seed, user_id.as_bytes()).map_err(anyhow::Error::from)?;

    let mut tx = state.db.begin().await?;
    let updated =
        sqlx::query("UPDATE users SET totp_secret_enc = $2, totp_last_step = NULL WHERE id = $1 AND NOT mfa_enabled")
            .bind(user_id)
            .bind(&encrypted)
            .execute(&mut *tx)
            .await?
            .rows_affected();
    if updated == 0 {
        return Err(ApiError::Conflict("MFA is already enrolled".into()));
    }
    audit::record(&mut tx, &meta.user_event(user_id, "auth.mfa.enroll_started")).await?;
    tx.commit().await?;

    let body = EnrollResponse {
        otpauth_uri: totp::otpauth_uri(&state.auth.totp_issuer, &auth.session.username, &seed),
        secret: totp::base32(&seed),
    };
    Ok((StatusCode::OK, Json(body)).into_response())
}

/// `POST /auth/mfa/verify` — step 2: TOTP. On success the pre-MFA session is replaced
/// by a fresh full session (new token, new CSRF token).
#[utoipa::path(post, path = "/api/v1/auth/mfa/verify", tag = "auth", request_body = VerifyRequest,
    responses((status = 200, description = "Full session cookie set (token rotated)", body = MeResponse),
              (status = 401, body = Problem, content_type = "application/problem+json"), (status = 409, body = Problem, content_type = "application/problem+json"), (status = 429, body = Problem, content_type = "application/problem+json")),
    security(("session" = [], "csrf" = [])))]
pub async fn mfa_verify(
    State(state): State<AppState>,
    meta: RequestMeta,
    auth: SessionAuth,
    ApiJson(req): ApiJson<VerifyRequest>,
) -> ApiResult<Response> {
    if auth.session.mfa_passed {
        return Err(ApiError::Conflict("session is already verified".into()));
    }
    let user_id = auth.session.user_id;
    if !state.limiters.mfa_per_user.check(&user_id.to_string()) {
        return Err(ApiError::TooManyRequests);
    }

    let mut tx = state.db.begin().await?;
    let user = users::find_by_id_for_update(&mut tx, user_id).await?.ok_or(ApiError::Unauthorized)?;
    let seed = user
        .totp_secret_enc
        .as_deref()
        .ok_or_else(|| ApiError::Conflict("MFA is not enrolled; call /auth/mfa/enroll first".into()))?;
    let seed = state.data_key.decrypt(seed, user_id.as_bytes()).map_err(anyhow::Error::from)?;

    let step = if user.is_active && !user.is_locked() {
        totp::verify(&seed, req.code.expose_secret(), Utc::now().timestamp(), user.totp_last_step)
    } else {
        None
    };
    let Some(step) = step else {
        let locked = users::register_failure(&mut tx, user_id).await?;
        audit::record(&mut tx, &meta.user_event(user_id, "auth.mfa.failed").details(json!({ "locked": locked })))
            .await?;
        tx.commit().await?;
        return Err(ApiError::Unauthorized);
    };

    let enrolled_now = !user.mfa_enabled;
    sqlx::query(
        "UPDATE users SET totp_last_step = $2, mfa_enabled = true, failed_logins = 0, locked_until = NULL,
                          last_login_at = now()
         WHERE id = $1",
    )
    .bind(user_id)
    .bind(step)
    .execute(&mut *tx)
    .await?;
    session::delete(&mut tx, &auth.session.token_hash).await?;
    let new = session::create(&mut tx, user_id, true, meta.ip, meta.user_agent.as_deref(), &state.auth).await?;
    let ev = meta.user_event(user_id, "auth.login.success").details(json!({ "mfa_enrolled_now": enrolled_now }));
    audit::record(&mut tx, &ev).await?;
    tx.commit().await?;

    let body = MeResponse { id: user_id, username: user.username, role: user.role, csrf_token: new.csrf_token.clone() };
    Ok(with_cookie(&state, &new, StatusCode::OK, body))
}

/// `POST /auth/logout` — works for pre-MFA and full sessions.
#[utoipa::path(post, path = "/api/v1/auth/logout", tag = "auth",
    responses((status = 204, description = "Session deleted, cookie cleared"), (status = 401, body = Problem, content_type = "application/problem+json"), (status = 403, body = Problem, content_type = "application/problem+json")),
    security(("session" = [], "csrf" = [])))]
pub async fn logout(State(state): State<AppState>, meta: RequestMeta, auth: SessionAuth) -> ApiResult<Response> {
    let mut tx = state.db.begin().await?;
    session::delete(&mut tx, &auth.session.token_hash).await?;
    audit::record(&mut tx, &meta.user_event(auth.session.user_id, "auth.logout")).await?;
    tx.commit().await?;
    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, session::clear_cookie(&state.auth));
    Ok((StatusCode::NO_CONTENT, headers).into_response())
}

/// `GET /auth/me` — current user and the CSRF token for this session (lets the SPA
/// recover the token after a page reload).
#[utoipa::path(get, path = "/api/v1/auth/me", tag = "auth",
    responses((status = 200, body = MeResponse), (status = 401, body = Problem, content_type = "application/problem+json")), security(("session" = [])))]
pub async fn me(user: CurrentUser) -> Json<MeResponse> {
    Json(MeResponse { id: user.id, username: user.username, role: user.role, csrf_token: user.session.csrf_token })
}
