//! `/api/v1/users` — user administration (admin only).
//!
//! Guard rails: an admin cannot change their own role or status, reset their own MFA or
//! password here (that would lock them out mid-session), and the last active admin can be
//! neither demoted nor disabled. Passwords are never returned or audited.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sqlx::PgConnection;
use utoipa::ToSchema;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::app::AppState;
use crate::audit;
use crate::auth::{CurrentUser, RequestMeta, Role, password, session};
use crate::error::{ApiError, ApiResult, Problem};
use crate::extract::{ApiJson, ApiPath};
use crate::users::{self, CreateUserError};

#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct UserOut {
    pub id: Uuid,
    pub username: String,
    pub role: Role,
    /// TOTP enrolled. Until then the user enrolls at the next login.
    pub mfa_enabled: bool,
    pub is_active: bool,
    /// Temporarily locked after repeated failed logins.
    pub is_locked: bool,
    pub locked_until: Option<DateTime<Utc>>,
    pub failed_logins: i32,
    pub created_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

const USER_COLUMNS: &str = "id, username::text AS username, role, mfa_enabled, is_active,
    (locked_until IS NOT NULL AND locked_until > now()) AS is_locked, locked_until, failed_logins,
    created_at, last_login_at";

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UserCreate {
    #[schema(example = "alice", pattern = "^[A-Za-z0-9._@-]{1,64}$")]
    pub username: String,
    pub role: Role,
    /// Initial password (at least 12 characters). TOTP is enrolled at first login.
    #[schema(value_type = String, format = Password)]
    pub password: SecretString,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UserUpdate {
    #[serde(default)]
    pub role: Option<Role>,
    /// `false` disables the account and ends its sessions.
    #[serde(default)]
    pub is_active: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PasswordReset {
    #[schema(value_type = String, format = Password)]
    pub password: SecretString,
}

async fn fetch(conn: &mut PgConnection, id: Uuid) -> Result<Option<UserOut>, sqlx::Error> {
    sqlx::query_as(&format!("SELECT {USER_COLUMNS} FROM users WHERE id = $1")).bind(id).fetch_optional(conn).await
}

fn not_self(user: &CurrentUser, id: Uuid, what: &str) -> Result<(), ApiError> {
    if user.id == id {
        return Err(ApiError::Conflict(format!("you cannot {what} your own account here")));
    }
    Ok(())
}

/// List users.
#[utoipa::path(get, path = "/api/v1/users", tag = "users",
    responses((status = 200, body = Vec<UserOut>), (status = 403, body = Problem, content_type = "application/problem+json")),
    security(("session" = [])))]
pub async fn list(State(state): State<AppState>, user: CurrentUser) -> ApiResult<Json<Vec<UserOut>>> {
    user.require(Role::Admin)?;
    let rows =
        sqlx::query_as(&format!("SELECT {USER_COLUMNS} FROM users ORDER BY username")).fetch_all(&state.db).await?;
    Ok(Json(rows))
}

/// Create a user with an initial password; TOTP enrollment happens at their first login.
#[utoipa::path(post, path = "/api/v1/users", tag = "users", request_body = UserCreate,
    responses((status = 201, body = UserOut), (status = 403, body = Problem, content_type = "application/problem+json"),
              (status = 409, description = "Username taken", body = Problem, content_type = "application/problem+json"),
              (status = 422, description = "Invalid username or weak password", body = Problem, content_type = "application/problem+json")),
    security(("session" = [], "csrf" = [])))]
pub async fn create(
    State(state): State<AppState>,
    meta: RequestMeta,
    user: CurrentUser,
    ApiJson(req): ApiJson<UserCreate>,
) -> ApiResult<(StatusCode, Json<UserOut>)> {
    user.require(Role::Admin)?;
    let username = req.username.trim();
    let pw = Zeroizing::new(req.password.expose_secret().to_owned());
    let mut tx = state.db.begin().await?;
    let id =
        users::create(&mut tx, username, pw, req.role, meta.user_event(user.id, "user.create")).await.map_err(|e| {
            match e {
                CreateUserError::InvalidUsername | CreateUserError::Policy(_) => ApiError::Unprocessable(e.to_string()),
                CreateUserError::Exists => ApiError::Conflict(e.to_string()),
                CreateUserError::Db(e) => ApiError::Database(e),
                CreateUserError::Audit(e) => ApiError::Audit(e),
                CreateUserError::Other(e) => ApiError::Internal(e),
            }
        })?;
    let out = fetch(&mut tx, id).await?.ok_or(ApiError::NotFound)?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(out)))
}

/// Change a user's role or enable/disable the account.
#[utoipa::path(patch, path = "/api/v1/users/{id}", tag = "users", params(("id" = Uuid, Path)), request_body = UserUpdate,
    responses((status = 200, body = UserOut), (status = 404, body = Problem, content_type = "application/problem+json"),
              (status = 409, description = "Own account, or the last active admin", body = Problem, content_type = "application/problem+json")),
    security(("session" = [], "csrf" = [])))]
pub async fn update(
    State(state): State<AppState>,
    meta: RequestMeta,
    user: CurrentUser,
    ApiPath(id): ApiPath<Uuid>,
    ApiJson(req): ApiJson<UserUpdate>,
) -> ApiResult<Json<UserOut>> {
    user.require(Role::Admin)?;
    let mut tx = state.db.begin().await?;
    // Serialize admin changes: the "last active admin" check below must see a stable set.
    let admins: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM users WHERE role = 'admin' AND is_active ORDER BY id FOR UPDATE")
            .fetch_all(&mut *tx)
            .await?;
    let current = fetch(&mut tx, id).await?.ok_or(ApiError::NotFound)?;

    let role = req.role.filter(|r| *r != current.role);
    let active = req.is_active.filter(|a| *a != current.is_active);
    if role.is_none() && active.is_none() {
        tx.commit().await?;
        return Ok(Json(current));
    }
    not_self(&user, id, "change the role or status of")?;
    let loses_admin = current.role == Role::Admin
        && current.is_active
        && (role.is_some_and(|r| r != Role::Admin) || active == Some(false));
    if loses_admin && admins.iter().filter(|a| **a != id).count() == 0 {
        return Err(ApiError::Conflict("the last active admin cannot be demoted or disabled".into()));
    }

    sqlx::query("UPDATE users SET role = COALESCE($2, role), is_active = COALESCE($3, is_active) WHERE id = $1")
        .bind(id)
        .bind(role)
        .bind(active)
        .execute(&mut *tx)
        .await?;
    if active == Some(false) {
        session::delete_all_for_user(&mut tx, id).await?;
    }
    let mut changes = Map::new();
    if let Some(r) = role {
        changes.insert("role".into(), json!({ "from": current.role, "to": r }));
    }
    if let Some(a) = active {
        changes.insert("is_active".into(), Value::Bool(a));
    }
    let ev = meta.user_event(user.id, "user.update").target("user", id.to_string()).details(Value::Object(changes));
    audit::record(&mut tx, &ev).await?;
    let out = fetch(&mut tx, id).await?.ok_or(ApiError::NotFound)?;
    tx.commit().await?;
    Ok(Json(out))
}

/// Remove the user's TOTP enrollment and end their sessions; they enroll again at next login.
#[utoipa::path(post, path = "/api/v1/users/{id}/reset-mfa", tag = "users", params(("id" = Uuid, Path)),
    responses((status = 200, body = UserOut), (status = 404, body = Problem, content_type = "application/problem+json"),
              (status = 409, description = "Own account", body = Problem, content_type = "application/problem+json")),
    security(("session" = [], "csrf" = [])))]
pub async fn reset_mfa(
    State(state): State<AppState>,
    meta: RequestMeta,
    user: CurrentUser,
    ApiPath(id): ApiPath<Uuid>,
) -> ApiResult<Json<UserOut>> {
    user.require(Role::Admin)?;
    not_self(&user, id, "reset MFA of")?;
    let mut tx = state.db.begin().await?;
    fetch(&mut tx, id).await?.ok_or(ApiError::NotFound)?;
    users::reset_mfa(&mut tx, id).await?;
    audit::record(&mut tx, &meta.user_event(user.id, "user.mfa_reset").target("user", id.to_string())).await?;
    let out = fetch(&mut tx, id).await?.ok_or(ApiError::NotFound)?;
    tx.commit().await?;
    Ok(Json(out))
}

/// Clear the failed-login counter and lock.
#[utoipa::path(post, path = "/api/v1/users/{id}/unlock", tag = "users", params(("id" = Uuid, Path)),
    responses((status = 200, body = UserOut), (status = 404, body = Problem, content_type = "application/problem+json")),
    security(("session" = [], "csrf" = [])))]
pub async fn unlock(
    State(state): State<AppState>,
    meta: RequestMeta,
    user: CurrentUser,
    ApiPath(id): ApiPath<Uuid>,
) -> ApiResult<Json<UserOut>> {
    user.require(Role::Admin)?;
    let mut tx = state.db.begin().await?;
    fetch(&mut tx, id).await?.ok_or(ApiError::NotFound)?;
    users::reset_failures(&mut tx, id).await?;
    audit::record(&mut tx, &meta.user_event(user.id, "user.unlock").target("user", id.to_string())).await?;
    let out = fetch(&mut tx, id).await?.ok_or(ApiError::NotFound)?;
    tx.commit().await?;
    Ok(Json(out))
}

/// Set a new password for another user, unlock the account and end its sessions.
#[utoipa::path(post, path = "/api/v1/users/{id}/password", tag = "users", params(("id" = Uuid, Path)),
    request_body = PasswordReset,
    responses((status = 200, body = UserOut), (status = 404, body = Problem, content_type = "application/problem+json"),
              (status = 409, description = "Own account: use /auth/password", body = Problem, content_type = "application/problem+json"),
              (status = 422, description = "Weak password", body = Problem, content_type = "application/problem+json")),
    security(("session" = [], "csrf" = [])))]
pub async fn reset_password(
    State(state): State<AppState>,
    meta: RequestMeta,
    user: CurrentUser,
    ApiPath(id): ApiPath<Uuid>,
    ApiJson(req): ApiJson<PasswordReset>,
) -> ApiResult<Json<UserOut>> {
    user.require(Role::Admin)?;
    not_self(&user, id, "reset the password of")?;
    let mut conn = state.db.acquire().await?;
    let target = fetch(&mut conn, id).await?.ok_or(ApiError::NotFound)?;
    drop(conn);
    password::check_policy(&target.username, req.password.expose_secret())
        .map_err(|e| ApiError::Unprocessable(e.to_string()))?;
    let phc = password::hash_blocking(Zeroizing::new(req.password.expose_secret().to_owned())).await?;

    let mut tx = state.db.begin().await?;
    users::set_password(&mut tx, id, &phc).await?;
    users::reset_failures(&mut tx, id).await?;
    session::delete_all_for_user(&mut tx, id).await?;
    audit::record(&mut tx, &meta.user_event(user.id, "user.password_reset").target("user", id.to_string())).await?;
    let out = fetch(&mut tx, id).await?.ok_or(ApiError::NotFound)?;
    tx.commit().await?;
    Ok(Json(out))
}
