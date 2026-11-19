//! OpenAPI 3.1 document generated from handler annotations.
//!
//! Served at `GET /api/v1/openapi.json` and committed as `docs/openapi.json`
//! (a test fails when the committed file is stale; regenerate with
//! `UPDATE_OPENAPI=1 cargo test -p st-server --test openapi`).

use utoipa::openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::routes;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "SecretTrace API",
        description = "Secrets lifecycle tracking. Plaintext secret values never reach this API: \
                       clients send `SHA-256(\"secrettrace/v1\\0\" || normalize(value))`.",
        license(name = "Proprietary")
    ),
    paths(
        routes::health::healthz,
        routes::health::readyz,
        routes::auth::login,
        routes::auth::mfa_enroll,
        routes::auth::mfa_verify,
        routes::auth::logout,
        routes::auth::me,
        routes::api_tokens::list,
        routes::api_tokens::create,
        routes::api_tokens::revoke,
        routes::secrets::list,
        routes::secrets::create,
        routes::secrets::get,
        routes::secrets::update,
        routes::secrets::locations,
    ),
    modifiers(&SecuritySchemes),
    tags(
        (name = "auth", description = "Password + mandatory TOTP login, sessions"),
        (name = "secrets", description = "Registry of tracked secrets"),
        (name = "api-tokens", description = "Machine credentials for agents and CI (admin)"),
        (name = "health", description = "Liveness and readiness probes"),
    )
)]
#[derive(Debug)]
pub struct ApiDoc;

struct SecuritySchemes;

impl Modify for SecuritySchemes {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "session",
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::with_description(
                "__Host-st_session",
                "Session cookie (`st_session` when ST_COOKIE_SECURE=false)",
            ))),
        );
        components.add_security_scheme(
            "csrf",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                "X-CSRF-Token",
                "Required on POST/PATCH/DELETE with a session; returned by login, verify and /auth/me",
            ))),
        );
        components.add_security_scheme(
            "token",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("stk_<id>_<secret>")
                    .description(Some("API token for agents and CI"))
                    .build(),
            ),
        );
    }
}

/// Pretty JSON of the document (stable output for the committed copy).
#[must_use]
pub fn json() -> String {
    ApiDoc::openapi().to_pretty_json().unwrap_or_default()
}
