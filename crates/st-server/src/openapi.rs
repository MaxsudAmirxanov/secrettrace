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
        routes::auth::change_password,
        routes::users::list,
        routes::users::create,
        routes::users::update,
        routes::users::reset_mfa,
        routes::users::unlock,
        routes::users::reset_password,
        routes::audit::list,
        routes::audit::verify,
        routes::overview::overview,
        routes::overview::locations,
        routes::api_tokens::list,
        routes::api_tokens::create,
        routes::api_tokens::revoke,
        routes::secrets::list,
        routes::secrets::create,
        routes::secrets::get,
        routes::secrets::update,
        routes::secrets::locations,
        routes::ingest::start,
        routes::ingest::match_digests,
        routes::ingest::findings,
        routes::ingest::complete,
        routes::sources::list,
        routes::sources::create,
        routes::sources::get,
        routes::sources::update,
        routes::sources::delete,
        routes::sources::enqueue_scan,
        routes::scans::list,
        routes::scans::get,
        routes::scans::cancel,
        routes::canaries::list,
        routes::canaries::create,
        routes::canaries::get,
        routes::canaries::update,
    ),
    modifiers(&SecuritySchemes),
    tags(
        (name = "auth", description = "Password + mandatory TOTP login, sessions"),
        (name = "secrets", description = "Registry of tracked secrets"),
        (name = "api-tokens", description = "Machine credentials for agents and CI (admin)"),
        (name = "ingest", description = "Scan results from agents and CI (API tokens): match digests, report locations"),
        (name = "sources", description = "Sources to scan: git repositories with schedule and credential reference"),
        (name = "scans", description = "Scan jobs: server-side (manual, scheduled) and reported by API tokens"),
        (name = "canaries", description = "Canary tokens: bait whose use or discovery is a leak"),
        (name = "overview", description = "Dashboard numbers and the list of all findings"),
        (name = "users", description = "User administration (admin)"),
        (name = "audit", description = "Audit log and hash-chain verification (admin)"),
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
