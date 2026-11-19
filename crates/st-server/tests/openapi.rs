//! The committed `docs/openapi.json` must match the code.
//! Regenerate: `UPDATE_OPENAPI=1 cargo test -p st-server --test openapi`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::Value;

const SPEC_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/openapi.json");

#[test]
fn committed_spec_is_up_to_date() {
    let current = st_server::openapi::json() + "\n";
    if std::env::var_os("UPDATE_OPENAPI").is_some() {
        std::fs::write(SPEC_PATH, &current).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(SPEC_PATH).unwrap_or_default();
    assert!(
        committed == current,
        "docs/openapi.json is stale; run: UPDATE_OPENAPI=1 cargo test -p st-server --test openapi"
    );
}

#[test]
fn spec_covers_routes_and_security() {
    let spec: Value = serde_json::from_str(&st_server::openapi::json()).unwrap();
    assert_eq!(spec["openapi"].as_str().map(|v| v.starts_with("3.1")), Some(true));
    let paths = spec["paths"].as_object().unwrap();
    for p in [
        "/api/v1/auth/login",
        "/api/v1/auth/mfa/verify",
        "/api/v1/secrets",
        "/api/v1/secrets/{id}",
        "/api/v1/secrets/{id}/locations",
        "/api/v1/api-tokens/{id}",
    ] {
        assert!(paths.contains_key(p), "missing {p}");
    }

    // Every operation except the public ones declares security; every mutation needs CSRF.
    let public = ["/healthz", "/readyz", "/api/v1/auth/login"];
    for (path, item) in paths {
        for (method, op) in item.as_object().unwrap() {
            if public.contains(&path.as_str()) {
                continue;
            }
            let requirements = op
                .get("security")
                .and_then(Value::as_array)
                .unwrap_or_else(|| panic!("{method} {path} has no security"));
            if method != "get" {
                assert!(requirements.iter().any(|s| s.get("csrf").is_some()), "{method} {path} lacks csrf");
            }
        }
    }

    // Response models never carry digests or fingerprints.
    let schemas = spec["components"]["schemas"].as_object().unwrap();
    for name in ["SecretOut", "TokenInfo", "CreatedToken", "LocationOut"] {
        let s = schemas.get(name).unwrap_or_else(|| panic!("schema {name} missing")).to_string();
        for leak in ["\"digest\"", "\"fingerprint\"", "token_hash"] {
            assert!(!s.contains(leak), "{name} exposes {leak}");
        }
    }
    for scheme in ["session", "csrf", "token"] {
        assert!(spec["components"]["securitySchemes"].get(scheme).is_some(), "{scheme} scheme");
    }
}
