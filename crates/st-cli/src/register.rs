//! `secrettrace register`: register a secret by digest as a signed-in user.
//!
//! The registry is a human operation: it needs a user session with MFA (API tokens are
//! ingest-only). The value is read and hashed first and zeroized before anything is
//! sent; then the password and TOTP code are read from the terminal, the session is used
//! for one `POST /secrets` and logged out. Nothing is stored on disk.

use std::path::PathBuf;

use anyhow::{Context as _, bail};
use clap::Args;
use serde::{Deserialize, Serialize};
use st_core::{Hints, SecretType, prepare};
use zeroize::Zeroizing;

use crate::CliSecretType;
use crate::client::{Auth, Client, ServerArgs};

#[derive(Args)]
pub struct RegisterArgs {
    #[command(flatten)]
    server: ServerArgs,
    /// Your SecretTrace user name (operator or admin).
    #[arg(long, short = 'u', value_name = "NAME")]
    user: String,
    /// Registry name, e.g. `prod-aws-deploy-key`.
    #[arg(long)]
    name: String,
    #[arg(long = "type", value_enum)]
    secret_type: CliSecretType,
    /// Owning team or person.
    #[arg(long)]
    owner: String,
    #[arg(long)]
    purpose: Option<String>,
    /// Expiry: `YYYY-MM-DD` (midnight UTC) or an RFC 3339 timestamp.
    #[arg(long, value_name = "DATE")]
    expires: Option<String>,
    /// JSON file with allow rules: `[{"uri_pattern": "…", "path_pattern": "…",
    /// "environment": "…", "source_type": "…", "comment": "…"}]`. They can also be
    /// edited in the web UI later.
    #[arg(long, value_name = "FILE")]
    allow_rules: Option<PathBuf>,
    /// Read the secret value from stdin instead of a hidden prompt.
    #[arg(long)]
    stdin: bool,
}

#[derive(Serialize)]
struct LoginRequest<'a> {
    username: &'a str,
    password: &'a str,
}

#[derive(Deserialize)]
struct LoginResponse {
    mfa_enrolled: bool,
    csrf_token: String,
}

#[derive(Serialize)]
struct VerifyRequest<'a> {
    code: &'a str,
}

#[derive(Deserialize)]
struct MeResponse {
    csrf_token: String,
}

#[derive(Serialize)]
struct SecretCreate<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    secret_type: SecretType,
    owner: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    purpose: Option<&'a str>,
    digest: String,
    hints: &'a Hints,
    allow_rules: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct SecretOut {
    id: String,
    name: String,
    #[serde(rename = "type")]
    secret_type: String,
    owner: String,
    masked: String,
    status: String,
    expires_at: Option<String>,
}

pub fn run(args: &RegisterArgs) -> anyhow::Result<()> {
    // Validate everything that does not need the server before asking for anything.
    let client = Client::new(&args.server)?;
    let expires_at = args.expires.as_deref().map(expiry).transpose()?;
    let allow_rules = match &args.allow_rules {
        Some(path) => {
            let text = std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
            let rules: serde_json::Value =
                serde_json::from_str(&text).with_context(|| format!("{}: invalid JSON", path.display()))?;
            if !rules.is_array() {
                bail!("{}: allow rules must be a JSON array", path.display());
            }
            rules
        }
        None => serde_json::Value::Array(Vec::new()),
    };

    let secret_type = SecretType::from(args.secret_type);
    let value = crate::read_value(secret_type, args.stdin)?;
    let (digest, hints) = prepare(secret_type, &value).context("value rejected")?;
    drop(value); // zeroized here

    let password = Zeroizing::new(
        rpassword::prompt_password(format!("Password for {}: ", args.user)).context("cannot read from terminal")?,
    );
    let login = client
        .post::<LoginResponse>("/auth/login", Auth::None, &LoginRequest { username: &args.user, password: &password })
        .map_err(|e| anyhow::anyhow!("sign-in failed: {e}"))?;
    drop(password);
    let cookie = Zeroizing::new(login.set_cookie.context("the server did not set a session cookie")?);
    let pre = Session { client: &client, cookie, csrf: Zeroizing::new(login.body.csrf_token) };
    if !login.body.mfa_enrolled {
        pre.logout();
        bail!("this account has no TOTP yet: finish the first sign-in in the web UI");
    }

    let code = Zeroizing::new(rpassword::prompt_password("TOTP code: ").context("cannot read from terminal")?);
    let verified = client
        .post::<MeResponse>("/auth/mfa/verify", pre.auth(), &VerifyRequest { code: code.trim() })
        .map_err(|e| anyhow::anyhow!("sign-in failed: {e}"));
    drop(code);
    let verified = match verified {
        Ok(v) => v,
        Err(e) => {
            pre.logout();
            return Err(e);
        }
    };
    // The server rotates the session on MFA: the pre-MFA cookie is already dead.
    let session = Session {
        client: &client,
        cookie: Zeroizing::new(verified.set_cookie.context("the server did not set a session cookie")?),
        csrf: Zeroizing::new(verified.body.csrf_token),
    };

    let body = SecretCreate {
        name: &args.name,
        secret_type,
        owner: &args.owner,
        purpose: args.purpose.as_deref(),
        digest: digest.to_hex(),
        hints: &hints,
        allow_rules,
        expires_at,
    };
    let created = client.post::<SecretOut>("/secrets", session.auth(), &body);
    session.logout();
    let created = created.map_err(|e| match e.status.map(|s| s.as_u16()) {
        Some(403) => anyhow::anyhow!("{e} (registering secrets needs the operator or admin role)"),
        Some(409) => anyhow::anyhow!("{e} (this value or name is already registered)"),
        _ => anyhow::anyhow!("registration failed: {e}"),
    })?;
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, &created.body)?;
    std::io::Write::write_all(&mut stdout, b"\n")?;
    Ok(())
}

struct Session<'c> {
    client: &'c Client,
    cookie: Zeroizing<String>,
    csrf: Zeroizing<String>,
}

impl Session<'_> {
    fn auth(&self) -> Auth<'_> {
        Auth::Session { cookie: &self.cookie, csrf: &self.csrf }
    }

    /// Best effort: the session also expires on its own.
    fn logout(&self) {
        if let Err(e) = self.client.post_empty("/auth/logout", self.auth()) {
            eprintln!("secrettrace: logout failed: {e}");
        }
    }
}

/// `YYYY-MM-DD` → midnight UTC; anything with a `T` is passed through for the server to
/// parse as RFC 3339.
fn expiry(s: &str) -> anyhow::Result<String> {
    let s = s.trim();
    if s.contains('T') {
        return Ok(s.to_owned());
    }
    let parts: Vec<&str> = s.split('-').collect();
    let ok = matches!(parts.as_slice(), [y, m, d]
        if y.len() == 4 && m.len() == 2 && d.len() == 2
            && [y, m, d].iter().all(|p| p.bytes().all(|b| b.is_ascii_digit()))
            && (1..=12).contains(&m.parse::<u8>().unwrap_or(0))
            && (1..=31).contains(&d.parse::<u8>().unwrap_or(0)));
    if !ok {
        bail!("--expires must be YYYY-MM-DD or an RFC 3339 timestamp");
    }
    Ok(format!("{s}T00:00:00Z"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn expiry_dates() {
        assert_eq!(expiry("2027-01-31").unwrap(), "2027-01-31T00:00:00Z");
        assert_eq!(expiry("2027-01-31T12:00:00+03:00").unwrap(), "2027-01-31T12:00:00+03:00");
        assert!(expiry("2027-13-01").is_err());
        assert!(expiry("31.01.2027").is_err());
        assert!(expiry("tomorrow").is_err());
    }
}
