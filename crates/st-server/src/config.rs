//! Configuration from environment variables.
//!
//! Every sensitive variable `ST_X` may instead be given as `ST_X_FILE` pointing to a
//! file (Docker/Kubernetes secrets). Setting both is an error. Sensitive values are
//! wrapped in [`SecretString`], whose `Debug` output is redacted.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use secrecy::SecretString;

use crate::auth::AuthSettings;
use crate::crypto::aead::{AeadError, DataKey};
use crate::crypto::pepper::{Pepper, PepperError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Pretty,
}

#[derive(Debug)]
pub struct Config {
    pub listen_addr: SocketAddr,
    /// Runtime connection (least-privileged `st_app` role).
    pub database_url: SecretString,
    /// Connection used by `migrate` (schema owner). Falls back to `database_url`.
    pub migration_database_url: Option<SecretString>,
    pub db_max_connections: u32,
    pub pepper: Pepper,
    /// AES-256-GCM key for sensitive DB fields (TOTP seeds).
    pub data_key: DataKey,
    pub auth: AuthSettings,
    pub log_format: LogFormat,
    pub request_timeout: Duration,
    pub max_body_bytes: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("required variable {0} is not set")]
    Missing(&'static str),
    #[error("both {0} and {0}_FILE are set; use only one")]
    Ambiguous(&'static str),
    #[error("cannot read {var}_FILE ({path}): {source}")]
    File {
        var: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid value for {var}: {reason}")]
    Invalid { var: &'static str, reason: String },
    #[error("invalid pepper configuration: {0}")]
    Pepper(#[from] PepperError),
    #[error("invalid ST_DATA_KEY: {0}")]
    DataKey(#[from] AeadError),
}

impl Config {
    /// Load from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Load using an arbitrary lookup function (used by tests).
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let env = Env { lookup: &lookup };

        let pepper_keys = env.secret("ST_PEPPER_KEYS")?.ok_or(ConfigError::Missing("ST_PEPPER_KEYS"))?;
        let pepper_current = env.parse_opt::<u16>("ST_PEPPER_CURRENT")?;
        let data_key = env.secret("ST_DATA_KEY")?.ok_or(ConfigError::Missing("ST_DATA_KEY"))?;

        Ok(Self {
            listen_addr: env.parse_or("ST_LISTEN_ADDR", SocketAddr::from(([0, 0, 0, 0], 8080)))?,
            database_url: env.secret("ST_DATABASE_URL")?.ok_or(ConfigError::Missing("ST_DATABASE_URL"))?,
            migration_database_url: env.secret("ST_MIGRATION_DATABASE_URL")?,
            db_max_connections: env.parse_or("ST_DB_MAX_CONNECTIONS", 10)?,
            pepper: Pepper::parse(&pepper_keys, pepper_current)?,
            data_key: DataKey::parse(&data_key)?,
            auth: AuthSettings {
                session_ttl: Duration::from_secs(env.parse_or("ST_SESSION_TTL_SECS", 12 * 3600)?),
                session_idle: Duration::from_secs(env.parse_or("ST_SESSION_IDLE_SECS", 30 * 60)?),
                cookie_secure: env.parse_or("ST_COOKIE_SECURE", true)?,
                totp_issuer: env.get("ST_TOTP_ISSUER").unwrap_or_else(|| "SecretTrace".into()),
                trusted_proxies: env.ip_list("ST_TRUSTED_PROXIES")?,
            },
            log_format: match env.get("ST_LOG_FORMAT").as_deref() {
                None | Some("json") => LogFormat::Json,
                Some("pretty") => LogFormat::Pretty,
                Some(other) => {
                    return Err(ConfigError::Invalid {
                        var: "ST_LOG_FORMAT",
                        reason: format!("expected json|pretty, got {other:?}"),
                    });
                }
            },
            request_timeout: Duration::from_secs(env.parse_or("ST_REQUEST_TIMEOUT_SECS", 30)?),
            max_body_bytes: env.parse_or("ST_MAX_BODY_BYTES", 1024 * 1024)?,
        })
    }
}

struct Env<'a> {
    lookup: &'a dyn Fn(&str) -> Option<String>,
}

impl Env<'_> {
    fn get(&self, var: &str) -> Option<String> {
        (self.lookup)(var).filter(|v| !v.is_empty())
    }

    fn parse_opt<T: std::str::FromStr>(&self, var: &'static str) -> Result<Option<T>, ConfigError>
    where
        T::Err: std::fmt::Display,
    {
        self.get(var)
            .map(|v| v.parse::<T>().map_err(|e| ConfigError::Invalid { var, reason: e.to_string() }))
            .transpose()
    }

    fn parse_or<T: std::str::FromStr>(&self, var: &'static str, default: T) -> Result<T, ConfigError>
    where
        T::Err: std::fmt::Display,
    {
        Ok(self.parse_opt(var)?.unwrap_or(default))
    }

    /// Comma-separated IP addresses.
    fn ip_list(&self, var: &'static str) -> Result<Vec<IpAddr>, ConfigError> {
        self.get(var)
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| s.parse().map_err(|e| ConfigError::Invalid { var, reason: format!("{s:?}: {e}") }))
                    .collect()
            })
            .transpose()
            .map(Option::unwrap_or_default)
    }

    /// Value of `var` or the contents of the file named by `var_FILE`.
    fn secret(&self, var: &'static str) -> Result<Option<SecretString>, ConfigError> {
        let file_var = format!("{var}_FILE");
        match (self.get(var), self.get(&file_var)) {
            (Some(_), Some(_)) => Err(ConfigError::Ambiguous(var)),
            (Some(v), None) => Ok(Some(SecretString::from(v))),
            (None, Some(path)) => {
                let path = PathBuf::from(path);
                let content =
                    std::fs::read_to_string(&path).map_err(|source| ConfigError::File { var, path, source })?;
                let trimmed = content.trim_end_matches(['\n', '\r']);
                if trimmed.is_empty() {
                    return Err(ConfigError::Missing(var));
                }
                Ok(Some(SecretString::from(trimmed.to_owned())))
            }
            (None, None) => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::collections::HashMap;

    use secrecy::ExposeSecret;

    use super::*;

    const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="; // 32 bytes
    const DATA_KEY: &str = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="; // 32 bytes

    fn load(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let map: HashMap<String, String> = pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect();
        Config::from_lookup(|k| map.get(k).cloned())
    }

    fn base() -> Vec<(&'static str, &'static str)> {
        vec![
            ("ST_DATABASE_URL", "postgres://st_app:hunter2-db@db/secrettrace"),
            ("ST_PEPPER_KEYS", "1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="),
            ("ST_DATA_KEY", DATA_KEY),
        ]
    }

    #[test]
    fn defaults() {
        let c = load(&base()).unwrap();
        assert_eq!(c.listen_addr.port(), 8080);
        assert_eq!(c.db_max_connections, 10);
        assert_eq!(c.log_format, LogFormat::Json);
        assert_eq!(c.pepper.current_version(), 1);
        assert!(c.migration_database_url.is_none());
        assert!(c.auth.cookie_secure, "cookies are Secure by default");
        assert_eq!(c.auth.session_idle, Duration::from_secs(1800));
        assert!(c.auth.trusted_proxies.is_empty());
    }

    #[test]
    fn auth_settings() {
        let mut v = base();
        v.extend([("ST_COOKIE_SECURE", "false"), ("ST_TRUSTED_PROXIES", "10.0.0.2, ::1")]);
        let c = load(&v).unwrap();
        assert!(!c.auth.cookie_secure);
        assert_eq!(c.auth.trusted_proxies.len(), 2);

        let mut v = base();
        v.push(("ST_TRUSTED_PROXIES", "10.0.0.0/8"));
        assert!(matches!(load(&v).unwrap_err(), ConfigError::Invalid { var: "ST_TRUSTED_PROXIES", .. }));

        let mut v = base();
        v.retain(|(k, _)| *k != "ST_DATA_KEY");
        assert!(matches!(load(&v).unwrap_err(), ConfigError::Missing("ST_DATA_KEY")));
    }

    #[test]
    fn debug_output_never_contains_secrets() {
        let c = load(&base()).unwrap();
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("hunter2-db"), "{dbg}");
        assert!(!dbg.contains(KEY), "{dbg}");
        assert!(!dbg.contains(DATA_KEY), "{dbg}");
    }

    #[test]
    fn missing_required() {
        let err = load(&[("ST_PEPPER_KEYS", "1:x"), ("ST_DATA_KEY", DATA_KEY)]).unwrap_err();
        assert!(matches!(err, ConfigError::Missing("ST_DATABASE_URL")), "{err}");
    }

    #[test]
    fn file_variant_and_ambiguity() {
        let dir = std::env::temp_dir().join(format!("st-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("db_url");
        std::fs::write(&path, "postgres://from-file\n").unwrap();
        let p = path.to_str().unwrap();

        let mut vars = vec![("ST_PEPPER_KEYS", base()[1].1), ("ST_DATA_KEY", DATA_KEY), ("ST_DATABASE_URL_FILE", p)];
        let c = load(&vars).unwrap();
        assert_eq!(c.database_url.expose_secret(), "postgres://from-file");

        vars.push(("ST_DATABASE_URL", "postgres://env"));
        assert!(matches!(load(&vars).unwrap_err(), ConfigError::Ambiguous("ST_DATABASE_URL")));

        let missing =
            [("ST_PEPPER_KEYS", base()[1].1), ("ST_DATA_KEY", DATA_KEY), ("ST_DATABASE_URL_FILE", "/nonexistent/st")];
        assert!(matches!(load(&missing).unwrap_err(), ConfigError::File { .. }));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn invalid_values() {
        let mut v = base();
        v.push(("ST_LOG_FORMAT", "xml"));
        assert!(matches!(load(&v).unwrap_err(), ConfigError::Invalid { var: "ST_LOG_FORMAT", .. }));

        let mut v = base();
        v.push(("ST_DB_MAX_CONNECTIONS", "many"));
        assert!(matches!(load(&v).unwrap_err(), ConfigError::Invalid { var: "ST_DB_MAX_CONNECTIONS", .. }));
    }
}
