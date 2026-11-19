//! Configuration from environment variables.
//!
//! Every sensitive variable `ST_X` may instead be given as `ST_X_FILE` pointing to a
//! file (Docker/Kubernetes secrets). Setting both is an error. Sensitive values are
//! wrapped in [`SecretString`], whose `Debug` output is redacted.

use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::time::Duration;

use secrecy::SecretString;

use crate::auth::AuthSettings;
use crate::crypto::aead::{AeadError, DataKey};
use crate::crypto::pepper::{Pepper, PepperError};
use crate::worker::WorkerConfig;

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
    /// Unique digests one API token may submit to `/ingest/…/match` per hour.
    pub ingest_digests_per_hour: u32,
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
            log_format: env.log_format()?,
            request_timeout: Duration::from_secs(env.parse_or("ST_REQUEST_TIMEOUT_SECS", 30)?),
            max_body_bytes: env.parse_or("ST_MAX_BODY_BYTES", 1024 * 1024)?,
            ingest_digests_per_hour: match env.parse_or("ST_INGEST_DIGESTS_PER_HOUR", 200_000u32)? {
                0 => {
                    return Err(ConfigError::Invalid {
                        var: "ST_INGEST_DIGESTS_PER_HOUR",
                        reason: "must be at least 1".into(),
                    });
                }
                n => n,
            },
        })
    }
}

/// Configuration of `secrettrace-server worker`: database, pepper and the worker settings.
/// No `ST_DATA_KEY`: the worker never touches TOTP seeds (least privilege).
#[derive(Debug)]
pub struct WorkerSettings {
    pub database_url: SecretString,
    pub db_max_connections: u32,
    pub pepper: Pepper,
    pub log_format: LogFormat,
    pub worker: WorkerConfig,
}

impl WorkerSettings {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let env = Env { lookup: &lookup };
        let pepper_keys = env.secret("ST_PEPPER_KEYS")?.ok_or(ConfigError::Missing("ST_PEPPER_KEYS"))?;
        Ok(Self {
            database_url: env.secret("ST_DATABASE_URL")?.ok_or(ConfigError::Missing("ST_DATABASE_URL"))?,
            db_max_connections: env.parse_or("ST_DB_MAX_CONNECTIONS", 5)?,
            pepper: Pepper::parse(&pepper_keys, env.parse_opt::<u16>("ST_PEPPER_CURRENT")?)?,
            log_format: env.log_format()?,
            worker: WorkerConfig::from_lookup(&lookup)?,
        })
    }
}

impl WorkerConfig {
    /// `ST_WORKER_*` variables over [`WorkerConfig::new`] defaults.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let env = Env { lookup: &lookup };
        let path = |var: &str, default: &str| PathBuf::from(env.get(var).unwrap_or_else(|| default.to_owned()));
        let mut c = Self::new(
            path("ST_WORKER_DATA_DIR", "/var/lib/secrettrace/worker"),
            path("ST_WORKER_CREDENTIALS_DIR", "/run/git-credentials"),
        );
        if let Some(id) = env.get("ST_WORKER_ID") {
            let ok = id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
            if !ok {
                return Err(invalid("ST_WORKER_ID", "must be 1-64 chars of [A-Za-z0-9._-]"));
            }
            c.worker_id = id;
        }
        if let Some(dir) = env.get("ST_WORKER_TMP_DIR") {
            c.tmp_dir = PathBuf::from(dir);
        }
        c.ssh_known_hosts = env.get("ST_WORKER_SSH_KNOWN_HOSTS").map(PathBuf::from);
        c.concurrency = env.bounded("ST_WORKER_CONCURRENCY", c.concurrency.get(), 1..=16)?;
        c.scan_threads = env.bounded("ST_WORKER_SCAN_THREADS", c.scan_threads.get().min(64), 1..=64)?;
        c.job_timeout = env.secs("ST_WORKER_JOB_TIMEOUT_SECS", c.job_timeout, 10..=86_400)?;
        c.lease_timeout = env.secs("ST_WORKER_LEASE_TIMEOUT_SECS", c.lease_timeout, 10..=3600)?;
        c.poll_interval = env.secs("ST_WORKER_POLL_INTERVAL_SECS", c.poll_interval, 1..=3600)?;
        c.max_attempts = u32::try_from(env.bounded("ST_WORKER_MAX_ATTEMPTS", 3, 1..=20)?.get()).unwrap_or(3);
        c.allowed_hosts = env
            .get("ST_WORKER_ALLOWED_HOSTS")
            .map(|v| v.split(',').map(|h| h.trim().to_ascii_lowercase()).filter(|h| !h.is_empty()).collect())
            .unwrap_or_default();
        if c.allowed_hosts.iter().any(|h| !h.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))) {
            return Err(invalid("ST_WORKER_ALLOWED_HOSTS", "comma-separated host names"));
        }
        c.allow_any_host = env.parse_or("ST_WORKER_ALLOW_ANY_HOST", false)?;
        if c.allowed_hosts.is_empty() && !c.allow_any_host {
            return Err(invalid(
                "ST_WORKER_ALLOWED_HOSTS",
                "list the hosts sources may point at (or set ST_WORKER_ALLOW_ANY_HOST=true)",
            ));
        }
        c.allow_local_repos = env.parse_or("ST_WORKER_ALLOW_LOCAL_REPOS", false)?;
        c.max_blob_bytes = match env.parse_or("ST_WORKER_MAX_BLOB_BYTES", c.max_blob_bytes)? {
            n @ 1..=67_108_864 => n,
            _ => return Err(invalid("ST_WORKER_MAX_BLOB_BYTES", "must be 1-67108864")),
        };
        c.max_repo_bytes = match env.parse_or("ST_WORKER_MAX_REPO_BYTES", c.max_repo_bytes)? {
            n @ 1_048_576..=1_099_511_627_776 => n,
            _ => return Err(invalid("ST_WORKER_MAX_REPO_BYTES", "must be 1 MiB - 1 TiB")),
        };
        Ok(c)
    }
}

fn invalid(var: &'static str, reason: &str) -> ConfigError {
    ConfigError::Invalid { var, reason: reason.into() }
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

    fn log_format(&self) -> Result<LogFormat, ConfigError> {
        match self.get("ST_LOG_FORMAT").as_deref() {
            None | Some("json") => Ok(LogFormat::Json),
            Some("pretty") => Ok(LogFormat::Pretty),
            Some(other) => Err(ConfigError::Invalid {
                var: "ST_LOG_FORMAT",
                reason: format!("expected json|pretty, got {other:?}"),
            }),
        }
    }

    fn bounded(
        &self,
        var: &'static str,
        default: usize,
        range: std::ops::RangeInclusive<usize>,
    ) -> Result<NonZeroUsize, ConfigError> {
        let n = self.parse_or(var, default)?;
        if !range.contains(&n) {
            return Err(invalid(var, &format!("must be {}-{}", range.start(), range.end())));
        }
        NonZeroUsize::new(n).ok_or_else(|| invalid(var, "must not be 0"))
    }

    fn secs(
        &self,
        var: &'static str,
        default: Duration,
        range: std::ops::RangeInclusive<u64>,
    ) -> Result<Duration, ConfigError> {
        let n = self.parse_or(var, default.as_secs())?;
        if !range.contains(&n) {
            return Err(invalid(var, &format!("must be {}-{} seconds", range.start(), range.end())));
        }
        Ok(Duration::from_secs(n))
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
    const KEY_SPEC: &str = "1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
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
        assert_eq!(c.ingest_digests_per_hour, 200_000);
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
    fn worker_settings_need_no_data_key() {
        let vars = [
            ("ST_DATABASE_URL", "postgres://x"),
            ("ST_PEPPER_KEYS", KEY_SPEC),
            ("ST_WORKER_ALLOWED_HOSTS", "git.example"),
        ];
        let map: HashMap<String, String> = vars.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect();
        let s = WorkerSettings::from_lookup(|k| map.get(k).cloned()).unwrap();
        assert_eq!(s.worker.data_dir, PathBuf::from("/var/lib/secrettrace/worker"));
        assert_eq!(s.worker.credentials_dir, PathBuf::from("/run/git-credentials"));
        assert_eq!(s.worker.max_attempts, 3);
        assert!(!s.worker.allow_local_repos && !s.worker.allow_any_host);
        assert_eq!(s.worker.max_repo_bytes, 2 * 1024 * 1024 * 1024);
        assert!(!format!("{s:?}").contains("AAECAw"), "no pepper in Debug");
    }

    #[test]
    fn worker_config_values() {
        let load = |pairs: &[(&str, &str)]| {
            let mut map: HashMap<String, String> =
                pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect();
            map.entry("ST_WORKER_ALLOW_ANY_HOST".into()).or_insert_with(|| "true".into());
            WorkerConfig::from_lookup(|k| map.get(k).cloned())
        };
        let c = load(&[
            ("ST_WORKER_ID", "w-1"),
            ("ST_WORKER_CONCURRENCY", "4"),
            ("ST_WORKER_ALLOWED_HOSTS", "GitHub.com, gitlab.example"),
            ("ST_WORKER_JOB_TIMEOUT_SECS", "600"),
            ("ST_WORKER_ALLOW_LOCAL_REPOS", "true"),
            ("ST_WORKER_SSH_KNOWN_HOSTS", "/etc/kh"),
        ])
        .unwrap();
        assert_eq!((c.worker_id.as_str(), c.concurrency.get()), ("w-1", 4));
        assert_eq!(c.allowed_hosts, vec!["github.com".to_owned(), "gitlab.example".to_owned()]);
        assert_eq!(c.job_timeout, Duration::from_secs(600));
        assert!(c.allow_local_repos);
        assert_eq!(c.ssh_known_hosts, Some(PathBuf::from("/etc/kh")));
        for (var, bad) in [
            ("ST_WORKER_CONCURRENCY", "0"),
            ("ST_WORKER_CONCURRENCY", "99"),
            ("ST_WORKER_MAX_ATTEMPTS", "0"),
            ("ST_WORKER_LEASE_TIMEOUT_SECS", "0"),
            ("ST_WORKER_POLL_INTERVAL_SECS", "x"),
            ("ST_WORKER_MAX_BLOB_BYTES", "0"),
            ("ST_WORKER_ID", "a b"),
            ("ST_WORKER_ALLOWED_HOSTS", "a/b"),
            ("ST_WORKER_MAX_REPO_BYTES", "1000"),
        ] {
            assert!(matches!(load(&[(var, bad)]), Err(ConfigError::Invalid { .. })), "{var}={bad}");
        }
    }

    #[test]
    fn worker_refuses_any_host_unless_asked() {
        let load = |pairs: &[(&str, &str)]| {
            let map: HashMap<String, String> = pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect();
            WorkerConfig::from_lookup(|k| map.get(k).cloned())
        };
        let err = load(&[]).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid { var: "ST_WORKER_ALLOWED_HOSTS", .. }), "{err}");
        assert!(load(&[("ST_WORKER_ALLOW_ANY_HOST", "false")]).is_err());
        let any = load(&[("ST_WORKER_ALLOW_ANY_HOST", "true")]).unwrap();
        assert!(any.allow_any_host && any.allowed_hosts.is_empty());
        let listed = load(&[("ST_WORKER_ALLOWED_HOSTS", "git.example")]).unwrap();
        assert!(!listed.allow_any_host);
    }

    #[test]
    fn invalid_values() {
        let mut v = base();
        v.push(("ST_LOG_FORMAT", "xml"));
        assert!(matches!(load(&v).unwrap_err(), ConfigError::Invalid { var: "ST_LOG_FORMAT", .. }));

        let mut v = base();
        v.push(("ST_DB_MAX_CONNECTIONS", "many"));
        assert!(matches!(load(&v).unwrap_err(), ConfigError::Invalid { var: "ST_DB_MAX_CONNECTIONS", .. }));

        let mut v = base();
        v.push(("ST_INGEST_DIGESTS_PER_HOUR", "0"));
        assert!(matches!(load(&v).unwrap_err(), ConfigError::Invalid { var: "ST_INGEST_DIGESTS_PER_HOUR", .. }));
    }
}
