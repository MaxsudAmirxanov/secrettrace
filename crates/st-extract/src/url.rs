//! Credentials in URL userinfo: `scheme://user:password@host/…`.

use std::sync::LazyLock;

use regex::Regex;
use st_core::SecretType;

use crate::candidate::{Detector, Hit};
use crate::{Emitter, kv};

#[allow(clippy::expect_used)] // static pattern, exercised by tests
static URL: LazyLock<Regex> = LazyLock::new(|| {
    // The password is greedy and may contain an unencoded `@`: the last `@` before the host wins.
    Regex::new(
        r#"(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]*)://(?P<user>[^\s:/?#@"'`<>\\]*):(?P<pass>[^\s/?#"'`<>\\]+)@(?P<host>[^\s/?#@"'`<>\\]+)[^\s"'`<>\\]*"#,
    )
    .expect("valid URL pattern")
});

const DB_SCHEMES: &[&str] = &[
    "postgres",
    "postgresql",
    "mysql",
    "mariadb",
    "mongodb",
    "mongodb+srv",
    "redis",
    "rediss",
    "amqp",
    "amqps",
    "mssql",
    "sqlserver",
    "oracle",
    "clickhouse",
    "cockroachdb",
    "couchdb",
];

pub(crate) fn scan(text: &str, em: &mut Emitter<'_, '_>) {
    if !text.contains("://") {
        return;
    }
    for caps in URL.captures_iter(text) {
        let (Some(whole), Some(scheme), Some(user), Some(pass), Some(host)) =
            (caps.get(0), caps.name("scheme"), caps.name("user"), caps.name("pass"), caps.name("host"))
        else {
            continue;
        };
        if scheme.len() > 32 || user.len() > 256 || pass.len() > 512 || host.len() > 253 {
            continue;
        }
        if kv::is_placeholder(pass.as_str()) {
            continue;
        }

        let pass_hit = Hit::new(pass.range(), SecretType::Password, Detector::UrlPassword);
        em.emit_value(&pass_hit, pass.as_str());

        let trimmed = whole.as_str().trim_end_matches(['.', ',', ';', ':', ')', ']', '}']);
        let url_range = whole.start()..whole.start() + trimmed.len();
        let ty = if DB_SCHEMES.contains(&scheme.as_str().to_ascii_lowercase().as_str()) {
            SecretType::DbConnectionString
        } else {
            SecretType::Other
        };
        let url_hit = Hit::new(url_range.clone(), ty, Detector::Url);
        em.emit(&url_hit, trimmed);
        // JDBC wraps the URL: `jdbc:postgresql://…`.
        if text[..whole.start()].ends_with("jdbc:") {
            let start = whole.start() - "jdbc:".len();
            em.emit(&url_hit.at(start..url_range.end), &text[start..url_range.end]);
        }
    }
}
