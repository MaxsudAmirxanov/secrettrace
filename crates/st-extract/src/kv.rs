//! Values assigned to sensitive keys, in the syntaxes configs, code and logs use:
//!
//! * `KEY=value`, `key: value`, `"key": "value"`, `key => 'value'`, `key := value`,
//!   `password == "x"` (comparisons in code);
//! * `--password value` command-line flags;
//! * `<password>value</password>` XML elements;
//! * `.netrc` lines (`machine h login u password p`);
//! * `Authorization: Bearer …` / `Basic …` headers.
//!
//! Only keys whose *name* is sensitive are considered, so low-entropy passwords are
//! still found while ordinary settings are not.

use std::sync::LazyLock;

use regex::Regex;
use st_core::SecretType;

use crate::candidate::{Confidence, Detector, Encoding, Hit};
use crate::{Emitter, decode};

const MAX_KEY_LEN: usize = 64;
const MAX_VALUE_LEN: usize = 4096;

#[allow(clippy::expect_used)] // static patterns, exercised by tests
static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?x)
        (?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)
        \\?["']?                                  # closing quote of a quoted key
        [\ \t]*(?:===|==|!=|=>|:=|\+=|=|:)[\ \t]*
        (?:
            "(?P<dq>(?:[^"\\\n]|\\.)*)"
          | '(?P<sq>[^'\n]*)'
          | `(?P<bt>[^`\n]*)`
          | (?P<bare>[^\s"'`<>;&]+)
        )"#,
    )
    .expect("valid assignment pattern")
});

#[allow(clippy::expect_used)]
static FLAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?:^|[\s"'=])--(?P<key>[A-Za-z][A-Za-z0-9_\-]*)[\ \t]+(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)'|(?P<bare>[^\s"'`\-][^\s"'`]*))"#,
    )
    .expect("valid flag pattern")
});

#[allow(clippy::expect_used)]
static XML: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"<(?P<open>[A-Za-z_][A-Za-z0-9_.:\-]*)>(?P<val>[^<\n]+)</(?P<close>[A-Za-z_][A-Za-z0-9_.:\-]*)>")
        .expect("valid XML pattern")
});

#[allow(clippy::expect_used)]
static NETRC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*(?:machine[ \t]+\S+|default)\b[^\n]*?\bpassword[ \t]+(?P<val>\S+)")
        .expect("valid netrc pattern")
});

#[allow(clippy::expect_used)]
static AUTH_HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?P<scheme>bearer|basic)[ \t]+(?P<val>[A-Za-z0-9._~+/\-]{8,}={0,2})")
        .expect("valid auth header pattern")
});

/// Split `fooBarBaz` / `FOO-BAR.baz` into lowercase `_`-separated segments.
fn snake(key: &str) -> String {
    let mut out = String::with_capacity(key.len() + 8);
    let mut prev_lower = false;
    for c in key.chars() {
        if c.is_ascii_uppercase() && prev_lower {
            out.push('_');
        }
        prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        out.push(if matches!(c, '-' | '.' | ' ' | ':') { '_' } else { c.to_ascii_lowercase() });
    }
    out
}

/// Last segments that describe metadata *about* a secret rather than the secret.
const META_SUFFIXES: &[&str] = &[
    "file",
    "path",
    "dir",
    "filename",
    "ref",
    "name",
    "names",
    "id",
    "ids",
    "length",
    "len",
    "type",
    "policy",
    "header",
    "field",
    "prompt",
    "hint",
    "label",
    "placeholder",
    "pattern",
    "regex",
    "expiry",
    "expires",
    "expiration",
    "ttl",
    "timeout",
    "count",
    "min",
    "max",
    "enabled",
    "required",
    "version",
    "endpoint",
    "uri",
    "url",
    "env",
    "var",
    "arn",
    "format",
    "algorithm",
    "size",
    "rotation",
    "manager",
    "store",
    "provider",
];

/// Classify a key name; `None` means "not sensitive".
#[must_use]
pub fn classify_key(key: &str) -> Option<SecretType> {
    if key.is_empty() || key.len() > MAX_KEY_LEN {
        return None;
    }
    let k = snake(key);
    let segs: Vec<&str> = k.split('_').filter(|s| !s.is_empty()).collect();
    let has = |s: &str| segs.contains(&s);

    if ["dsn", "database_url", "db_url", "connection_string", "connectionstring", "conn_str", "connstr", "jdbc_url"]
        .iter()
        .any(|w| k.contains(w))
    {
        return Some(SecretType::DbConnectionString);
    }
    let last = segs.last()?;
    if META_SUFFIXES.contains(last) || k.contains("public") || k.contains("publishable") {
        return None;
    }
    if k.contains("password")
        || k.contains("passwd")
        || k.contains("passphrase")
        || has("pass")
        || has("pwd")
        || has("pw")
    {
        return Some(SecretType::Password);
    }
    if k.contains("private_key") || k.contains("privatekey") {
        return Some(SecretType::PrivateKey);
    }
    if k.contains("api_key")
        || k.contains("apikey")
        || k.contains("access_key")
        || k.contains("accesskey")
        || k.contains("account_key")
        || k.contains("accountkey")
        || k.contains("sharedaccesskey")
        || *last == "key"
    {
        return Some(SecretType::ApiKey);
    }
    if k.contains("token")
        || k.contains("secret")
        || k.contains("credential")
        || k.contains("authorization")
        || has("auth")
        || k.contains("bearer")
        || k.contains("signing_key")
        || k.contains("session_key")
    {
        return Some(SecretType::Token);
    }
    None
}

/// Template references and dummy values that are never the secret itself.
#[must_use]
pub fn is_placeholder(value: &str) -> bool {
    let t = value.trim();
    let mut chars = t.chars();
    let all_same = chars.next().is_some_and(|first| chars.all(|c| c == first));
    let env_ref = t.strip_prefix('$').is_some_and(|rest| {
        rest.starts_with(['{', '('])
            || (!rest.is_empty() && rest.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'))
    });
    let lower = t.to_ascii_lowercase();
    all_same
        || env_ref
        || t.starts_with("{{")
        || t.starts_with("%(")
        || t.starts_with("#{")
        || (t.starts_with('%') && t.ends_with('%'))
        || (t.starts_with('<') && t.ends_with('>'))
        || matches!(
            lower.as_str(),
            "null" | "none" | "nil" | "true" | "false" | "undefined" | "redacted" | "[redacted]" | "hidden" | "masked"
        )
}

pub(crate) fn scan(text: &str, em: &mut Emitter<'_, '_>) {
    assignments(text, em);
    flags(text, em);
    xml(text, em);
    netrc(text, em);
    auth_headers(text, em);
}

fn assignments(text: &str, em: &mut Emitter<'_, '_>) {
    for caps in ASSIGNMENT.captures_iter(text) {
        let Some(key) = caps.name("key") else { continue };
        let Some(ty) = classify_key(key.as_str()) else { continue };
        let hit = |range| Hit::new(range, ty, Detector::KeyValue).key(key.as_str());
        if let Some(v) = caps.name("dq") {
            quoted(em, &hit(v.range()), v.as_str(), true);
        } else if let Some(v) = caps.name("sq").or_else(|| caps.name("bt")) {
            quoted(em, &hit(v.range()), v.as_str(), false);
        } else if let Some(v) = caps.name("bare") {
            // The pattern stops at `;`/`&` so `Server=x;Password=y` yields both pairs;
            // the full token up to whitespace is recovered here for values containing them.
            let rest = &text[v.end()..];
            if rest.starts_with(['"', '\'', '`']) {
                continue; // code such as `os.environ["X"]`, not a literal value
            }
            let window = &rest[..floor_boundary(rest, MAX_VALUE_LEN + 1)];
            let Some(tail) = window
                .find(|c: char| c.is_whitespace() || "\"'`<>".contains(c))
                .or_else(|| (window.len() == rest.len()).then_some(rest.len()))
            else {
                continue; // longer than any value we consider
            };
            let end = v.end() + tail;
            bare(em, &hit(v.start()..end), &text[v.start()..end]);
        }
    }
}

fn flags(text: &str, em: &mut Emitter<'_, '_>) {
    if !text.contains("--") {
        return;
    }
    for caps in FLAG.captures_iter(text) {
        let Some(key) = caps.name("key") else { continue };
        let Some(ty) = classify_key(key.as_str()) else { continue };
        let hit = |range| Hit::new(range, ty, Detector::KeyValue).key(key.as_str());
        if let Some(v) = caps.name("dq") {
            quoted(em, &hit(v.range()), v.as_str(), true);
        } else if let Some(v) = caps.name("sq") {
            quoted(em, &hit(v.range()), v.as_str(), false);
        } else if let Some(v) = caps.name("bare") {
            bare(em, &hit(v.range()), v.as_str());
        }
    }
}

fn xml(text: &str, em: &mut Emitter<'_, '_>) {
    if !text.contains("</") {
        return;
    }
    for caps in XML.captures_iter(text) {
        let (Some(open), Some(close), Some(v)) = (caps.name("open"), caps.name("close"), caps.name("val")) else {
            continue;
        };
        if open.as_str() != close.as_str() {
            continue;
        }
        let Some(ty) = classify_key(open.as_str()) else { continue };
        let hit = Hit::new(v.range(), ty, Detector::KeyValue).key(open.as_str());
        quoted(em, &hit, v.as_str(), false);
    }
}

fn netrc(text: &str, em: &mut Emitter<'_, '_>) {
    if !text.contains("password") {
        return;
    }
    for caps in NETRC.captures_iter(text) {
        let Some(v) = caps.name("val") else { continue };
        let hit = Hit::new(v.range(), SecretType::Password, Detector::KeyValue).key("password");
        quoted(em, &hit, v.as_str(), false);
    }
}

fn auth_headers(text: &str, em: &mut Emitter<'_, '_>) {
    for caps in AUTH_HEADER.captures_iter(text) {
        let (Some(scheme), Some(v)) = (caps.name("scheme"), caps.name("val")) else { continue };
        if scheme.as_str().eq_ignore_ascii_case("basic") {
            // Basic carries base64(user:password): the password is the secret.
            if let Some(decoded) = decode::base64_text(v.as_str(), 4)
                && let Some(pass) = decode::basic_auth_password(&decoded)
            {
                em.emit(
                    &Hit::new(v.range(), SecretType::Password, Detector::BasicAuth).with_encoding(Encoding::Base64),
                    pass,
                );
            }
        } else {
            em.emit(&Hit::new(v.range(), SecretType::Token, Detector::AuthHeader), v.as_str());
        }
    }
}

fn floor_boundary(s: &str, max: usize) -> usize {
    let mut end = max.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    end
}

/// A quoted (or otherwise delimited) value: taken verbatim, plus its unescaped form.
fn quoted(em: &mut Emitter<'_, '_>, hit: &Hit<'_>, value: &str, escapes: bool) {
    if value.len() > MAX_VALUE_LEN || is_placeholder(value) {
        return;
    }
    em.emit_value(hit, value);
    if escapes && let Some(unescaped) = decode::json_unescape(value) {
        em.emit_value(&hit.with_encoding(Encoding::JsonString), &unescaped);
    }
}

/// An unquoted value: ends at whitespace; trailing list punctuation is dropped and
/// connection-string / query-string tails (`;Next=…`, `&next=…`) are tried as well.
fn bare(em: &mut Emitter<'_, '_>, hit: &Hit<'_>, value: &str) {
    let v = value.trim_end_matches([',', ';', ')', ']', '}']);
    if v.len() > MAX_VALUE_LEN || is_placeholder(v) || v.contains('(') {
        return;
    }
    if ["bearer", "basic", "token", "digest"].iter().any(|w| v.eq_ignore_ascii_case(w)) {
        return; // `Authorization: Bearer x` is handled by the header detector.
    }
    // `password: SecretString` / `token = self.token` in source code: still digested
    // (a weak registered password may look like this), but not trusted on its own.
    let hit = if looks_like_identifier(v) { hit.clone().confidence(Confidence::Low) } else { hit.clone() };
    let start = hit.range.start;
    em.emit_value(&hit.at(start..start + v.len()), v);
    if let Some(cut) = v.find([';', '&']) {
        em.emit_value(&hit.at(start..start + cut), &v[..cut]);
    }
}

/// Letters, `_`, `.` and `::` only, e.g. a type name or a field access.
fn looks_like_identifier(v: &str) -> bool {
    v.bytes().all(|b| b.is_ascii_alphabetic() || matches!(b, b'_' | b'.' | b':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_classification() {
        use SecretType::{ApiKey, DbConnectionString, Password, PrivateKey, Token};
        let cases: &[(&str, Option<SecretType>)] = &[
            ("DB_PASSWORD", Some(Password)),
            ("dbPass", Some(Password)),
            ("spring.datasource.password", Some(Password)),
            ("MYSQL_PWD", Some(Password)),
            ("passphrase", Some(Password)),
            ("bypass", None),
            ("compass_heading", None),
            ("password_file", None),
            ("PASSWORD_MIN_LENGTH", None),
            ("apiKey", Some(ApiKey)),
            ("AWS_SECRET_ACCESS_KEY", Some(ApiKey)),
            ("AccountKey", Some(ApiKey)),
            ("STRIPE_KEY", Some(ApiKey)),
            ("aws_access_key_id", None),
            ("public_key", None),
            ("publishableKey", None),
            ("private_key", Some(PrivateKey)),
            ("private_key_id", None),
            ("GITHUB_TOKEN", Some(Token)),
            ("client_secret", Some(Token)),
            ("auth", Some(Token)),
            ("Authorization", Some(Token)),
            ("author", None),
            ("token_uri", None),
            ("secret_name", None),
            ("DATABASE_URL", Some(DbConnectionString)),
            ("sentry_dsn", Some(DbConnectionString)),
            ("hostname", None),
            ("", None),
        ];
        for (key, expected) in cases {
            assert_eq!(classify_key(key), *expected, "{key}");
        }
    }

    #[test]
    fn placeholders() {
        for p in [
            "${DB_PASSWORD}",
            "$DB_PASSWORD",
            "$(cat /run/secrets/x)",
            "{{ .Values.password }}",
            "%(pw)s",
            "<your-token>",
            "********",
            "xxxxxxxx",
            "null",
            "None",
            "%PASSWORD%",
            "#{secret}",
        ] {
            assert!(is_placeholder(p), "{p}");
        }
        for v in ["hunter2hunter2", "$ecretPass1", "changeme", "p@ss%word"] {
            assert!(!is_placeholder(v), "{v}");
        }
    }
}
