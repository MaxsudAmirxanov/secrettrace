//! Which source URIs the worker is willing to fetch, checked before git ever runs.
//!
//! Accepted: `https://host[:port]/path`, `ssh://host[:port]/path`, scp-like
//! `user@host:path`; with `allow_local_repos` also `file:///abs` and absolute paths.
//! Plain `http://`, `git://`, `ext::`, `fd::`, relative paths, IPv6 literals and anything
//! git could take for an option (a host, user or path starting with `-`) are refused.

use super::JobError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Https,
    Ssh,
    Local,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    pub transport: Transport,
    /// Lowercase host name; empty for local repositories.
    pub host: String,
    /// The user given in an scp-like URI (`git@host:path`).
    pub user: Option<String>,
}

/// Hosts a source may point at: an explicit list, or (only when the deployer opted in
/// with `allow_any_host`) any host. IP literals are refused unless listed literally.
#[derive(Debug, Clone, Copy)]
pub struct HostPolicy<'a> {
    pub allowed: &'a [String],
    pub allow_any: bool,
    pub allow_local: bool,
}

pub fn parse(uri: &str, policy: HostPolicy<'_>) -> Result<Remote, JobError> {
    let remote = classify(uri, policy.allow_local).ok_or_else(|| JobError::permanent("unsupported source URI"))?;
    if remote.transport == Transport::Local {
        return Ok(remote);
    }
    let listed = policy.allowed.iter().any(|h| h.eq_ignore_ascii_case(&remote.host));
    let allowed =
        if is_ip_literal(&remote.host) { listed } else { listed || (policy.allowed.is_empty() && policy.allow_any) };
    if !allowed {
        return Err(JobError::permanent("source host is not allowed"));
    }
    Ok(remote)
}

/// Would a resolver take this host for an IPv4 address? Every dot-separated label is a
/// number in decimal, octal (`0177`) or hex (`0x7f`): `127.0.0.1`, `127.1`, `2130706433`,
/// `0x7f.0.0.1`. (IPv6 literals never get this far: brackets are not host characters.)
#[must_use]
pub fn is_ip_literal(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    !host.is_empty()
        && host.split('.').all(|label| {
            let l = label.to_ascii_lowercase();
            match l.strip_prefix("0x") {
                Some(hex) => hex.bytes().all(|b| b.is_ascii_hexdigit()),
                None => !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()),
            }
        })
}

fn classify(uri: &str, allow_local: bool) -> Option<Remote> {
    if uri.is_empty() || uri.len() > 2048 || uri.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return None;
    }
    if uri.contains('\\') {
        return None;
    }
    if let Some(rest) = uri.strip_prefix("https://") {
        return url_remote(rest, Transport::Https);
    }
    if let Some(rest) = uri.strip_prefix("ssh://") {
        return url_remote(rest, Transport::Ssh);
    }
    if let Some(path) = uri.strip_prefix("file://") {
        return (allow_local && local_path_ok(path)).then(local);
    }
    if uri.starts_with('/') {
        return (allow_local && local_path_ok(uri)).then(local);
    }
    if uri.contains("://") || uri.contains("::") {
        return None;
    }
    scp_remote(uri)
}

fn local() -> Remote {
    Remote { transport: Transport::Local, host: String::new(), user: None }
}

fn local_path_ok(path: &str) -> bool {
    path.starts_with('/') && !path.split('/').any(|seg| seg == "..")
}

/// `host[:port]/path` after the scheme. No userinfo (credentials never live in a URI).
fn url_remote(rest: &str, transport: Transport) -> Option<Remote> {
    let (authority, path) = rest.split_once('/')?;
    if path.is_empty() || path.starts_with('-') || authority.contains('@') {
        return None;
    }
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    if !host_ok(host) || port.is_some_and(|p| !p.parse::<u16>().is_ok_and(|n| n > 0)) {
        return None;
    }
    Some(Remote { transport, host: host.to_ascii_lowercase(), user: None })
}

/// `user@host:path`.
fn scp_remote(uri: &str) -> Option<Remote> {
    let (user, rest) = uri.split_once('@')?;
    let (host, path) = rest.split_once(':')?;
    let user_ok = !user.is_empty()
        && user.len() <= 64
        && !user.starts_with('-')
        && user.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if !user_ok || !host_ok(host) || path.is_empty() || path.starts_with('-') || user.contains('/') {
        return None;
    }
    Some(Remote { transport: Transport::Ssh, host: host.to_ascii_lowercase(), user: Some(user.to_owned()) })
}

fn host_ok(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with(['-', '.'])
        && host.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const ANY: HostPolicy<'static> = HostPolicy { allowed: &[], allow_any: true, allow_local: false };
    const LOCAL: HostPolicy<'static> = HostPolicy { allowed: &[], allow_any: false, allow_local: true };

    fn ok(uri: &str) -> Remote {
        parse(uri, ANY).unwrap_or_else(|e| panic!("{uri}: {e}"))
    }

    #[test]
    fn accepted_forms() {
        let r = ok("https://Git.Example:8443/infra/app.git");
        assert_eq!((r.transport, r.host.as_str(), r.user), (Transport::Https, "git.example", None));
        assert_eq!(ok("ssh://git.example/infra/app.git").transport, Transport::Ssh);
        let scp = ok("git@git.example:infra/app.git");
        assert_eq!((scp.transport, scp.user.as_deref()), (Transport::Ssh, Some("git")));
        assert_eq!(ok("git@git.example:/srv/app.git").host, "git.example");
    }

    #[test]
    fn rejected_forms() {
        for bad in [
            "http://git.example/a",
            "git://git.example/a",
            "ext::sh -c touch% /tmp/pwned",
            "ext::ssh",
            "fd::3",
            "https://user:pw@git.example/a",
            "https://-oProxyCommand=x/a",
            "ssh://-oProxyCommand=touch/a",
            "ssh://git@git.example/a",
            "-u@git.example:a",
            "git@-host:a",
            "git@host:-path",
            "https://git.example",
            "https://git.example/",
            "https://[::1]/a",
            "https://git.example:0/a",
            "https://git.example:99999/a",
            "https:\\\\git.example\\a",
            "relative/path",
            "host:path",
            "file:///srv/repo.git",
            "/srv/repo.git",
            "https://git.example/a b",
            "",
        ] {
            let err = parse(bad, ANY).map(|_| ()).unwrap_err();
            assert_eq!(err.message, "unsupported source URI", "{bad:?}");
            assert!(!err.retryable);
        }
    }

    #[test]
    fn local_repositories_only_when_allowed() {
        assert_eq!(parse("/srv/repo.git", LOCAL).map(|r| r.transport), Ok(Transport::Local));
        assert_eq!(parse("file:///srv/repo.git", LOCAL).map(|r| r.transport), Ok(Transport::Local));
        assert!(parse("file://srv/repo.git", LOCAL).is_err());
        assert!(parse("/srv/../etc", LOCAL).is_err());
        assert!(parse("/srv/repo.git", ANY).is_err());
    }

    #[test]
    fn host_allowlist() {
        let allowed = vec!["git.example".to_owned()];
        let policy = HostPolicy { allowed: &allowed, allow_any: false, allow_local: true };
        assert!(parse("https://GIT.example/a", policy).is_ok());
        assert!(parse("git@git.example:a", policy).is_ok());
        let err = parse("https://evil.example/a", policy).map(|_| ()).unwrap_err();
        assert_eq!((err.message.as_str(), err.retryable), ("source host is not allowed", false));
        assert!(parse("/srv/repo.git", policy).is_ok(), "local repos have no host");
        // A list wins over allow_any; an empty list without allow_any allows nothing.
        assert!(parse("https://evil.example/a", HostPolicy { allow_any: true, ..policy }).is_err());
        assert!(parse("https://git.example/a", HostPolicy { allowed: &[], ..policy }).is_err());
    }

    #[test]
    fn ip_literals_need_an_explicit_entry() {
        for ip in ["127.0.0.1", "127.1", "2130706433", "0x7f.0.0.1", "0177.0.0.1", "0x7F000001", "10.0.0.1."] {
            assert!(is_ip_literal(ip), "{ip}");
            let err = parse(&format!("https://{ip}/a"), ANY).map(|_| ()).unwrap_err();
            assert_eq!(err.message, "source host is not allowed", "{ip}");
        }
        for name in ["git.example", "1.2.3.4.nip.io", "0x7f.example", "a1"] {
            assert!(!is_ip_literal(name), "{name}");
        }
        let listed = vec!["10.0.0.5".to_owned()];
        let policy = HostPolicy { allowed: &listed, allow_any: false, allow_local: false };
        assert!(parse("https://10.0.0.5/a", policy).is_ok(), "listed literally");
        assert!(parse("https://10.0.0.6/a", policy).is_err());
        assert!(parse("https://[::1]/a", ANY).is_err(), "IPv6 literals are never accepted");
    }
}
