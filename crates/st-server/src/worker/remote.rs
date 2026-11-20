//! Which source URIs the worker is willing to fetch, checked before git ever runs.
//!
//! Accepted: `https://host[:port]/path`, `ssh://host[:port]/path`, scp-like
//! `user@host:path`; with `allow_local_repos` also `file:///abs` and absolute paths.
//! Plain `http://`, `git://`, `ext::`, `fd::`, relative paths, IPv6 literals and anything
//! git could take for an option (a host, user or path starting with `-`) are refused.
//!
//! Hosts allowed only by `allow_any_host` (not listed) get two more checks, against SSRF
//! into the deployment's own network: internal-looking names (`localhost`, single labels
//! such as compose service names, `.local`, `.internal`…) are refused up front, and the
//! name is resolved before the fetch: every address must be public, and git is pinned to
//! the checked one (`http.curloptResolve`, ssh `HostName`), so a second DNS answer
//! (rebinding) is never used. Through an HTTP proxy the proxy resolves the name itself.

use std::net::{IpAddr, Ipv4Addr};

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
    /// Explicit port of an `https://` or `ssh://` URI.
    pub port: Option<u16>,
    /// Allowed only through `allow_any_host`: resolve, require public addresses, pin.
    pub pin: bool,
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
    let any = !listed
        && policy.allowed.is_empty()
        && policy.allow_any
        && !is_ip_literal(&remote.host)
        && !internal_name(&remote.host);
    if !listed && !any {
        return Err(JobError::permanent("source host is not allowed"));
    }
    Ok(Remote { pin: any, ..remote })
}

/// Names that point into the local or private network rather than at a public git host.
fn internal_name(host: &str) -> bool {
    const SUFFIXES: &[&str] =
        &[".localhost", ".local", ".internal", ".lan", ".home.arpa", ".localdomain", ".intranet", ".corp"];
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    host == "localhost" || !host.contains('.') || SUFFIXES.iter().any(|s| host.ends_with(s))
}

/// Is this an address a public git host may have? Loopback, private, link-local,
/// shared (CGNAT), documentation, benchmarking, multicast and reserved ranges are not,
/// including IPv4 embedded in IPv6 (mapped, NAT64).
#[must_use]
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return public_v4(v4);
            }
            let s = v6.segments();
            if s[0] == 0x64 && s[1] == 0xff9b {
                // NAT64 well-known prefix: the low 32 bits are the IPv4 target.
                let low = (u32::from(s[6]) << 16) | u32::from(s[7]);
                return public_v4(Ipv4Addr::from(low));
            }
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (s[0] & 0xffc0) == 0xfec0 // site-local (deprecated)
                || (s[0] == 0x2001 && s[1] == 0x0db8)) // documentation
        }
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || a == 0
        || (a == 100 && (64..128).contains(&b)) // shared address space (CGNAT)
        || (a == 192 && b == 0 && c == 0) // IETF protocol assignments
        || (a == 198 && (18..20).contains(&b)) // benchmarking
        || a >= 240) // reserved
}

/// For a pinned remote: resolve the host and return the address git must use. Every
/// resolved address must be public, so a mixed answer cannot slip an internal one in.
pub async fn resolve_pinned(remote: &Remote) -> Result<Option<IpAddr>, JobError> {
    if !remote.pin {
        return Ok(None);
    }
    let port = remote.port.unwrap_or(match remote.transport {
        Transport::Ssh => 22,
        _ => 443,
    });
    let addrs: Vec<IpAddr> = tokio::net::lookup_host((remote.host.as_str(), port))
        .await
        .map_err(|_| JobError::retryable("cannot resolve the source host"))?
        .map(|a| a.ip())
        .collect();
    if addrs.is_empty() {
        return Err(JobError::retryable("cannot resolve the source host"));
    }
    if !addrs.iter().all(|&ip| is_public(ip)) {
        return Err(JobError::permanent("source host resolves to a non-public address"));
    }
    Ok(addrs.first().copied())
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
    Remote { transport: Transport::Local, host: String::new(), user: None, port: None, pin: false }
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
    let port = match port {
        Some(p) => Some(p.parse::<u16>().ok().filter(|&n| n > 0)?),
        None => None,
    };
    if !host_ok(host) {
        return None;
    }
    Some(Remote { transport, host: host.to_ascii_lowercase(), user: None, port, pin: false })
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
    Some(Remote {
        transport: Transport::Ssh,
        host: host.to_ascii_lowercase(),
        user: Some(user.to_owned()),
        port: None,
        pin: false,
    })
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
        assert_eq!((r.port, r.pin), (Some(8443), true), "allowed through allow_any: pinned");
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

    #[test]
    fn allow_any_refuses_internal_names_and_listed_hosts_are_not_pinned() {
        for host in
            ["localhost", "server", "postgres", "git.local", "vault.internal", "nas.lan", "x.home.arpa", "LOCALHOST."]
        {
            let err = parse(&format!("https://{host}/a"), ANY).map(|_| ()).unwrap_err();
            assert_eq!(err.message, "source host is not allowed", "{host}");
            assert!(parse(&format!("git@{host}:a"), ANY).is_err(), "{host}");
        }
        let listed = vec!["gitlab".to_owned()];
        let policy = HostPolicy { allowed: &listed, allow_any: false, allow_local: false };
        let r = parse("https://gitlab/a", policy).unwrap();
        assert!(!r.pin, "an operator-listed host is trusted as is");
    }

    #[test]
    fn public_addresses() {
        for ip in ["140.82.112.3", "2606:4700::6810:84e5", "8.8.8.8"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "198.18.0.1",
            "192.0.0.8",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
            "192.0.2.1",
            "::1",
            "::",
            "fd00::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::a00:1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[tokio::test]
    async fn resolution_refuses_non_public_answers() {
        let mut r = ok("https://git.example/a");
        // `localhost` resolves without network access; it can only get here forged.
        r.host = "localhost".into();
        let err = resolve_pinned(&r).await.unwrap_err();
        assert_eq!((err.message.as_str(), err.retryable), ("source host resolves to a non-public address", false));
        r.pin = false;
        assert_eq!(resolve_pinned(&r).await.unwrap(), None, "listed hosts are not resolved here");
    }
}
