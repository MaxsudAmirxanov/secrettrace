//! Credentials by reference: `sources.credential_ref` names a file in the worker's
//! credentials directory; the value itself never reaches the database, argv, environment
//! values, git config, logs or error messages.
//!
//! A credential is bound to hosts by whoever deploys it, not by the operators who name it
//! in a source: `<ref>` is usable only for the hosts listed in `<ref>.hosts` next to it (one
//! host per line, `#` comments). Without that file it is never used. The `.` keeps the hosts
//! file itself from ever being referenced as a credential.
//!
//! For a job the file is copied into the job's private temp dir (0700 dir, 0600 file):
//! - https: the file holds a token or password. Git asks for it through `GIT_ASKPASS`,
//!   which is this very binary in [`askpass`] mode reading the temp copy.
//! - ssh: the file holds an OpenSSH private key, passed to ssh as `IdentityFile` (ssh
//!   insists on a private, 0600 key file owned by the user, hence the copy).

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::JobError;

/// Largest credential file accepted.
pub const MAX_CREDENTIAL_BYTES: u64 = 16 * 1024;
/// Largest `<ref>.hosts` file accepted.
pub const MAX_HOSTS_BYTES: u64 = 4 * 1024;
/// Username sent with an https token when the source config names none.
pub const DEFAULT_HTTPS_USERNAME: &str = "x-access-token";

/// `ST_GIT_ASKPASS_FILE`: path of the temp copy of the token (empty: no credential).
pub const ASKPASS_FILE_VAR: &str = "ST_GIT_ASKPASS_FILE";
/// `ST_GIT_ASKPASS_USERNAME`: username for the `Username for …` prompt.
pub const ASKPASS_USERNAME_VAR: &str = "ST_GIT_ASKPASS_USERNAME";
/// `ST_GIT_ASKPASS_HOST`: the only host askpass answers prompts for.
pub const ASKPASS_HOST_VAR: &str = "ST_GIT_ASKPASS_HOST";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Token or password for https.
    Token,
    /// OpenSSH private key.
    SshKey,
}

/// A credential loaded for one job. The value is wiped on drop.
pub struct Credential {
    pub kind: Kind,
    value: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential").field("kind", &self.kind).finish_non_exhaustive()
    }
}

#[must_use]
pub fn valid_ref(name: &str) -> bool {
    (1..=64).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// Refuse `<ref>` unless `<dir>/<ref>.hosts` lists `host` (case-insensitive). A missing,
/// unreadable or malformed hosts file refuses as well, with the same message.
pub fn check_host_binding(dir: &Path, name: &str, host: &str) -> Result<(), JobError> {
    if !valid_ref(name) {
        return Err(JobError::permanent(format!("credential {name:?} has an invalid name")));
    }
    let refused = || JobError::permanent(format!("credential {name:?} is not allowed for this host"));
    let hosts = read_small(&dir.join(format!("{name}.hosts")), MAX_HOSTS_BYTES).map_err(|_| refused())?;
    let text = std::str::from_utf8(&hosts).map_err(|_| refused())?;
    if parse_hosts(text).iter().any(|h| h.eq_ignore_ascii_case(host)) { Ok(()) } else { Err(refused()) }
}

/// Host names of a hosts file: one per line, blank lines and `#` comments ignored,
/// lowercased; lines that are not a plain host name are ignored.
#[must_use]
pub fn parse_hosts(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or_default().trim())
        .filter(|l| {
            !l.is_empty()
                && !l.starts_with(['-', '.'])
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        })
        .map(str::to_ascii_lowercase)
        .collect()
}

/// A regular file (never through a symlink) of at most `max` bytes.
fn read_small(path: &Path, max: u64) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut file = open_no_follow(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() > max {
        return Err(io::Error::other("not a small regular file"));
    }
    let mut buf = Zeroizing::new(Vec::new());
    (&mut file).take(max + 1).read_to_end(&mut buf)?;
    if u64::try_from(buf.len()).unwrap_or(u64::MAX) > max {
        return Err(io::Error::other("too large"));
    }
    Ok(buf)
}

impl Credential {
    /// Load `<dir>/<name>`: never through a symlink, only a regular file, at most
    /// [`MAX_CREDENTIAL_BYTES`]. Errors name the reference, never the content.
    pub fn load(dir: &Path, name: &str, kind: Kind) -> Result<Self, JobError> {
        if !valid_ref(name) {
            return Err(JobError::permanent(format!("credential {name:?} has an invalid name")));
        }
        let err = |what: &str| JobError::permanent(format!("credential {name:?} {what}"));
        let mut file = open_no_follow(&dir.join(name)).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => err("not found"),
            _ if is_symlink_error(&e) => err("is not a regular file"),
            _ => err("cannot be read"),
        })?;
        let meta = file.metadata().map_err(|_| err("cannot be read"))?;
        if !meta.is_file() {
            return Err(err("is not a regular file"));
        }
        if meta.len() > MAX_CREDENTIAL_BYTES {
            return Err(err("is too large"));
        }
        let mut value = Zeroizing::new(Vec::with_capacity(usize::try_from(MAX_CREDENTIAL_BYTES + 1).unwrap_or(0)));
        (&mut file).take(MAX_CREDENTIAL_BYTES + 1).read_to_end(&mut value).map_err(|_| err("cannot be read"))?;
        if u64::try_from(value.len()).unwrap_or(u64::MAX) > MAX_CREDENTIAL_BYTES {
            return Err(err("is too large"));
        }
        match kind {
            Kind::Token => {
                let len = trimmed_len(&value);
                value.truncate(len);
                let printable = std::str::from_utf8(&value).is_ok_and(|s| !s.chars().any(char::is_control));
                if value.is_empty() || !printable {
                    return Err(err("is empty or invalid"));
                }
            }
            Kind::SshKey => {
                let text = std::str::from_utf8(&value).unwrap_or_default();
                if !(text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----")) {
                    return Err(err("is empty or invalid"));
                }
            }
        }
        Ok(Self { kind, value })
    }

    /// Write a private copy into `dir` (the job's temp dir) and return its path.
    pub fn write_private_copy(&self, dir: &Path) -> Result<PathBuf, JobError> {
        let name = match self.kind {
            Kind::Token => "token",
            Kind::SshKey => "id_key",
        };
        let path = dir.join(name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options.open(&path).map_err(|_| JobError::retryable("cannot prepare credential"))?;
        file.write_all(&self.value).map_err(|_| JobError::retryable("cannot prepare credential"))?;
        Ok(path)
    }
}

fn trimmed_len(v: &[u8]) -> usize {
    v.iter().rposition(|&b| b != b'\n' && b != b'\r').map_or(0, |i| i + 1)
}

fn open_no_follow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    options.open(path)
}

fn is_symlink_error(e: &io::Error) -> bool {
    #[cfg(unix)]
    {
        e.raw_os_error() == Some(libc::ELOOP)
    }
    #[cfg(not(unix))]
    {
        let _ = e;
        false
    }
}

// ── askpass ─────────────────────────────────────────────────────────────────

/// Answer one git credential prompt for `host`: `Username for 'https://host': ` → the
/// username, `Password for 'https://user@host': ` → the token from `file`. A prompt for any
/// other URL (a proxy, a redirect target), any other prompt, or no file → `None`.
#[must_use]
pub fn askpass_answer(prompt: &OsStr, file: &Path, username: Option<&str>, host: &str) -> Option<Zeroizing<String>> {
    let prompt = prompt.to_str()?;
    if !prompt_is_for_host(prompt, host) {
        return None;
    }
    if prompt.starts_with("Username for ") {
        let user = username.filter(|u| !u.is_empty()).unwrap_or(DEFAULT_HTTPS_USERNAME);
        return Some(Zeroizing::new(user.to_owned()));
    }
    if !prompt.starts_with("Password for ") || file.as_os_str().is_empty() {
        return None;
    }
    let mut f = open_no_follow(file).ok()?;
    if !f.metadata().ok()?.is_file() {
        return None;
    }
    let mut value = Zeroizing::new(Vec::new());
    (&mut f).take(MAX_CREDENTIAL_BYTES).read_to_end(&mut value).ok()?;
    let len = trimmed_len(&value);
    value.truncate(len);
    let text = std::str::from_utf8(&value).ok()?;
    (!text.is_empty()).then(|| Zeroizing::new(text.to_owned()))
}

/// Does the prompt quote `https://[user@]host[:port]` followed by `'` or `/`?
fn prompt_is_for_host(prompt: &str, host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    let Some((_, quoted)) = prompt.split_once('\'') else { return false };
    let Some(url) = quoted.get(..8).filter(|s| s.eq_ignore_ascii_case("https://")).map(|_| &quoted[8..]) else {
        return false;
    };
    let end = url.find(['\'', '/']).unwrap_or(url.len());
    if end == url.len() {
        return false; // not terminated by ' or /
    }
    let authority = &url[..end];
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let (h, port) = host_port.split_once(':').map_or((host_port, None), |(h, p)| (h, Some(p)));
    port.is_none_or(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())) && h.eq_ignore_ascii_case(host)
}

/// Askpass mode of the binary (see `main.rs`): print the answer and return the exit code.
#[must_use]
pub fn askpass(prompt: &OsStr) -> i32 {
    let file = std::env::var_os(ASKPASS_FILE_VAR).unwrap_or_default();
    let username = std::env::var(ASKPASS_USERNAME_VAR).ok();
    let host = std::env::var(ASKPASS_HOST_VAR).unwrap_or_default();
    let Some(answer) = askpass_answer(prompt, Path::new(&file), username.as_deref(), &host) else {
        return 1;
    };
    let mut out = io::stdout().lock();
    let mut line = Zeroizing::new(Vec::with_capacity(answer.len() + 1));
    line.extend_from_slice(answer.as_bytes());
    line.push(b'\n');
    if out.write_all(&line).and_then(|()| out.flush()).is_err() {
        return 1;
    }
    0
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn dir() -> tempfile::TempDir {
        tempfile::TempDir::new().unwrap()
    }

    #[test]
    fn loads_tokens_and_keys() {
        let d = dir();
        std::fs::write(d.path().join("gh_token"), "tok-value-1234\n").unwrap();
        let c = Credential::load(d.path(), "gh_token", Kind::Token).unwrap();
        let job_dir = dir();
        let token = c.write_private_copy(job_dir.path()).unwrap();
        assert_eq!(std::fs::read(token).unwrap(), b"tok-value-1234", "trailing newline trimmed");
        assert!(!format!("{c:?}").contains("tok-value"), "Debug never shows the value");

        std::fs::write(
            d.path().join("deploy"),
            "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
        )
        .unwrap();
        let key = Credential::load(d.path(), "deploy", Kind::SshKey).unwrap();
        let job = dir();
        let path = key.write_private_copy(job.path()).unwrap();
        assert!(std::fs::read_to_string(&path).unwrap().ends_with("KEY-----\n"), "key kept verbatim");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn rejects_bad_files_without_leaking_content() {
        let d = dir();
        let msg = |name: &str, kind: Kind| Credential::load(d.path(), name, kind).unwrap_err().message;

        assert_eq!(msg("missing", Kind::Token), "credential \"missing\" not found");
        assert_eq!(msg("../etc", Kind::Token), "credential \"../etc\" has an invalid name");
        assert_eq!(msg("", Kind::Token), "credential \"\" has an invalid name");

        std::fs::write(d.path().join("big"), vec![b'a'; 20 * 1024]).unwrap();
        assert_eq!(msg("big", Kind::Token), "credential \"big\" is too large");

        std::fs::write(d.path().join("empty"), "\n").unwrap();
        assert_eq!(msg("empty", Kind::Token), "credential \"empty\" is empty or invalid");
        std::fs::write(d.path().join("ctrl"), "abc\u{1b}def").unwrap();
        assert_eq!(msg("ctrl", Kind::Token), "credential \"ctrl\" is empty or invalid");
        std::fs::write(d.path().join("notkey"), "super-secret-not-a-key").unwrap();
        let m = msg("notkey", Kind::SshKey);
        assert_eq!(m, "credential \"notkey\" is empty or invalid");
        assert!(!m.contains("super-secret"));

        std::fs::create_dir(d.path().join("adir")).unwrap();
        assert_eq!(msg("adir", Kind::Token), "credential \"adir\" is not a regular file");

        #[cfg(unix)]
        {
            let outside = dir();
            std::fs::write(outside.path().join("target"), "stolen-token").unwrap();
            std::os::unix::fs::symlink(outside.path().join("target"), d.path().join("link")).unwrap();
            assert_eq!(msg("link", Kind::Token), "credential \"link\" is not a regular file");
            let fifo = d.path().join("fifo");
            assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
            assert_eq!(msg("fifo", Kind::Token), "credential \"fifo\" is not a regular file");
        }
    }

    #[test]
    fn askpass_prompts() {
        let d = dir();
        let token = d.path().join("token");
        std::fs::write(&token, "tok-123\n").unwrap();
        let ask = |prompt: &str, file: &Path, user: Option<&str>| {
            askpass_answer(OsStr::new(prompt), file, user, "git.example").map(|z| z.to_string())
        };
        assert_eq!(ask("Username for 'https://git.example': ", &token, None).as_deref(), Some("x-access-token"));
        assert_eq!(ask("Username for 'https://git.example': ", &token, Some("bot")).as_deref(), Some("bot"));
        assert_eq!(ask("Password for 'https://bot@git.example': ", &token, None).as_deref(), Some("tok-123"));
        assert_eq!(ask("Password for 'https://git.example': ", Path::new(""), None), None, "no credential");
        assert_eq!(ask("Are you sure you want to continue connecting (yes/no)? ", &token, None), None);
        assert_eq!(ask("Enter passphrase for key: ", &token, None), None);
        #[cfg(unix)]
        {
            let link = d.path().join("link");
            std::os::unix::fs::symlink(&token, &link).unwrap();
            assert_eq!(ask("Password for 'https://git.example': ", &link, None), None, "never through a symlink");
        }
    }

    #[test]
    fn askpass_answers_only_for_the_source_host() {
        let d = dir();
        let token = d.path().join("token");
        std::fs::write(&token, "tok-123").unwrap();
        let ask = |prompt: &str| askpass_answer(OsStr::new(prompt), &token, None, "git.example").is_some();
        for ok in [
            "Password for 'https://git.example': ",
            "Password for 'https://bot@git.example': ",
            "Password for 'https://bot@GIT.Example:8443': ",
            "Username for 'HTTPS://git.example/': ",
            "Password for 'https://git.example/org/repo.git': ",
        ] {
            assert!(ask(ok), "{ok}");
        }
        for bad in [
            "Password for 'http://git.example': ",
            "Password for 'https://proxy.internal:3128': ",
            "Password for 'https://git.example.evil': ",
            "Password for 'https://evil@other.example': ",
            "Password for 'https://git.example:x': ",
            "Password for 'https://git.example",
            "Password for git.example: ",
            "Proxy password for 'https://git.example': ",
        ] {
            assert!(!ask(bad), "{bad}");
        }
        assert!(askpass_answer(OsStr::new("Password for 'https://git.example': "), &token, None, "").is_none());
    }

    #[test]
    fn credentials_are_bound_to_hosts() {
        let d = dir();
        std::fs::write(d.path().join("gh"), "tok").unwrap();
        let check = |name: &str, host: &str| check_host_binding(d.path(), name, host).map_err(|e| e.message);
        let refused = Err("credential \"gh\" is not allowed for this host".to_owned());
        assert_eq!(check("gh", "github.com"), refused, "no hosts file");
        std::fs::write(d.path().join("gh.hosts"), "# deploy hosts\n\nGitHub.com  # main\n  api.github.com\nbad host\n")
            .unwrap();
        assert_eq!(check("gh", "github.com"), Ok(()));
        assert_eq!(check("gh", "API.GITHUB.COM"), Ok(()));
        assert_eq!(check("gh", "gitlab.com"), refused);
        assert_eq!(check("gh", "bad"), refused, "malformed lines are ignored");
        assert_eq!(check("gh.hosts", "github.com").unwrap_err(), "credential \"gh.hosts\" has an invalid name");
        std::fs::write(d.path().join("big.hosts"), "a\n".repeat(3000)).unwrap();
        assert!(check("big", "a").is_err(), "oversized hosts file");
        #[cfg(unix)]
        {
            std::fs::write(d.path().join("real.hosts"), "github.com\n").unwrap();
            std::os::unix::fs::symlink(d.path().join("real.hosts"), d.path().join("ln.hosts")).unwrap();
            assert!(check("ln", "github.com").is_err(), "hosts file never through a symlink");
        }
        assert_eq!(parse_hosts("a.example\n-x\n.y\n#c\nB.example"), vec!["a.example", "b.example"]);
    }
}
