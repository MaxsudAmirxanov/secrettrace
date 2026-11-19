//! Mirror maintenance: `git init --bare` once per source, then `git fetch` of branches and
//! tags only (`refs/pull/*` and other hosting refs are left out).
//!
//! Every invocation starts from an empty environment (only `PATH`, proxy and CA variables
//! are passed through), with `HOME` in the job's private temp dir, no system or global
//! config, an explicit protocol allowlist, no redirects, no credential helpers, no hooks,
//! object checks on receipt and stall timeouts. Credentials reach git only through
//! `GIT_ASKPASS` (a file path, answered only for the source host) or ssh's `IdentityFile`.
//!
//! git runs in its own process group; dropping the future (job timeout, cancellation,
//! shutdown, size limit) kills the whole group, helpers included. Output is read with
//! bounds, and nothing git or the remote prints is stored: failures map to fixed messages.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _};

use super::JobError;
use super::remote::{Remote, Transport};

/// Variables passed through to git from the worker's environment.
const PASSED_ENV: &[&str] = &[
    "PATH",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "GIT_SSL_CAINFO",
];

/// stderr kept for classifying a failure (the rest is drained).
const MAX_STDERR: u64 = 8 * 1024;
/// stdout of `ls-remote`, `for-each-ref`, `config`.
const MAX_STDOUT: u64 = 16 * 1024 * 1024;
/// How often the mirror size is checked during a fetch.
const SIZE_POLL: Duration = Duration::from_secs(2);

/// What one job's git invocations need.
pub struct GitEnv<'a> {
    pub git: &'a Path,
    pub uri: &'a str,
    pub remote: &'a Remote,
    /// The job's private temp dir (`HOME`).
    pub home: &'a Path,
    pub askpass: &'a Path,
    /// Temp copy of the https token, if any.
    pub token_file: Option<PathBuf>,
    pub username: Option<&'a str>,
    /// Temp copy of the ssh key, if any.
    pub ssh_key: Option<PathBuf>,
    pub known_hosts: Option<&'a Path>,
    /// The fetch is stopped once `objects/` grows past this.
    pub max_repo_bytes: u64,
}

impl std::fmt::Debug for GitEnv<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitEnv").field("remote", self.remote).finish_non_exhaustive()
    }
}

/// Kills the process group of a running git when dropped before [`GroupGuard::disarm`].
struct GroupGuard(Option<u32>);

impl GroupGuard {
    fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for GroupGuard {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            st_source::kill_process_group(pid);
        }
    }
}

impl GitEnv<'_> {
    fn command(&self, dir: Option<&Path>) -> Result<tokio::process::Command, JobError> {
        let mut cmd = st_source::git_command(self.git);
        cmd.env_clear().envs(st_source::GIT_BASE_ENV.iter().copied());
        for var in PASSED_ENV {
            if let Some(v) = std::env::var_os(var) {
                cmd.env(var, v);
            }
        }
        if std::env::var_os("PATH").is_none() {
            cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin");
        }
        let local = self.remote.transport == Transport::Local;
        let protocols = if local { "https:ssh:file" } else { "https:ssh" };
        cmd.env("HOME", self.home)
            .env("XDG_CONFIG_HOME", self.home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_ALLOW_PROTOCOL", protocols)
            .env("GIT_ASKPASS", self.askpass)
            .env(super::credentials::ASKPASS_FILE_VAR, self.token_file.as_deref().unwrap_or(Path::new("")))
            .env(super::credentials::ASKPASS_USERNAME_VAR, self.username.unwrap_or_default())
            .env(super::credentials::ASKPASS_HOST_VAR, &self.remote.host)
            .env("GIT_SSH_COMMAND", self.ssh_command()?)
            .env("GIT_SSH_VARIANT", "ssh");
        cmd.args([
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.https.allow=always",
            "-c",
            "protocol.ssh.allow=always",
        ]);
        if local {
            cmd.args(["-c", "protocol.file.allow=always"]);
        }
        for setting in [
            "http.followRedirects=false",
            "http.lowSpeedLimit=1000",
            "http.lowSpeedTime=60",
            "credential.helper=",
            "core.askPass=",
            "core.hooksPath=/dev/null",
            "fetch.recurseSubmodules=false",
            "submodule.recurse=false",
            "transfer.fsckObjects=true",
            "transfer.credentialsInUrl=die",
            "gc.auto=0",
            "maintenance.auto=false",
            "init.defaultBranch=main",
        ] {
            cmd.args(["-c", setting]);
        }
        if let Some(dir) = dir {
            cmd.arg("-C").arg(dir);
        }
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut cmd = tokio::process::Command::from(cmd);
        cmd.kill_on_drop(true);
        Ok(cmd)
    }

    /// `GIT_SSH_COMMAND` (run by git through `sh -c`): every path single-quoted.
    fn ssh_command(&self) -> Result<String, JobError> {
        let quote = |p: &Path| -> Result<String, JobError> {
            let s = p.to_str().filter(|s| !s.contains('\'')).ok_or_else(|| JobError::permanent("unusable path"))?;
            Ok(format!("'{s}'"))
        };
        let mut cmd = String::from(
            "ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
             -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o ControlMaster=no \
             -o ControlPath=none -o ProxyCommand=none -o ProxyJump=none -o ForwardAgent=no \
             -o PermitLocalCommand=no -o UpdateHostKeys=no -o ConnectTimeout=30 \
             -o ServerAliveInterval=15 -o ServerAliveCountMax=4",
        );
        let known_hosts = self.known_hosts.map(quote).transpose()?.unwrap_or_else(|| "/dev/null".into());
        let _ = write!(cmd, " -o UserKnownHostsFile={known_hosts} -o GlobalKnownHostsFile=/dev/null");
        if let Some(key) = &self.ssh_key {
            let _ = write!(cmd, " -o IdentityFile={}", quote(key)?);
        } else {
            cmd.push_str(" -o IdentityFile=none");
        }
        if self.remote.user.is_none()
            && let Some(user) = self.username
        {
            let ok = !user.starts_with('-')
                && user.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'@'));
            if !ok {
                return Err(JobError::permanent("invalid source username"));
            }
            let _ = write!(cmd, " -o User='{user}'");
        }
        Ok(cmd)
    }

    async fn run(&self, name: &str, dir: Option<&Path>, args: &[&str]) -> Result<Vec<u8>, JobError> {
        let mut cmd = self.command(dir)?;
        cmd.args(args);
        let mut child = cmd.spawn().map_err(|_| JobError::retryable("cannot run git"))?;
        let guard = GroupGuard(child.id());
        let (stdout, stderr) = (child.stdout.take(), child.stderr.take());
        let (out, err) = tokio::join!(read_limited(stdout, MAX_STDOUT), read_head(stderr, MAX_STDERR));
        let status = child.wait().await.map_err(|_| JobError::retryable("cannot run git"))?;
        guard.disarm();
        let out = out.ok_or_else(|| JobError::retryable(format!("git {name} output is too large")))?;
        if status.success() { Ok(out) } else { Err(classify(name, &err)) }
    }

    /// Bring `<mirror>` up to date with the remote: branches, tags and the default branch.
    pub async fn sync_mirror(&self, mirror: &Path) -> Result<(), JobError> {
        self.prepare(mirror).await?;
        let fetch = self.run(
            "fetch",
            Some(mirror),
            &[
                "fetch",
                "--prune",
                "--no-tags",
                "--no-recurse-submodules",
                "--no-write-fetch-head",
                "--quiet",
                "origin",
                "+refs/heads/*:refs/heads/*",
                "+refs/tags/*:refs/tags/*",
            ],
        );
        let objects = mirror.join("objects");
        let too_big = async {
            loop {
                tokio::time::sleep(SIZE_POLL).await;
                if self.exceeds_limit(&objects).await {
                    return;
                }
            }
        };
        tokio::select! {
            r = fetch => { r?; }
            () = too_big => return Err(size_error()),
        }
        if self.exceeds_limit(&objects).await {
            return Err(size_error());
        }
        self.set_head(mirror).await
    }

    async fn exceeds_limit(&self, objects: &Path) -> bool {
        let dir = objects.to_path_buf();
        let size = tokio::task::spawn_blocking(move || dir_size(&dir)).await.unwrap_or(0);
        size > self.max_repo_bytes
    }

    /// An existing mirror of the same URI is reused; anything else at that path is replaced.
    async fn prepare(&self, mirror: &Path) -> Result<(), JobError> {
        let io_err = |_| JobError::retryable("cannot prepare the mirror directory");
        match tokio::fs::symlink_metadata(mirror).await {
            Ok(meta) if meta.is_dir() => {
                let url = self.run("config", Some(mirror), &["config", "--get", "remote.origin.url"]).await;
                if url.as_deref().ok().map(|u| String::from_utf8_lossy(u).trim_end().to_owned()).as_deref()
                    == Some(self.uri)
                {
                    return Ok(());
                }
                tokio::fs::remove_dir_all(mirror).await.map_err(io_err)?;
            }
            Ok(_) => tokio::fs::remove_file(mirror).await.map_err(io_err)?,
            Err(_) => {}
        }
        let path = mirror.to_str().ok_or_else(|| JobError::permanent("unusable path"))?;
        self.run("init", None, &["init", "--bare", "--quiet", "--", path]).await?;
        self.run("config", Some(mirror), &["config", "remote.origin.url", self.uri]).await?;
        Ok(())
    }

    /// Point `HEAD` at the remote's default branch (as `ls-remote --symref` reports it),
    /// falling back to `main`, `master` or a single branch.
    async fn set_head(&self, mirror: &Path) -> Result<(), JobError> {
        let dir = Some(mirror);
        let out = self.run("ls-remote", dir, &["ls-remote", "--symref", "origin", "HEAD"]).await?;
        let advertised = String::from_utf8_lossy(&out)
            .lines()
            .find_map(|l| l.strip_prefix("ref: ")?.strip_suffix("\tHEAD").map(str::to_owned))
            .filter(|r| valid_branch_ref(r));
        let target = if let Some(r) = advertised {
            Some(r)
        } else {
            let out = self.run("for-each-ref", dir, &["for-each-ref", "--format=%(refname)", "refs/heads"]).await?;
            let text = String::from_utf8_lossy(&out);
            let branches: Vec<&str> = text.lines().filter(|r| valid_branch_ref(r)).collect();
            ["refs/heads/main", "refs/heads/master"]
                .into_iter()
                .find(|b| branches.contains(b))
                .or_else(|| (branches.len() == 1).then(|| branches[0]))
                .map(str::to_owned)
        };
        if let Some(target) = target {
            self.run("symbolic-ref", dir, &["symbolic-ref", "HEAD", &target]).await?;
        }
        Ok(())
    }
}

fn size_error() -> JobError {
    JobError::permanent("repository exceeds the size limit")
}

/// Everything up to `limit` bytes, or `None` if there is more (the child is then killed by
/// its guard when the caller gives up).
async fn read_limited(pipe: Option<impl AsyncRead + Unpin>, limit: u64) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    if let Some(pipe) = pipe {
        pipe.take(limit + 1).read_to_end(&mut out).await.ok()?;
    }
    (u64::try_from(out.len()).unwrap_or(u64::MAX) <= limit).then_some(out)
}

/// The first `limit` bytes; the rest is read and discarded so the child never blocks.
async fn read_head(pipe: Option<impl AsyncRead + Unpin>, limit: u64) -> Vec<u8> {
    let mut head = Vec::new();
    if let Some(mut pipe) = pipe {
        let _ = (&mut pipe).take(limit).read_to_end(&mut head).await;
        let _ = tokio::io::copy(&mut pipe, &mut tokio::io::sink()).await;
    }
    head
}

/// Bytes of regular files under `dir`, without following symlinks.
fn dir_size(dir: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else { continue };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue }; // DirEntry::metadata does not follow symlinks
            if meta.is_dir() {
                stack.push(entry.path());
            } else if meta.is_file() {
                total = total.saturating_add(meta.len());
            }
        }
    }
    total
}

fn valid_branch_ref(r: &str) -> bool {
    r.strip_prefix("refs/heads/").is_some_and(|name| {
        !name.is_empty()
            && !name.starts_with('-')
            && !name.contains("..")
            && !name.chars().any(|c| c.is_control() || c.is_whitespace() || "~^:?*[\\".contains(c))
    })
}

/// Failure categories, checked in order against git's own stderr lines (never `remote:`
/// lines, which the server controls). Only the category is stored.
const CATEGORIES: &[(&str, &[&str])] = &[
    ("timed out", &["timed out", "operation too slow", "timeout"]),
    (
        "authentication failed",
        &[
            "authentication failed",
            "could not read username",
            "could not read password",
            "permission denied (publickey",
            "terminal prompts disabled",
            "invalid username or password",
            "returned error: 401",
        ],
    ),
    ("host key verification failed", &["host key verification failed", "no matching host key"]),
    ("TLS error", &["ssl", "tls", "certificate", "gnutls"]),
    (
        "could not connect",
        &[
            "could not resolve host",
            "could not resolve hostname",
            "connection refused",
            "failed to connect",
            "couldn't connect",
            "network is unreachable",
            "no route to host",
            "connection reset",
            "connection closed",
        ],
    ),
    (
        "repository not found or access denied",
        &[
            "not found",
            "does not appear to be a git repository",
            "returned error: 403",
            "access denied",
            "does not exist",
        ],
    ),
    (
        "remote rejected the request",
        &["rejected", "remote error", "returned error", "protocol error", "unexpected disconnect"],
    ),
];

/// A fixed message for a failed git command: `git <name> failed[: <category>]`.
#[must_use]
pub fn classify(name: &str, stderr: &[u8]) -> JobError {
    let text = String::from_utf8_lossy(stderr);
    let own: String = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.to_ascii_lowercase().starts_with("remote:"))
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join("\n");
    let category = CATEGORIES.iter().find(|(_, needles)| needles.iter().any(|n| own.contains(n))).map(|(c, _)| *c);
    let retryable = !matches!(category, Some("host key verification failed"));
    let message = match category {
        Some(c) => format!("git {name} failed: {c}"),
        None => format!("git {name} failed"),
    };
    JobError { message, retryable }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_map_to_fixed_messages() {
        let m = |stderr: &str| classify("fetch", stderr.as_bytes()).message;
        assert_eq!(
            m("fatal: Authentication failed for 'https://bot:tok-SECRET@git.example/a.git/'\n"),
            "git fetch failed: authentication failed"
        );
        assert_eq!(
            m("remote: Repository not found.\nfatal: repository 'https://git.example/a/' not found\n"),
            "git fetch failed: repository not found or access denied"
        );
        assert_eq!(
            m("fatal: unable to access 'https://x/': Could not resolve host: x\n"),
            "git fetch failed: could not connect"
        );
        assert_eq!(
            m("fatal: unable to access 'https://x/': SSL certificate problem: self-signed\n"),
            "git fetch failed: TLS error"
        );
        assert_eq!(m("error: RPC failed; curl 28 Operation too slow.\n"), "git fetch failed: timed out");
        assert_eq!(
            m("Host key verification failed.\nfatal: Could not read from remote repository.\n"),
            "git fetch failed: host key verification failed"
        );
        assert!(!classify("fetch", b"Host key verification failed.\n").retryable);
        assert_eq!(m("git@x: Permission denied (publickey).\n"), "git fetch failed: authentication failed");
        assert_eq!(
            m("fatal: The remote end hung up unexpectedly\nerror: remote rejected\n"),
            "git fetch failed: remote rejected the request"
        );
        assert_eq!(m(""), "git fetch failed");
        assert_eq!(classify("ls-remote", b"weird").message, "git ls-remote failed");
    }

    #[test]
    fn remote_lines_never_survive() {
        // A hostile server prints its own text, including words that look like categories.
        let hostile = "remote: please visit https://evil.example/?t=tok-SECRET authentication failed\n\
                       remote: \u{1b}[31mnot found\n";
        let e = classify("fetch", hostile.as_bytes());
        assert_eq!(e.message, "git fetch failed");
        assert!(!e.message.contains("evil") && !e.message.contains("SECRET"));
        let mixed = format!("{hostile}fatal: unable to access: Connection refused\n");
        assert_eq!(classify("fetch", mixed.as_bytes()).message, "git fetch failed: could not connect");
    }

    #[tokio::test]
    async fn output_is_read_with_bounds() {
        let big = [b'x'; 100];
        assert_eq!(read_limited(Some(&big[..]), 100).await.map(|v| v.len()), Some(100));
        assert_eq!(read_limited(Some(&big[..]), 99).await, None, "too much output is refused");
        assert_eq!(read_limited(None::<&[u8]>, 10).await, Some(Vec::new()));
        let head = read_head(Some(&big[..]), 10).await;
        assert_eq!(head.len(), 10, "stderr is cut, the rest drained");
    }

    #[test]
    fn branch_refs() {
        assert!(valid_branch_ref("refs/heads/main"));
        assert!(valid_branch_ref("refs/heads/release/1.0"));
        for bad in ["refs/tags/v1", "refs/heads/", "refs/heads/-x", "refs/heads/a..b", "refs/heads/a b", "main"] {
            assert!(!valid_branch_ref(bad), "{bad}");
        }
    }

    #[test]
    fn mirror_size_ignores_symlinks() {
        let d = tempfile::TempDir::new().unwrap_or_else(|e| panic!("{e}"));
        std::fs::create_dir(d.path().join("pack")).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(d.path().join("pack/a"), [0u8; 1000]).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(d.path().join("b"), [0u8; 24]).unwrap_or_else(|e| panic!("{e}"));
        #[cfg(unix)]
        std::os::unix::fs::symlink("/usr", d.path().join("link")).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(dir_size(d.path()), 1024);
    }

    #[test]
    fn ssh_command_quotes_paths_and_never_uses_agents() {
        let remote = Remote { transport: Transport::Ssh, host: "git.example".into(), user: None };
        let env = GitEnv {
            git: Path::new("git"),
            uri: "ssh://git.example/a.git",
            remote: &remote,
            home: Path::new("/tmp/h"),
            askpass: Path::new("/bin/false"),
            token_file: None,
            username: Some("git"),
            ssh_key: Some(PathBuf::from("/tmp/h/id_key")),
            known_hosts: Some(Path::new("/etc/kh")),
            max_repo_bytes: 1,
        };
        let cmd = env.ssh_command().unwrap_or_default();
        assert!(cmd.contains("-o IdentityFile='/tmp/h/id_key'"), "{cmd}");
        assert!(cmd.contains("-o UserKnownHostsFile='/etc/kh'"), "{cmd}");
        assert!(cmd.contains("-o User='git'") && cmd.contains("BatchMode=yes") && cmd.contains("ForwardAgent=no"));
        assert!(cmd.contains("ConnectTimeout=30") && cmd.contains("ServerAliveInterval=15"));
        let quoted = GitEnv { ssh_key: Some(PathBuf::from("/tmp/it's")), ..env };
        assert!(quoted.ssh_command().is_err());
    }
}
