//! Git history source.
//!
//! **Scanning** reads every unique blob reachable from the selected revisions exactly once:
//!
//! ```text
//! git rev-list --objects <revs> → git cat-file --batch-check → (blob, size, path)
//!                                                  └─ wanted? → git cat-file --batch → content
//! ```
//!
//! A secret committed once and kept through 10 000 commits is one blob, read once.
//! **Locating** is a separate, later step for the few blobs that matched:
//! `git log --find-object=<blob>…` lists the commits that added or removed them.
//!
//! Git runs with a scrubbed environment: no inherited `GIT_DIR`/`GIT_INDEX_FILE` (we may
//! run inside a hook), no replace refs (they could hide a blob's real content), no lazy
//! fetching in partial clones, no prompts, no signature verification. Revisions are
//! validated and passed after `--end-of-options`, so a ref name cannot become an option.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::Serialize;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{DEFAULT_MAX_FILE_BYTES, Document, Locator, SourceError, Stats, Visit, decode_text};

/// Inherited variables that would point git at another repository, index or object store,
/// or change what objects mean.
pub const SCRUBBED_ENV: &[&str] = &[
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_NAMESPACE",
    "GIT_REPLACE_REF_BASE",
    "GIT_GRAFT_FILE",
    "GIT_SHALLOW_FILE",
    "GIT_EXTERNAL_DIFF",
    "GIT_TRACE",
    "GIT_TRACE2",
    "GIT_TRACE2_EVENT",
    "GIT_TRACE_PACKET",
    "GIT_TRACE_CURL",
    "GIT_CURL_VERBOSE",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
];

/// Environment every git invocation gets (after [`SCRUBBED_ENV`] is removed).
pub const GIT_BASE_ENV: &[(&str, &str)] = &[
    ("GIT_TERMINAL_PROMPT", "0"),
    ("GIT_NO_LAZY_FETCH", "1"),
    ("GIT_NO_REPLACE_OBJECTS", "1"),
    ("GIT_OPTIONAL_LOCKS", "0"),
    ("LC_ALL", "C"),
];

/// `-c` options every git invocation gets.
pub const GIT_BASE_CONFIG: &[&str] =
    &["-c", "core.fsmonitor=false", "-c", "log.showSignature=false", "-c", "color.ui=false"];

/// A hardened `git` command: inherited repository-redirecting variables removed, no
/// prompts, no lazy fetching, no replace refs, no fsmonitor, no signature checks; stdin
/// null, stdout and stderr piped. Callers add `-C <dir>` and the subcommand.
///
/// On Unix git runs in its own process group, so [`kill_process_group`] also stops the
/// helpers it starts (`git-remote-https`, `ssh`, `pack-objects`).
#[must_use]
pub fn git_command(git: &Path) -> Command {
    let mut cmd = Command::new(git);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        cmd.process_group(0);
    }
    for var in SCRUBBED_ENV {
        cmd.env_remove(var);
    }
    cmd.envs(GIT_BASE_ENV.iter().copied())
        .args(GIT_BASE_CONFIG)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// SIGKILL the process group led by `pid` (see [`git_command`]). Errors (already gone) are
/// ignored.
pub fn kill_process_group(pid: u32) {
    #[cfg(unix)]
    if let Some(pid) = i32::try_from(pid).ok().and_then(rustix::process::Pid::from_raw) {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
    #[cfg(not(unix))]
    let _ = pid;
}

/// How often a cancellation flag is checked while git runs.
const CANCEL_POLL: Duration = Duration::from_millis(25);

/// Most exclusions passed to `rev-list --stdin` in one scan.
pub const MAX_EXCLUDES: usize = 100_000;

/// Blobs per `git log` call when locating; keeps argv far below `ARG_MAX`.
const LOCATE_BATCH: usize = 500;

/// Longest accepted revision argument.
const MAX_REV_LEN: usize = 1024;

/// A git object name (SHA-1 or SHA-256), lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct ObjectId(String);

impl ObjectId {
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let valid = matches!(s.len(), 40 | 64) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        valid.then(|| Self(s.to_owned()))
    }

    fn parse_bytes(b: &[u8]) -> Option<Self> {
        std::str::from_utf8(b).ok().and_then(Self::parse)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn is_null(&self) -> bool {
        self.0.bytes().all(|b| b == b'0')
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone)]
pub struct GitOptions {
    /// Revisions to scan (`main`, `v1.0..HEAD`, `^<last-scanned>` for incremental scans);
    /// empty means every ref (`--all`).
    pub revs: Vec<String>,
    /// Larger blobs are skipped (counted in [`Stats::skipped_large`]).
    pub max_blob_bytes: u64,
    /// Commits to start from, passed on `rev-list`'s stdin instead of `revs` (any number
    /// fits). Used only when `revs` is empty; empty as well means every ref (`--all`).
    pub include: Vec<ObjectId>,
    /// Commits whose history is excluded (`^<oid>`): what an earlier scan covered. Passed
    /// on `rev-list`'s stdin, so any number fits (up to [`MAX_EXCLUDES`]).
    pub exclude: Vec<ObjectId>,
    /// After the history, also read every blob of this revision's tree that the history
    /// pass did not list (`HEAD`: the whole current state, even when the history is
    /// incremental). A revision that does not resolve (unborn `HEAD`) adds nothing.
    pub current_tree: Option<String>,
}

impl Default for GitOptions {
    fn default() -> Self {
        Self {
            revs: Vec::new(),
            max_blob_bytes: DEFAULT_MAX_FILE_BYTES,
            include: Vec::new(),
            exclude: Vec::new(),
            current_tree: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    /// The commit introduced the blob at this path (added or modified to it).
    Added,
    /// The commit removed or replaced it.
    Removed,
}

/// A commit where a blob appeared at or disappeared from a path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Occurrence {
    pub commit: ObjectId,
    /// Committer time, Unix seconds.
    pub time: i64,
    pub path: String,
    pub change: Change,
}

#[derive(Debug, Clone)]
pub struct GitRepo {
    dir: PathBuf,
    git: PathBuf,
    /// Once set, running git processes (and their helpers) are killed.
    cancel: Option<Arc<AtomicBool>>,
}

impl GitRepo {
    /// Open a repository (working tree or bare) with the `git` from `PATH`.
    pub fn open(dir: &Path) -> Result<Self, SourceError> {
        Self::open_with(dir, "git")
    }

    pub fn open_with(dir: &Path, git: impl Into<PathBuf>) -> Result<Self, SourceError> {
        let repo = Self { dir: dir.to_path_buf(), git: git.into(), cancel: None };
        let mut cmd = repo.command();
        cmd.args(["rev-parse", "--git-dir"]);
        let out = cmd.output().map_err(SourceError::GitSpawn)?;
        if !out.status.success() {
            return Err(SourceError::NotARepository(format!("{}: {}", dir.display(), summarize(&out.stderr))));
        }
        Ok(repo)
    }

    /// Kill every git this handle runs (with its process group) as soon as `flag` is set;
    /// the call in progress then fails.
    #[must_use]
    pub fn with_cancel(mut self, flag: Arc<AtomicBool>) -> Self {
        self.cancel = Some(flag);
        self
    }

    fn spawn(&self, name: &'static str, cmd: Command) -> Result<Proc, SourceError> {
        Proc::spawn(name, cmd, self.cancel.as_ref())
    }

    /// Does the command succeed? (stdout discarded)
    fn succeeds(&self, args: &[OsString]) -> Result<bool, SourceError> {
        let mut cmd = self.command();
        cmd.args(args).stdout(Stdio::null());
        let proc = self.spawn("rev-parse", cmd)?;
        Ok(proc.finish().is_ok())
    }

    fn command(&self) -> Command {
        let mut cmd = git_command(&self.git);
        cmd.arg("-C").arg(&self.dir);
        cmd
    }

    /// Run a short command and return its stdout.
    fn run(&self, name: &'static str, args: &[OsString]) -> Result<Vec<u8>, SourceError> {
        let mut cmd = self.command();
        cmd.args(args);
        let mut proc = self.spawn(name, cmd)?;
        let mut out = Vec::new();
        let read = proc.child.stdout.take().map(|mut s| s.read_to_end(&mut out));
        proc.finish()?;
        read.transpose().map_err(SourceError::GitIo)?;
        Ok(out)
    }

    /// Feed every unique blob reachable from `options.revs` to `visit`.
    ///
    /// The path in each [`Locator::Git`] is the first one `rev-list` met the blob under
    /// (cut at a newline in the file name); [`GitRepo::locate`] gives all of them.
    pub fn blobs(&self, options: &GitOptions, visit: &mut Visit<'_>) -> Result<Stats, SourceError> {
        let mut stats = Stats::default();
        if options.exclude.len() > MAX_EXCLUDES {
            return Err(SourceError::Revision(format!("more than {MAX_EXCLUDES} excluded commits")));
        }
        let revs = rev_args(&options.revs)?;
        // Blobs of the current tree the history pass has not listed yet.
        let mut pending = match &options.current_tree {
            Some(rev) => self.tree_entries(rev)?,
            None => HashMap::new(),
        };

        if options.include.len() > MAX_EXCLUDES {
            return Err(SourceError::Revision(format!("more than {MAX_EXCLUDES} start commits")));
        }
        let from_stdin = options.revs.is_empty() && !options.include.is_empty();
        let mut list = self.command();
        list.args(["rev-list", "--objects", "--missing=print"]);
        if from_stdin || !options.exclude.is_empty() {
            list.arg("--stdin").stdin(Stdio::piped());
        }
        if from_stdin {
            list.arg("--");
        } else {
            list.args(revs);
        }
        let mut list = self.spawn("rev-list", list)?;
        if let Some(mut stdin) = list.child.stdin.take() {
            // rev-list reads all of stdin before it writes anything: no pipe deadlock.
            let start_points = if from_stdin { options.include.as_slice() } else { &[] };
            for oid in start_points {
                writeln!(stdin, "{oid}").map_err(SourceError::GitIo)?;
            }
            for oid in &options.exclude {
                writeln!(stdin, "^{oid}").map_err(SourceError::GitIo)?;
            }
        }
        let list_out = list.child.stdout.take().ok_or(SourceError::GitProtocol("rev-list"))?;

        let mut check = self.command();
        check
            .args(["cat-file", "--buffer", "--batch-check=%(objecttype) %(objectname) %(objectsize) %(rest)"])
            .stdin(Stdio::from(list_out));
        let mut check = self.spawn("cat-file --batch-check", check)?;
        let mut objects = BufReader::new(check.child.stdout.take().ok_or(SourceError::GitProtocol("cat-file"))?);

        let mut reader = BlobReader::spawn(self)?;
        let mut line = Vec::new();
        loop {
            line.clear();
            if objects.read_until(b'\n', &mut line).map_err(SourceError::GitIo)? == 0 {
                break;
            }
            let entry = line.strip_suffix(b"\n").unwrap_or(&line);
            let mut fields = entry.splitn(4, |&b| b == b' ');
            let (kind, oid, size, path) = (fields.next(), fields.next(), fields.next(), fields.next());
            if oid == Some(b"missing") && size.is_none() {
                // "?<oid> missing": rev-list --missing=print reported an absent object.
                stats.skipped_missing += 1;
                continue;
            }
            let (Some(kind), Some(oid), Some(size)) = (kind, oid, size) else {
                return Err(SourceError::GitProtocol("cat-file --batch-check"));
            };
            if kind != b"blob" {
                continue;
            }
            let oid = ObjectId::parse_bytes(oid).ok_or(SourceError::GitProtocol("cat-file --batch-check"))?;
            let size = parse_u64(size).ok_or(SourceError::GitProtocol("cat-file --batch-check"))?;
            pending.remove(&oid);
            let path = String::from_utf8_lossy(path.unwrap_or_default()).into_owned();
            if reader.emit(oid, size, path, options.max_blob_bytes, &mut stats, visit)?.is_break() {
                return Ok(stats); // children are killed on drop
            }
        }
        list.finish()?;
        check.finish()?;

        let mut rest: Vec<(ObjectId, (String, u64))> = pending.into_iter().collect();
        rest.sort_unstable_by(|a, b| (a.1).0.cmp(&(b.1).0));
        for (oid, (path, size)) in rest {
            if reader.emit(oid, size, path, options.max_blob_bytes, &mut stats, visit)?.is_break() {
                return Ok(stats);
            }
        }
        reader.finish()?;
        Ok(stats)
    }

    /// Blobs of a revision's tree: id → (first path, size). Empty if it does not resolve.
    fn tree_entries(&self, rev: &str) -> Result<HashMap<ObjectId, (String, u64)>, SourceError> {
        let rev = validate_rev(rev)?;
        let mut verify = os_args(&["rev-parse", "--verify", "--quiet", "--end-of-options"]);
        verify.push(format!("{rev}^{{tree}}").into());
        if !self.succeeds(&verify)? {
            return Ok(HashMap::new());
        }
        let mut args = os_args(&["ls-tree", "-r", "-z", "-l", "--full-tree", "--end-of-options"]);
        args.push(rev.into());
        let out = self.run("ls-tree", &args)?;
        let mut entries = HashMap::new();
        for entry in out.split(|&b| b == 0).filter(|e| !e.is_empty()) {
            // "<mode> <type> <oid> <padded size>\t<path>"
            let (meta, path) = split_once(entry, b'\t').ok_or(SourceError::GitProtocol("ls-tree"))?;
            let mut meta = meta.split(|&b| b == b' ').filter(|f| !f.is_empty());
            let (_, kind, oid, size) = (meta.next(), meta.next(), meta.next(), meta.next());
            if kind != Some(b"blob") {
                continue; // submodule commits
            }
            let oid = oid.and_then(ObjectId::parse_bytes).ok_or(SourceError::GitProtocol("ls-tree"))?;
            let size = size.and_then(parse_u64).ok_or(SourceError::GitProtocol("ls-tree"))?;
            entries.entry(oid).or_insert_with(|| (String::from_utf8_lossy(path).into_owned(), size));
        }
        Ok(entries)
    }

    /// The configured URL of a remote (`remote.<name>.url`, as written in the config, without
    /// `insteadOf` rewriting), or `None` when the remote is not configured. May contain
    /// credentials (CI checkouts often embed a token): callers must strip them.
    pub fn remote_url(&self, remote: &str) -> Result<Option<String>, SourceError> {
        if remote.is_empty()
            || remote.starts_with('-')
            || !remote.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Ok(None);
        }
        let key = format!("remote.{remote}.url");
        let out = self.run("config", &os_args(&["config", "--default", "", "--get", &key]))?;
        let url = String::from_utf8_lossy(&out).trim().to_owned();
        Ok(Some(url).filter(|u| !u.is_empty()))
    }

    /// Commit ids the branches and tags point to (annotated tags peeled), sorted, unique.
    pub fn ref_tips(&self) -> Result<Vec<ObjectId>, SourceError> {
        let out = self.run(
            "for-each-ref",
            &os_args(&[
                "for-each-ref",
                "--format=%(objectname) %(objecttype) %(*objectname) %(*objecttype)",
                "refs/heads",
                "refs/tags",
            ]),
        )?;
        let mut tips = HashSet::new();
        for line in out.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
            let mut f = line.split(|&b| b == b' ');
            let (oid, kind, peeled, peeled_kind) = (f.next(), f.next(), f.next(), f.next());
            let commit = match (kind, peeled_kind) {
                (Some(b"commit"), _) => oid,
                (Some(b"tag"), Some(b"commit")) => peeled,
                _ => None, // tags of trees or blobs, nested tags: history is still scanned via --all
            };
            if let Some(c) = commit {
                tips.insert(ObjectId::parse_bytes(c).ok_or(SourceError::GitProtocol("for-each-ref"))?);
            }
        }
        let mut tips: Vec<_> = tips.into_iter().collect();
        tips.sort_unstable();
        Ok(tips)
    }

    /// Which of `ids` are commits present in the object store.
    pub fn existing_commits(&self, ids: &[ObjectId]) -> Result<HashSet<ObjectId>, SourceError> {
        if ids.is_empty() {
            return Ok(HashSet::new());
        }
        let mut cmd = self.command();
        cmd.args(["cat-file", "--batch-check=%(objectname) %(objecttype)"]).stdin(Stdio::piped());
        let mut proc = self.spawn("cat-file --batch-check", cmd)?;
        let mut stdin = proc.child.stdin.take().ok_or(SourceError::GitProtocol("cat-file"))?;
        let stdout = proc.child.stdout.take().ok_or(SourceError::GitProtocol("cat-file"))?;
        let mut found = HashSet::new();
        thread::scope(|s| {
            // cat-file answers while we write: feed it from another thread.
            let writer = s.spawn(move || -> io::Result<()> {
                for id in ids {
                    writeln!(stdin, "{id}")?;
                }
                Ok(())
            });
            for line in BufReader::new(stdout).split(b'\n') {
                let line = line.map_err(SourceError::GitIo)?;
                let mut f = line.split(|&b| b == b' ');
                if let (Some(id), Some(b"commit")) = (f.next(), f.next()) {
                    found.insert(ObjectId::parse_bytes(id).ok_or(SourceError::GitProtocol("cat-file"))?);
                }
            }
            writer.join().map_err(|_| SourceError::GitProtocol("cat-file"))?.map_err(SourceError::GitIo)
        })?;
        proc.finish()?;
        Ok(found)
    }

    /// Blobs in the `HEAD` tree with their paths: what is still "in the current state".
    /// An unborn `HEAD` (empty repository) gives an empty map.
    pub fn head_blobs(&self) -> Result<HashMap<ObjectId, Vec<String>>, SourceError> {
        if !self.succeeds(&os_args(&["rev-parse", "--verify", "--quiet", "HEAD^{tree}"]))? {
            return Ok(HashMap::new());
        }
        let out = self.run("ls-tree", &os_args(&["ls-tree", "-r", "-z", "--full-tree", "HEAD"]))?;
        let mut blobs: HashMap<ObjectId, Vec<String>> = HashMap::new();
        for entry in out.split(|&b| b == 0).filter(|e| !e.is_empty()) {
            // "<mode> <type> <oid>\t<path>"
            let (meta, path) = split_once(entry, b'\t').ok_or(SourceError::GitProtocol("ls-tree"))?;
            let mut meta = meta.split(|&b| b == b' ');
            let (_, kind, oid) = (meta.next(), meta.next(), meta.next());
            if kind != Some(b"blob") {
                continue; // submodule commits
            }
            let oid = oid.and_then(ObjectId::parse_bytes).ok_or(SourceError::GitProtocol("ls-tree"))?;
            blobs.entry(oid).or_default().push(String::from_utf8_lossy(path).into_owned());
        }
        Ok(blobs)
    }

    /// Commits under `revs` (empty: all refs) that added or removed any of `blobs`, per blob
    /// in topological order, parents first (timestamps alone are ambiguous: commits made in
    /// the same second, rewritten history). Merge commits are not diffed (as in plain `git log`), so a blob that
    /// first appears in a merge resolution has no occurrences.
    pub fn locate(
        &self,
        revs: &[String],
        blobs: &[ObjectId],
    ) -> Result<HashMap<ObjectId, Vec<Occurrence>>, SourceError> {
        let revs = rev_args(revs)?;
        let mut found: HashMap<ObjectId, Vec<Occurrence>> = HashMap::new();
        for chunk in blobs.chunks(LOCATE_BATCH) {
            let wanted: HashSet<&ObjectId> = chunk.iter().collect();
            let mut args = os_args(&[
                "log",
                "--no-color",
                "--topo-order",
                "--reverse",
                "--no-show-signature",
                "--no-ext-diff",
                "--raw",
                "--no-abbrev",
                "--no-renames",
                "-z",
                "--format=commit %H %ct",
            ]);
            args.extend(chunk.iter().map(|b| OsString::from(format!("--find-object={b}"))));
            args.extend(revs.iter().cloned());
            parse_log(&self.run("log", &args)?, &wanted, &mut found)?;
        }
        Ok(found)
    }
}

/// `-z` output of `git log --raw --format='commit %H %ct'`:
/// `commit <H> <T>\0\n:<mode> <mode> <old> <new> <status>\0<path>\0…`.
fn parse_log(
    out: &[u8],
    wanted: &HashSet<&ObjectId>,
    found: &mut HashMap<ObjectId, Vec<Occurrence>>,
) -> Result<(), SourceError> {
    const BAD: SourceError = SourceError::GitProtocol("log");
    let mut tokens = out.split(|&b| b == 0).map(|t| t.strip_prefix(b"\n").unwrap_or(t));
    let mut commit: Option<(ObjectId, i64)> = None;
    while let Some(token) = tokens.next() {
        if let Some(header) = token.strip_prefix(b"commit ") {
            let (id, time) = split_once(header, b' ').ok_or(BAD)?;
            let id = ObjectId::parse_bytes(id).ok_or(BAD)?;
            let time = std::str::from_utf8(time).ok().and_then(|t| t.trim().parse().ok()).ok_or(BAD)?;
            commit = Some((id, time));
        } else if let Some(meta) = token.strip_prefix(b":") {
            let path = tokens.next().ok_or(BAD)?;
            let (id, time) = commit.as_ref().ok_or(BAD)?;
            let mut fields = meta.split(|&b| b == b' ');
            let (_, _, old, new) = (fields.next(), fields.next(), fields.next(), fields.next());
            let old = old.and_then(ObjectId::parse_bytes).ok_or(BAD)?;
            let new = new.and_then(ObjectId::parse_bytes).ok_or(BAD)?;
            for (blob, change) in [(new, Change::Added), (old, Change::Removed)] {
                if !blob.is_null() && wanted.contains(&blob) {
                    found.entry(blob).or_default().push(Occurrence {
                        commit: id.clone(),
                        time: *time,
                        path: String::from_utf8_lossy(path).into_owned(),
                        change,
                    });
                }
            }
        } else if !token.is_empty() {
            return Err(BAD);
        }
    }
    Ok(())
}

/// `--all`, or the validated revisions after `--end-of-options`; then `--` so nothing is
/// taken for a path.
fn rev_args(revs: &[String]) -> Result<Vec<OsString>, SourceError> {
    let mut args = Vec::with_capacity(revs.len() + 2);
    if revs.is_empty() {
        args.push("--all".into());
    } else {
        args.push("--end-of-options".into());
        for rev in revs {
            args.push(validate_rev(rev)?.into());
        }
    }
    args.push("--".into());
    Ok(args)
}

fn validate_rev(rev: &str) -> Result<&str, SourceError> {
    let valid = !rev.is_empty()
        && rev.len() <= MAX_REV_LEN
        && !rev.starts_with('-')
        && !rev.chars().any(|c| c.is_whitespace() || c.is_control());
    if valid { Ok(rev) } else { Err(SourceError::Revision(rev.chars().take(80).collect())) }
}

fn os_args(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

fn split_once(b: &[u8], sep: u8) -> Option<(&[u8], &[u8])> {
    let i = b.iter().position(|&c| c == sep)?;
    Some((&b[..i], &b[i + 1..]))
}

fn parse_u64(b: &[u8]) -> Option<u64> {
    std::str::from_utf8(b).ok()?.parse().ok()
}

/// First line of git's stderr, printable ASCII only, bounded. Git does not print object
/// contents to stderr; this still keeps error messages short and log-safe.
fn summarize(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let line = text.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("no error output");
    line.chars().map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' }).take(300).collect()
}

/// `git cat-file --batch`, one blob per synchronous request.
struct BlobReader {
    proc: Proc,
    requests: std::process::ChildStdin,
    contents: ZeroizingReader,
}

impl BlobReader {
    fn spawn(repo: &GitRepo) -> Result<Self, SourceError> {
        let mut batch = repo.command();
        batch.args(["cat-file", "--batch"]).stdin(Stdio::piped());
        let mut proc = repo.spawn("cat-file --batch", batch)?;
        let requests = proc.child.stdin.take().ok_or(SourceError::GitProtocol("cat-file"))?;
        let contents = ZeroizingReader::new(proc.child.stdout.take().ok_or(SourceError::GitProtocol("cat-file"))?);
        Ok(Self { proc, requests, contents })
    }

    /// Read one blob (unless empty, too large, missing or binary) and hand it to `visit`.
    fn emit(
        &mut self,
        oid: ObjectId,
        size: u64,
        path: String,
        max_bytes: u64,
        stats: &mut Stats,
        visit: &mut Visit<'_>,
    ) -> Result<std::ops::ControlFlow<()>, SourceError> {
        use std::ops::ControlFlow;
        if size == 0 {
            return Ok(ControlFlow::Continue(()));
        }
        if size > max_bytes {
            stats.skipped_large += 1;
            return Ok(ControlFlow::Continue(()));
        }
        writeln!(self.requests, "{oid}").and_then(|()| self.requests.flush()).map_err(SourceError::GitIo)?;
        let Some(bytes) = self.contents.object(&oid)? else {
            stats.skipped_missing += 1;
            return Ok(ControlFlow::Continue(()));
        };
        let len = bytes.len();
        let Some((text, encoding)) = decode_text(bytes) else {
            stats.skipped_binary += 1;
            return Ok(ControlFlow::Continue(()));
        };
        stats.document(len);
        Ok(visit(Document { locator: Locator::Git { blob: oid, path }, text, encoding, truncated: false }))
    }

    fn finish(self) -> Result<(), SourceError> {
        drop(self.requests);
        self.proc.finish()
    }
}

/// A child process whose stderr is drained by a thread (a full stderr pipe would block it)
/// and which is killed, with its process group, if dropped before [`Proc::finish`] or once
/// the cancellation flag is set.
struct Proc {
    name: &'static str,
    child: Child,
    stderr: Option<JoinHandle<Vec<u8>>>,
    /// Set when the child has been waited for: stops the watchdog.
    done: Arc<AtomicBool>,
}

impl Proc {
    fn spawn(name: &'static str, mut cmd: Command, cancel: Option<&Arc<AtomicBool>>) -> Result<Self, SourceError> {
        let mut child = cmd.spawn().map_err(SourceError::GitSpawn)?;
        let stderr = child.stderr.take().map(|mut pipe| {
            thread::spawn(move || {
                let mut head = Vec::new();
                let _ = (&mut pipe).take(4096).read_to_end(&mut head);
                let _ = io::copy(&mut pipe, &mut io::sink());
                head
            })
        });
        let done = Arc::new(AtomicBool::new(false));
        if let Some(cancel) = cancel {
            let (cancel, done, pid) = (Arc::clone(cancel), Arc::clone(&done), child.id());
            thread::spawn(move || {
                while !done.load(Ordering::Acquire) {
                    if cancel.load(Ordering::Relaxed) {
                        kill_process_group(pid);
                        break;
                    }
                    thread::sleep(CANCEL_POLL);
                }
            });
        }
        Ok(Self { name, child, stderr, done })
    }

    fn finish(mut self) -> Result<(), SourceError> {
        let status = self.child.wait().map_err(SourceError::GitIo)?;
        self.done.store(true, Ordering::Release);
        let stderr = self.stderr.take().and_then(|h| h.join().ok()).unwrap_or_default();
        if status.success() {
            Ok(())
        } else {
            Err(SourceError::Git { command: self.name, message: summarize(&stderr) })
        }
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        if !self.done.swap(true, Ordering::AcqRel) {
            kill_process_group(self.child.id());
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Buffered reader over `cat-file --batch` whose buffer is wiped on drop (a `BufReader`
/// would free its last chunk of blob content without zeroizing it).
struct ZeroizingReader {
    inner: ChildStdout,
    buf: Zeroizing<Vec<u8>>,
    pos: usize,
    filled: usize,
}

impl ZeroizingReader {
    fn new(inner: ChildStdout) -> Self {
        Self { inner, buf: Zeroizing::new(vec![0; 64 * 1024]), pos: 0, filled: 0 }
    }

    /// Read one `--batch` response: `<oid> blob <size>\n<content>\n` or `<oid> missing\n`.
    fn object(&mut self, oid: &ObjectId) -> Result<Option<Zeroizing<Vec<u8>>>, SourceError> {
        const BAD: SourceError = SourceError::GitProtocol("cat-file --batch");
        let mut header = Vec::new();
        self.read_until(b'\n', &mut header).map_err(SourceError::GitIo)?;
        let header = header.strip_suffix(b"\n").ok_or(BAD)?;
        let mut fields = header.split(|&b| b == b' ');
        if fields.next() != Some(oid.as_str().as_bytes()) {
            return Err(BAD);
        }
        match (fields.next(), fields.next()) {
            (Some(b"missing"), None) => Ok(None),
            (Some(b"blob"), Some(size)) => {
                let size = parse_u64(size).and_then(|s| usize::try_from(s).ok()).ok_or(BAD)?;
                let mut content = Zeroizing::new(vec![0; size]);
                self.read_exact(&mut content).map_err(SourceError::GitIo)?;
                let mut newline = [0u8; 1];
                self.read_exact(&mut newline).map_err(SourceError::GitIo)?;
                if newline != *b"\n" {
                    return Err(BAD);
                }
                Ok(Some(content))
            }
            _ => Err(BAD),
        }
    }
}

impl Read for ZeroizingReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let n = available.len().min(out.len());
        out[..n].copy_from_slice(&available[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for ZeroizingReader {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.pos >= self.filled {
            self.buf[..self.filled].zeroize();
            self.filled = self.inner.read(&mut self.buf)?;
            self.pos = 0;
        }
        Ok(&self.buf[self.pos..self.filled])
    }

    fn consume(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.filled);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_ids() {
        assert!(ObjectId::parse(&"a".repeat(40)).is_some());
        assert!(ObjectId::parse(&"0".repeat(64)).is_some_and(|o| o.is_null()));
        assert!(ObjectId::parse(&"A".repeat(40)).is_none());
        assert!(ObjectId::parse("abc").is_none());
    }

    #[test]
    fn revisions_are_validated() {
        assert_eq!(rev_args(&[]).unwrap_or_default(), os_args(&["--all", "--"]));
        let ok = rev_args(&["main".into(), "^v1.0".into(), "HEAD~3..HEAD".into()]).unwrap_or_default();
        assert_eq!(ok.first().map(OsString::as_os_str), Some("--end-of-options".as_ref()));
        for bad in ["--output=/tmp/x", "", "a b", "a\nb"] {
            assert!(matches!(rev_args(&[bad.into()]), Err(SourceError::Revision(_))), "{bad:?}");
        }
    }

    #[test]
    fn log_parsing() {
        let a = "a".repeat(40);
        let b = "b".repeat(40);
        let c = "c".repeat(40);
        let z = "0".repeat(40);
        let out = format!(
            "commit {c} 200\0\n:100644 000000 {a} {z} D\0x/a\0:100644 100644 {z} {b} A\0y\0\
             commit {b} 100\0\n:000000 100644 {z} {a} A\0x/a\0"
        );
        let blob_a = ObjectId(a);
        let wanted: HashSet<&ObjectId> = [&blob_a].into_iter().collect();
        let mut found = HashMap::new();
        parse_log(out.as_bytes(), &wanted, &mut found).unwrap_or_else(|e| panic!("{e}"));
        let occ = &found[&blob_a];
        assert_eq!(occ.len(), 2, "blob b is not wanted");
        assert_eq!((occ[0].change, occ[0].time, occ[0].path.as_str()), (Change::Removed, 200, "x/a"));
        assert_eq!((occ[1].change, occ[1].time), (Change::Added, 100));
        assert!(parse_log(b"garbage\0", &wanted, &mut found).is_err());
    }

    #[test]
    fn stderr_summary_is_bounded_and_printable() {
        assert_eq!(summarize(b"\nfatal: bad revision 'x\x1b[31m'\nmore"), "fatal: bad revision 'x?[31m'");
        assert_eq!(summarize(&[b'e'; 1000]).len(), 300);
        assert_eq!(summarize(b""), "no error output");
    }
}
