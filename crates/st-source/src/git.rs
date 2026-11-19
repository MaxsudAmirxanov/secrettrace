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
use std::thread::{self, JoinHandle};

use serde::Serialize;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{DEFAULT_MAX_FILE_BYTES, Document, Locator, SourceError, Stats, Visit, decode_text};

/// Inherited variables that would point git at another repository, index or object store,
/// or change what objects mean.
const SCRUBBED_ENV: &[&str] = &[
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
];

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
}

impl Default for GitOptions {
    fn default() -> Self {
        Self { revs: Vec::new(), max_blob_bytes: DEFAULT_MAX_FILE_BYTES }
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
}

impl GitRepo {
    /// Open a repository (working tree or bare) with the `git` from `PATH`.
    pub fn open(dir: &Path) -> Result<Self, SourceError> {
        Self::open_with(dir, "git")
    }

    pub fn open_with(dir: &Path, git: impl Into<PathBuf>) -> Result<Self, SourceError> {
        let repo = Self { dir: dir.to_path_buf(), git: git.into() };
        let out = repo.command().args(["rev-parse", "--git-dir"]).output().map_err(SourceError::GitSpawn)?;
        if !out.status.success() {
            return Err(SourceError::NotARepository(format!("{}: {}", dir.display(), summarize(&out.stderr))));
        }
        Ok(repo)
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(&self.git);
        for var in SCRUBBED_ENV {
            cmd.env_remove(var);
        }
        cmd.env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("LC_ALL", "C")
            .arg("-C")
            .arg(&self.dir)
            .args(["-c", "core.fsmonitor=false", "-c", "log.showSignature=false", "-c", "color.ui=false"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }

    /// Run a short command and return its stdout.
    fn run(&self, name: &'static str, args: &[OsString]) -> Result<Vec<u8>, SourceError> {
        let out = self.command().args(args).output().map_err(SourceError::GitSpawn)?;
        if !out.status.success() {
            return Err(SourceError::Git { command: name, message: summarize(&out.stderr) });
        }
        Ok(out.stdout)
    }

    /// Feed every unique blob reachable from `options.revs` to `visit`.
    ///
    /// The path in each [`Locator::Git`] is the first one `rev-list` met the blob under
    /// (cut at a newline in the file name); [`GitRepo::locate`] gives all of them.
    pub fn blobs(&self, options: &GitOptions, visit: &mut Visit<'_>) -> Result<Stats, SourceError> {
        let mut stats = Stats::default();

        let mut list = self.command();
        list.args(["rev-list", "--objects", "--missing=print"]).args(rev_args(&options.revs)?);
        let mut list = Proc::spawn("rev-list", list)?;
        let list_out = list.child.stdout.take().ok_or(SourceError::GitProtocol("rev-list"))?;

        let mut check = self.command();
        check
            .args(["cat-file", "--buffer", "--batch-check=%(objecttype) %(objectname) %(objectsize) %(rest)"])
            .stdin(Stdio::from(list_out));
        let mut check = Proc::spawn("cat-file --batch-check", check)?;
        let mut objects = BufReader::new(check.child.stdout.take().ok_or(SourceError::GitProtocol("cat-file"))?);

        let mut batch = self.command();
        batch.args(["cat-file", "--batch"]).stdin(Stdio::piped());
        let mut batch = Proc::spawn("cat-file --batch", batch)?;
        let mut requests = batch.child.stdin.take().ok_or(SourceError::GitProtocol("cat-file"))?;
        let mut contents = ZeroizingReader::new(batch.child.stdout.take().ok_or(SourceError::GitProtocol("cat-file"))?);

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
            if size == 0 {
                continue;
            }
            if size > options.max_blob_bytes {
                stats.skipped_large += 1;
                continue;
            }

            writeln!(requests, "{oid}").and_then(|()| requests.flush()).map_err(SourceError::GitIo)?;
            let Some(bytes) = contents.object(&oid)? else {
                stats.skipped_missing += 1;
                continue;
            };
            let len = bytes.len();
            let Some((text, encoding)) = decode_text(bytes) else {
                stats.skipped_binary += 1;
                continue;
            };
            stats.document(len);
            let path = String::from_utf8_lossy(path.unwrap_or_default()).into_owned();
            let doc = Document { locator: Locator::Git { blob: oid, path }, text, encoding, truncated: false };
            if visit(doc).is_break() {
                return Ok(stats); // children are killed on drop
            }
        }
        drop(requests);
        list.finish()?;
        check.finish()?;
        batch.finish()?;
        Ok(stats)
    }

    /// Blobs in the `HEAD` tree with their paths: what is still "in the current state".
    /// An unborn `HEAD` (empty repository) gives an empty map.
    pub fn head_blobs(&self) -> Result<HashMap<ObjectId, Vec<String>>, SourceError> {
        let mut verify = self.command();
        verify.args(["rev-parse", "--verify", "--quiet", "HEAD^{tree}"]);
        if !verify.output().map_err(SourceError::GitSpawn)?.status.success() {
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
            let valid = !rev.is_empty()
                && rev.len() <= MAX_REV_LEN
                && !rev.starts_with('-')
                && !rev.chars().any(|c| c.is_whitespace() || c.is_control());
            if !valid {
                return Err(SourceError::Revision(rev.chars().take(80).collect()));
            }
            args.push(rev.into());
        }
    }
    args.push("--".into());
    Ok(args)
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

/// A child process whose stderr is drained by a thread (a full stderr pipe would block it)
/// and which is killed if dropped before [`Proc::finish`].
struct Proc {
    name: &'static str,
    child: Child,
    stderr: Option<JoinHandle<Vec<u8>>>,
    done: bool,
}

impl Proc {
    fn spawn(name: &'static str, mut cmd: Command) -> Result<Self, SourceError> {
        let mut child = cmd.spawn().map_err(SourceError::GitSpawn)?;
        let stderr = child.stderr.take().map(|mut pipe| {
            thread::spawn(move || {
                let mut head = Vec::new();
                let _ = (&mut pipe).take(4096).read_to_end(&mut head);
                let _ = io::copy(&mut pipe, &mut io::sink());
                head
            })
        });
        Ok(Self { name, child, stderr, done: false })
    }

    fn finish(mut self) -> Result<(), SourceError> {
        let status = self.child.wait().map_err(SourceError::GitIo)?;
        self.done = true;
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
        if !self.done {
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
