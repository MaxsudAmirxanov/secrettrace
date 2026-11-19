//! Sources against real trees and real git repositories (built in temp dirs).
//!
//! Secret-shaped fixtures are generated at runtime so the repository itself stays clean
//! for gitleaks.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]

use std::collections::BTreeSet;
use std::fs;
use std::num::NonZeroUsize;
use std::path::Path;
use std::process::Command;

use st_extract::{Config, Extractor};
use st_source::{
    Change, FsOptions, FsSource, GitOptions, GitRepo, Locator, ObjectId, Report, SourceError, TextEncoding, scan,
};
use tempfile::TempDir;

/// Deterministic token generator (xorshift).
struct Gen(u64);

impl Gen {
    fn token(&mut self, prefix: &str, len: usize) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut s = String::from(prefix);
        for _ in 0..len {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            s.push(char::from(ALPHABET[usize::try_from(self.0 % 62).unwrap()]));
        }
        s
    }

    fn github(&mut self) -> String {
        self.token("ghp_", 36)
    }
}

fn extractor() -> Extractor {
    Extractor::new(Config::default())
}

fn jobs(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n).unwrap()
}

fn fs_scan(root: &Path, options: FsOptions, n: usize) -> Report {
    let source = FsSource::new(root, options).unwrap();
    scan(&extractor(), jobs(n), |visit| source.walk(visit)).unwrap()
}

/// Paths with a GitHub-token candidate.
fn token_paths(report: &Report) -> BTreeSet<String> {
    report
        .documents
        .iter()
        .filter(|d| d.candidates.iter().any(|c| c.rule == Some("github_token")))
        .map(|d| d.locator.path().to_owned())
        .collect()
}

#[test]
fn filesystem_walk_reads_text_and_counts_the_rest() {
    let mut g = Gen(7);
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join("app/config")).unwrap();
    fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
    fs::create_dir_all(root.join(".git")).unwrap();
    fs::write(root.join("app/.env"), format!("GITHUB_TOKEN={}\n", g.github())).unwrap();
    fs::write(root.join("app/config/plain.yaml"), "replicas: 3\n").unwrap();
    fs::write(root.join("node_modules/pkg/index.js"), format!("t='{}'", g.github())).unwrap();
    fs::write(root.join(".git/config"), format!("url = https://x:{}@github.com/o/r\n", g.github())).unwrap();
    fs::write(root.join("logo.png"), b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR").unwrap();
    // UTF-16LE with BOM, as written by many Windows tools.
    let utf16: Vec<u8> = [0xFF, 0xFE]
        .into_iter()
        .chain(format!("$token = \"{}\"\r\n", g.github()).encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    fs::write(root.join("deploy.ps1"), utf16).unwrap();

    let options = FsOptions { exclude: vec!["node_modules".into()], ..FsOptions::default() };
    let report = fs_scan(root, options, 1);
    assert_eq!(token_paths(&report), BTreeSet::from(["app/.env".into(), "deploy.ps1".into()]));
    let ps1 = report.documents.iter().find(|d| d.locator.path() == "deploy.ps1").unwrap();
    assert_eq!(ps1.encoding, TextEncoding::Utf16Le);
    assert!(matches!(ps1.locator, Locator::Filesystem { .. }));

    let s = &report.stats;
    assert_eq!((s.documents, s.skipped_binary, s.skipped_excluded), (3, 1, 2), "{s:?}");
    assert_eq!(s.read_errors, 0);

    // Default excludes can be turned off; then .git/ is read like anything else.
    let all = fs_scan(root, FsOptions { default_excludes: false, ..FsOptions::default() }, 1);
    assert!(token_paths(&all).contains(".git/config"));
    assert!(token_paths(&all).contains("node_modules/pkg/index.js"));
}

#[test]
fn single_file_root_and_missing_root() {
    let mut g = Gen(11);
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("ci.log");
    fs::write(&file, format!("step 3: export TOKEN={}\n", g.github())).unwrap();
    let report = fs_scan(&file, FsOptions::default(), 1);
    assert_eq!(token_paths(&report), BTreeSet::from(["ci.log".into()]));

    let err = FsSource::new(&dir.path().join("nope"), FsOptions::default()).unwrap_err();
    assert!(matches!(err, SourceError::Root { .. }), "{err}");
}

#[test]
fn large_files_are_scanned_up_to_the_cap() {
    let mut g = Gen(13);
    let dir = TempDir::new().unwrap();
    let early = g.github();
    let late = g.github();
    let body = format!("A={early}\n{}\nB={late}\n", "x".repeat(10_000));
    fs::write(dir.path().join("big.log"), body).unwrap();
    let report = fs_scan(dir.path(), FsOptions { max_file_bytes: 4096, ..FsOptions::default() }, 1);
    let doc = &report.documents[0];
    assert!(doc.truncated);
    assert_eq!(doc.candidates.iter().filter(|c| c.rule == Some("github_token")).count(), 1, "only the early one");
    assert_eq!((report.stats.truncated, report.stats.bytes), (1, 4096));
}

#[cfg(unix)]
#[test]
fn symlinks_and_special_files_are_never_read() {
    use std::os::unix::fs::symlink;

    let mut g = Gen(17);
    let outside = TempDir::new().unwrap();
    let secret_file = outside.path().join("pepper");
    fs::write(&secret_file, format!("{}\n", g.github())).unwrap();

    let dir = TempDir::new().unwrap();
    let root = dir.path();
    symlink(&secret_file, root.join("link-to-file")).unwrap();
    symlink(outside.path(), root.join("link-to-dir")).unwrap();
    // A FIFO would block a naive open() forever.
    let fifo = root.join("pipe");
    let made = Command::new("mkfifo").arg(&fifo).status().is_ok_and(|s| s.success());

    let report = fs_scan(root, FsOptions::default(), 2);
    assert!(report.documents.is_empty(), "{:?}", report.documents);
    assert_eq!(report.stats.skipped_special, 2 + u64::from(made));

    // An explicitly given symlink root is followed (canonicalized) on purpose.
    let via_link = fs_scan(&root.join("link-to-dir"), FsOptions::default(), 1);
    assert_eq!(token_paths(&via_link), BTreeSet::from(["pepper".into()]));
}

#[cfg(unix)]
#[test]
fn unreadable_files_are_reported_without_content() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("locked.env");
    fs::write(&path, "PASSWORD=correct-horse-battery\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::File::open(&path).is_ok() {
        return; // running as root: permissions are not enforced
    }
    let report = fs_scan(dir.path(), FsOptions::default(), 1);
    assert_eq!(report.stats.read_errors, 1);
    let err = &report.stats.errors[0];
    assert_eq!(err.path, "locked.env");
    assert!(!err.error.contains("correct-horse"));
}

#[test]
fn parallel_and_sequential_scans_agree() {
    let mut g = Gen(19);
    let dir = TempDir::new().unwrap();
    for i in 0..60 {
        let body = if i % 3 == 0 { format!("token: {}\n", g.github()) } else { format!("n: {i}\n") };
        fs::write(dir.path().join(format!("f{i:02}.yaml")), body).unwrap();
    }
    let a = fs_scan(dir.path(), FsOptions::default(), 1);
    let b = fs_scan(dir.path(), FsOptions::default(), 4);
    let key = |r: &Report| -> Vec<(String, Vec<String>)> {
        r.documents
            .iter()
            .map(|d| (d.locator.path().to_owned(), d.candidates.iter().map(|c| c.masked.clone()).collect()))
            .collect()
    };
    assert_eq!(key(&a), key(&b));
    assert_eq!(a.documents.len(), 20);
    assert_eq!(a.stats, b.stats);
}

// ── git ─────────────────────────────────────────────────────────────────────

struct Repo {
    dir: TempDir,
    /// Commits get increasing timestamps so history order is deterministic.
    clock: std::cell::Cell<u64>,
}

impl Repo {
    fn new() -> Self {
        let repo = Self { dir: TempDir::new().unwrap(), clock: std::cell::Cell::new(1_700_000_000) };
        repo.git(&["init", "-q", "-b", "main"]);
        repo
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn git(&self, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(self.path())
            .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"])
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_DATE", self.date())
            .env("GIT_COMMITTER_DATE", self.date())
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    fn date(&self) -> String {
        format!("@{} +0000", self.clock.get())
    }

    fn write(&self, path: &str, content: impl AsRef<[u8]>) {
        let full = self.path().join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, content).unwrap();
    }

    fn commit(&self, message: &str) -> String {
        self.git(&["add", "-A"]);
        self.clock.set(self.clock.get() + 60);
        self.git(&["commit", "-q", "--allow-empty", "-m", message]);
        self.git(&["rev-parse", "HEAD"])
    }

    fn blob(&self, rev_path: &str) -> ObjectId {
        ObjectId::parse(&self.git(&["rev-parse", rev_path])).unwrap()
    }

    fn scan(&self, options: &GitOptions) -> Result<Report, SourceError> {
        let repo = GitRepo::open(self.path())?;
        scan(&extractor(), jobs(2), |visit| repo.blobs(options, visit))
    }
}

#[test]
fn git_history_is_scanned_once_per_blob_and_located() {
    let mut g = Gen(23);
    let leaked = g.github();
    let repo = Repo::new();

    repo.write("README.md", "# demo\n");
    repo.write("config/prod.env", format!("GITHUB_TOKEN={leaked}\n"));
    let c1 = repo.commit("add config");
    let blob = repo.blob("HEAD:config/prod.env");

    // The next two commits get the same timestamp as c1: order must come from the graph.
    repo.git(&["rm", "-q", "config/prod.env"]);
    repo.clock.set(repo.clock.get() - 60);
    let c2 = repo.commit("remove secret");

    // The same content re-added elsewhere is the same blob: read once, found at both paths.
    repo.write("backup/prod.env", format!("GITHUB_TOKEN={leaked}\n"));
    repo.clock.set(repo.clock.get() - 60);
    let c3 = repo.commit("oops");
    for i in 0..20 {
        repo.write("CHANGELOG", format!("v{i}\n"));
        repo.commit("bump");
    }
    repo.write("assets/blob.bin", b"\0\x01\x02binary");
    repo.write("assets/huge.txt", "y".repeat(70_000));
    repo.commit("assets");

    let report = repo.scan(&GitOptions { max_blob_bytes: 64 * 1024, ..GitOptions::default() }).unwrap();
    let hits: Vec<_> =
        report.documents.iter().filter(|d| d.candidates.iter().any(|c| c.rule == Some("github_token"))).collect();
    assert_eq!(hits.len(), 1, "one blob, scanned once");
    let Locator::Git { blob: found, path } = &hits[0].locator else { panic!("not a git locator") };
    assert_eq!(found, &blob);
    assert!(path.ends_with("prod.env"));
    let s = &report.stats;
    assert_eq!((s.skipped_binary, s.skipped_large), (1, 1), "{s:?}");
    // README, prod.env, 20 CHANGELOG versions.
    assert_eq!(s.documents, 22);

    let repo_handle = GitRepo::open(repo.path()).unwrap();
    let located = repo_handle.locate(&[], std::slice::from_ref(&blob)).unwrap();
    let occurrences: Vec<_> =
        located[&blob].iter().map(|o| (o.commit.as_str().to_owned(), o.path.as_str(), o.change)).collect();
    assert_eq!(
        occurrences,
        vec![
            (c1.clone(), "config/prod.env", Change::Added),
            (c2, "config/prod.env", Change::Removed),
            (c3, "backup/prod.env", Change::Added),
        ]
    );

    let head = repo_handle.head_blobs().unwrap();
    assert_eq!(head[&blob], vec!["backup/prod.env".to_owned()]);

    // Incremental scan: only blobs not reachable from c1 are read.
    let since =
        repo.scan(&GitOptions { revs: vec!["main".into(), format!("^{c1}")], ..GitOptions::default() }).unwrap();
    assert!(since.documents.iter().all(|d| !d.candidates.iter().any(|c| c.rule == Some("github_token"))));
    assert_eq!(since.stats.documents, 21, "only the CHANGELOG versions and huge.txt are new");
}

#[test]
fn every_ref_is_scanned_by_default() {
    let mut g = Gen(29);
    let repo = Repo::new();
    repo.write("a.txt", "hello\n");
    repo.commit("init");
    repo.git(&["checkout", "-q", "-b", "feature"]);
    repo.write("feature.env", format!("TOKEN={}\n", g.github()));
    repo.commit("feature secret");
    repo.git(&["checkout", "-q", "main"]);
    repo.write("stash.env", format!("TOKEN={}\n", g.github()));
    repo.git(&["add", "stash.env"]);
    repo.git(&["stash", "-q"]);

    let all = repo.scan(&GitOptions::default()).unwrap();
    let paths: BTreeSet<_> = token_paths(&all);
    assert_eq!(paths, BTreeSet::from(["feature.env".into(), "stash.env".into()]));

    let main_only = repo.scan(&GitOptions { revs: vec!["main".into()], ..GitOptions::default() }).unwrap();
    assert!(token_paths(&main_only).is_empty());
    assert!(GitRepo::open(repo.path()).unwrap().head_blobs().unwrap().len() == 1);
}

#[test]
fn replace_refs_cannot_hide_a_blob() {
    let mut g = Gen(31);
    let repo = Repo::new();
    repo.write("app.env", format!("TOKEN={}\n", g.github()));
    repo.commit("secret");
    let secret = repo.blob("HEAD:app.env");
    let innocent = repo.git(&["hash-object", "-w", "--stdin"]); // empty blob
    repo.git(&["replace", "-f", secret.as_str(), &innocent]);
    assert_eq!(repo.git(&["cat-file", "-p", "HEAD:app.env"]), "", "plain git now shows the replacement");

    let report = repo.scan(&GitOptions::default()).unwrap();
    assert_eq!(token_paths(&report), BTreeSet::from(["app.env".into()]));
}

#[test]
fn hostile_revisions_and_bad_repos_are_rejected() {
    let repo = Repo::new();
    repo.write("a", "1\n");
    repo.commit("init");
    for bad in ["--output=/tmp/pwned", "-n1", "a b"] {
        let err = repo.scan(&GitOptions { revs: vec![bad.into()], ..GitOptions::default() }).unwrap_err();
        assert!(matches!(err, SourceError::Revision(_)), "{bad}: {err}");
    }
    let err = repo.scan(&GitOptions { revs: vec!["no-such-branch".into()], ..GitOptions::default() }).unwrap_err();
    assert!(
        matches!(&err, SourceError::Git { command: "rev-list", message } if message.contains("no-such-branch")),
        "{err}"
    );

    let plain = TempDir::new().unwrap();
    assert!(matches!(GitRepo::open(plain.path()), Err(SourceError::NotARepository(_))));
    let missing_git = GitRepo::open_with(repo.path(), "/nonexistent/git");
    assert!(matches!(missing_git, Err(SourceError::GitSpawn(_))));
}

#[test]
fn empty_repository() {
    let repo = Repo::new();
    let handle = GitRepo::open(repo.path()).unwrap();
    assert!(handle.head_blobs().unwrap().is_empty());
    // No refs at all: `--all` walks nothing.
    let report = repo.scan(&GitOptions::default()).unwrap();
    assert_eq!(report.stats.documents, 0);
}

#[test]
fn early_stop_kills_git_cleanly() {
    let repo = Repo::new();
    for i in 0..30 {
        repo.write(&format!("f{i}"), format!("{i}\n"));
    }
    repo.commit("many");
    let handle = GitRepo::open(repo.path()).unwrap();
    let mut seen = 0;
    let stats = handle
        .blobs(&GitOptions::default(), &mut |_doc| {
            seen += 1;
            if seen == 3 { std::ops::ControlFlow::Break(()) } else { std::ops::ControlFlow::Continue(()) }
        })
        .unwrap();
    assert_eq!((seen, stats.documents), (3, 3));
}
