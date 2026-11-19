//! Filesystem source: a directory tree or a single file.
//!
//! Hostile trees (a cloned repository, an extracted artifact) are expected:
//!
//! - symlinks are never followed, neither while walking nor when opening (`O_NOFOLLOW`),
//!   so a link to `/run/secrets/…` or `~/.ssh` is not read;
//! - only regular files are read; FIFOs are opened non-blocking and rejected after `fstat`;
//! - files over the size cap are read up to it and reported as truncated.
//!
//! The root itself is canonicalized, so an explicitly given symlink root is honored.

use std::cell::Cell;
use std::fs::{File, OpenOptions};
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use walkdir::{DirEntry, WalkDir};
use zeroize::Zeroizing;

use crate::{DEFAULT_MAX_FILE_BYTES, Document, Locator, SourceError, Stats, Visit, decode_text};

/// Excluded unless [`FsOptions::default_excludes`] is off. VCS internals are scanned by the
/// git source, where history is de-duplicated by blob.
pub const DEFAULT_EXCLUDES: &[&str] = &[".git", ".hg", ".svn"];

/// Bytes read before deciding whether a file is binary.
const SNIFF_BYTES: u64 = 8192;

#[derive(Debug, Clone)]
pub struct FsOptions {
    /// Files are read up to this size; longer ones are scanned partially.
    pub max_file_bytes: u64,
    /// Directory nesting limit below the root.
    pub max_depth: usize,
    /// gitignore-like globs: without `/` they match a file or directory name at any depth
    /// (`node_modules`, `*.min.js`); with `/` the path from the root (`docs/**/*.md`).
    pub exclude: Vec<String>,
    /// Also exclude [`DEFAULT_EXCLUDES`].
    pub default_excludes: bool,
}

impl Default for FsOptions {
    fn default() -> Self {
        Self { max_file_bytes: DEFAULT_MAX_FILE_BYTES, max_depth: 64, exclude: Vec::new(), default_excludes: true }
    }
}

#[derive(Debug)]
pub struct FsSource {
    root: PathBuf,
    names: GlobSet,
    paths: GlobSet,
    options: FsOptions,
}

impl FsSource {
    pub fn new(root: &Path, options: FsOptions) -> Result<Self, SourceError> {
        let root = std::fs::canonicalize(root)
            .map_err(|source| SourceError::Root { path: root.display().to_string(), source })?;
        let mut names = GlobSetBuilder::new();
        let mut paths = GlobSetBuilder::new();
        let defaults = DEFAULT_EXCLUDES.iter().filter(|_| options.default_excludes).copied();
        for pattern in defaults.chain(options.exclude.iter().map(String::as_str)) {
            let trimmed = pattern.trim_end_matches('/');
            let (set, glob) = match trimmed.strip_prefix('/') {
                Some(anchored) => (&mut paths, anchored),
                None if trimmed.contains('/') => (&mut paths, trimmed),
                None => (&mut names, trimmed),
            };
            let invalid = |reason: String| SourceError::Pattern { pattern: pattern.to_owned(), reason };
            if glob.is_empty() {
                return Err(invalid("empty".into()));
            }
            let glob =
                GlobBuilder::new(glob).literal_separator(true).build().map_err(|e| invalid(e.kind().to_string()))?;
            set.add(glob);
        }
        let build = |b: GlobSetBuilder| {
            b.build().map_err(|e| SourceError::Pattern { pattern: String::new(), reason: e.to_string() })
        };
        Ok(Self { root, names: build(names)?, paths: build(paths)?, options })
    }

    /// The canonical root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn walk(&self, visit: &mut Visit<'_>) -> Result<Stats, SourceError> {
        let mut stats = Stats::default();
        let excluded = Cell::new(0u64);
        let walker = WalkDir::new(&self.root)
            .follow_links(false)
            .max_depth(self.options.max_depth)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|e| {
                let skip = e.depth() > 0 && self.excluded(e);
                excluded.set(excluded.get() + u64::from(skip));
                !skip
            });

        for entry in walker {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    let path = e.path().map_or_else(String::new, |p| self.relative(p));
                    let error = e.into_io_error().unwrap_or_else(|| io::Error::other("filesystem loop"));
                    stats.read_error(path, &error);
                    continue;
                }
            };
            let kind = entry.file_type();
            if kind.is_dir() {
                continue;
            }
            if !kind.is_file() {
                stats.skipped_special += 1;
                continue;
            }
            let path = self.relative(entry.path());
            let (bytes, truncated) = match read_regular(entry.path(), self.options.max_file_bytes) {
                Ok(Read::Text(bytes, truncated)) => (bytes, truncated),
                Ok(Read::Binary) => {
                    stats.skipped_binary += 1;
                    continue;
                }
                Ok(Read::Special) => {
                    stats.skipped_special += 1;
                    continue;
                }
                Err(e) => {
                    stats.read_error(path, &e);
                    continue;
                }
            };
            let len = bytes.len();
            let Some((text, encoding)) = decode_text(bytes) else {
                stats.skipped_binary += 1;
                continue;
            };
            stats.document(len);
            let doc = Document { locator: Locator::Filesystem { path }, text, encoding, truncated };
            if visit(doc).is_break() {
                break;
            }
        }
        stats.skipped_excluded = excluded.get();
        Ok(stats)
    }

    fn excluded(&self, entry: &DirEntry) -> bool {
        self.names.is_match(Path::new(entry.file_name())) || self.paths.is_match(self.relative(entry.path()))
    }

    /// Path relative to the root with `/` separators; a single-file root is its file name.
    fn relative(&self, path: &Path) -> String {
        let rel = path.strip_prefix(&self.root).unwrap_or(path);
        if rel.as_os_str().is_empty() {
            return path.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        }
        let parts: Vec<_> = rel.components().map(|c| c.as_os_str().to_string_lossy()).collect();
        parts.join("/")
    }
}

enum Read {
    Text(Zeroizing<Vec<u8>>, bool),
    Binary,
    Special,
}

fn open_no_follow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // NOFOLLOW: the entry may have been swapped for a symlink since the walk saw it.
        // NONBLOCK: opening a FIFO for reading would otherwise wait for a writer.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    options.open(path)
}

fn read_regular(path: &Path, max: u64) -> io::Result<Read> {
    let file = match open_no_follow(path) {
        Ok(file) => file,
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Ok(Read::Special),
        Err(e) => return Err(e),
    };
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Ok(Read::Special);
    }
    let len = meta.len();
    // Allocate once: growing a Vec frees the old copy of the content without wiping it.
    let mut buf = Zeroizing::new(Vec::with_capacity(usize::try_from(len.min(max)).unwrap_or(0)));
    let mut file = file.take(max);
    (&mut file).take(SNIFF_BYTES).read_to_end(&mut buf)?;
    let bom = buf.starts_with(&[0xFF, 0xFE]) || buf.starts_with(&[0xFE, 0xFF]);
    if !bom && st_extract::looks_binary(&buf) {
        return Ok(Read::Binary);
    }
    file.read_to_end(&mut buf)?;
    let truncated = len > max || u64::try_from(buf.len()).is_ok_and(|n| n >= max) && has_more(file.into_inner())?;
    Ok(Read::Text(buf, truncated))
}

/// After reading exactly `max` bytes: is there more (the file grew since `fstat`)?
fn has_more(mut file: File) -> io::Result<bool> {
    let mut probe = [0u8; 1];
    let n = file.read(&mut probe)?;
    zeroize::Zeroize::zeroize(&mut probe);
    Ok(n > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclude_pattern_kinds() {
        let opts = FsOptions {
            exclude: vec!["node_modules".into(), "/build/".into(), "docs/**/*.md".into()],
            ..FsOptions::default()
        };
        let fs = FsSource::new(Path::new("."), opts).unwrap_or_else(|e| panic!("{e}"));
        assert!(fs.names.is_match("node_modules"));
        assert!(fs.names.is_match(".git"));
        assert!(fs.paths.is_match("build"));
        assert!(fs.paths.is_match("docs/a/b/c.md"));
        assert!(!fs.paths.is_match("src/build"));
        assert!(!fs.paths.is_match("docs/x.rs"));
    }

    #[test]
    fn invalid_patterns_are_rejected() {
        for bad in ["a[", "/", ""] {
            let opts = FsOptions { exclude: vec![bad.into()], ..FsOptions::default() };
            assert!(matches!(FsSource::new(Path::new("."), opts), Err(SourceError::Pattern { .. })), "{bad:?}");
        }
    }
}
