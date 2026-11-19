//! Sources for SecretTrace scanners.
//!
//! A source turns something that may contain secrets into text [`Document`]s for the
//! candidate extractor (`st-extract`):
//!
//! - [`FsSource`]: a directory tree or a single file. Symlinks and special files are never
//!   opened, so a hostile tree cannot redirect the scanner to `/run/secrets/…` or block it
//!   on a FIFO.
//! - [`GitRepo`]: the whole history. Every unique blob is read and scanned once, however
//!   many commits contain it; [`GitRepo::locate`] later resolves the commits and paths of
//!   the few blobs that matched (`git log --find-object`), and [`GitRepo::head_blobs`]
//!   tells whether a blob is still in the current tree.
//!
//! [`scan`] runs extraction on a worker pool and returns only masked [`Candidate`]s.
//! File contents live in `Zeroizing` buffers and never reach errors, logs or reports.

mod fs;
mod git;
mod pipeline;
mod text;

use std::io;
use std::ops::ControlFlow;

use serde::Serialize;
use zeroize::Zeroizing;

pub use fs::{DEFAULT_EXCLUDES, FsOptions, FsSource};
pub use git::{Change, GitOptions, GitRepo, ObjectId, Occurrence};
pub use pipeline::{DocumentFindings, Report, scan};
pub use st_extract::Candidate;
pub use text::{TextEncoding, decode_text};

/// Default size cap for one file or blob, equal to the extractor's input limit.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Only this many per-file errors are kept in [`Stats::errors`]; the counter stays exact.
pub const MAX_REPORTED_ERRORS: usize = 100;

/// Where a document came from.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum Locator {
    /// A file; the path is relative to the scan root, with `/` separators.
    Filesystem { path: String },
    /// A blob in git history; `path` is one path it was seen under
    /// ([`GitRepo::locate`] lists all of them, with commits).
    Git { blob: ObjectId, path: String },
}

impl Locator {
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Self::Filesystem { path } | Self::Git { path, .. } => path,
        }
    }
}

/// One unit of text handed to the extractor.
#[derive(Debug)]
pub struct Document {
    pub locator: Locator,
    pub text: Zeroizing<String>,
    pub encoding: TextEncoding,
    /// Only a prefix of the content was read (the file exceeds the size cap).
    pub truncated: bool,
}

/// Callback a source feeds documents to; `Break` stops the walk early.
pub type Visit<'a> = dyn FnMut(Document) -> ControlFlow<()> + 'a;

/// Counters of a walk. Skipped items are counted, never silently dropped.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct Stats {
    /// Documents handed to the extractor.
    pub documents: u64,
    /// Bytes of those documents, as read.
    pub bytes: u64,
    /// Documents with partial results: content cut at the size cap or extractor limits hit.
    pub truncated: u64,
    pub skipped_binary: u64,
    /// Git blobs over the size cap (files over the cap are read up to it instead).
    pub skipped_large: u64,
    /// Entries matched by an exclude pattern (an excluded directory counts once).
    pub skipped_excluded: u64,
    /// Symlinks, FIFOs, sockets, devices, submodule entries.
    pub skipped_special: u64,
    /// Git objects absent from a shallow or partial clone (never fetched lazily).
    pub skipped_missing: u64,
    pub read_errors: u64,
    /// The first [`MAX_REPORTED_ERRORS`] read errors: path and OS error, no content.
    pub errors: Vec<ReadError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReadError {
    pub path: String,
    pub error: String,
}

impl Stats {
    /// Add the counters of another walk (several roots in one run).
    pub fn merge(&mut self, other: &Self) {
        self.documents += other.documents;
        self.bytes += other.bytes;
        self.truncated += other.truncated;
        self.skipped_binary += other.skipped_binary;
        self.skipped_large += other.skipped_large;
        self.skipped_excluded += other.skipped_excluded;
        self.skipped_special += other.skipped_special;
        self.skipped_missing += other.skipped_missing;
        self.read_errors += other.read_errors;
        let room = MAX_REPORTED_ERRORS.saturating_sub(self.errors.len());
        self.errors.extend(other.errors.iter().take(room).cloned());
    }

    fn read_error(&mut self, path: String, error: &io::Error) {
        self.read_errors += 1;
        if self.errors.len() < MAX_REPORTED_ERRORS {
            self.errors.push(ReadError { path, error: error.to_string() });
        }
    }

    fn document(&mut self, bytes: usize) {
        self.documents += 1;
        self.bytes += u64::try_from(bytes).unwrap_or(u64::MAX);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("{path}: {source}")]
    Root { path: String, source: io::Error },
    #[error("invalid exclude pattern {pattern:?}: {reason}")]
    Pattern { pattern: String, reason: String },
    #[error("invalid revision {0:?}: must be non-empty, without whitespace, not starting with '-'")]
    Revision(String),
    #[error("cannot run git: {0}")]
    GitSpawn(#[source] io::Error),
    #[error("not a git repository: {0}")]
    NotARepository(String),
    #[error("git {command} failed: {message}")]
    Git { command: &'static str, message: String },
    #[error("unexpected output from git {0}")]
    GitProtocol(&'static str),
    #[error("i/o error talking to git: {0}")]
    GitIo(#[source] io::Error),
}
