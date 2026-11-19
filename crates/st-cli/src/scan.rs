//! `secrettrace scan fs|git`: local scanning of trees and git history.
//!
//! Matching against the registry needs the server and arrives with ingest; for now the
//! command prints what would be sent: masked candidates and locations, never plaintext.

use std::collections::HashMap;
use std::io::Write as _;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context as _, bail};
use clap::{Args, Subcommand};
use serde::Serialize;
use st_extract::{Candidate, Confidence};
use st_source::{
    DEFAULT_MAX_FILE_BYTES, DocumentFindings, FsOptions, FsSource, GitOptions, GitRepo, Locator, ObjectId, Occurrence,
    Report, Stats, TextEncoding, scan,
};

use crate::OutputArgs;

#[derive(Subcommand)]
pub enum Target {
    /// Files under directories (or single files). Symlinks and special files are skipped;
    /// `.git`, `.hg` and `.svn` are excluded by default (scan history with `scan git`).
    Fs {
        /// Directories or files to scan.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Skip entries matching a glob: `node_modules`, `*.min.js` (any depth) or
        /// `docs/**/*.md` (from the root). Repeatable.
        #[arg(long = "exclude", value_name = "GLOB")]
        exclude: Vec<String>,
        /// Do not exclude `.git`, `.hg` and `.svn`.
        #[arg(long)]
        no_default_excludes: bool,
        /// Read at most this many bytes per file; longer files are scanned partially.
        #[arg(long, value_name = "BYTES", default_value_t = DEFAULT_MAX_FILE_BYTES)]
        max_file_size: u64,
        #[command(flatten)]
        common: CommonArgs,
    },
    /// Every unique blob in the history of a repository (working tree or bare), each read once.
    Git {
        /// Repository path.
        #[arg(default_value = ".")]
        repo: PathBuf,
        /// Revisions to scan instead of all refs: `main`, `v1.0..HEAD`, `^<commit>` to skip
        /// what an earlier scan covered. Repeatable.
        #[arg(long = "rev", value_name = "REV")]
        revs: Vec<String>,
        /// Skip blobs larger than this.
        #[arg(long, value_name = "BYTES", default_value_t = DEFAULT_MAX_FILE_BYTES)]
        max_blob_size: u64,
        /// Also list the commits that added or removed each blob with candidates
        /// (one extra pass over history).
        #[arg(long)]
        locate: bool,
        #[command(flatten)]
        common: CommonArgs,
    },
}

#[derive(Args)]
pub struct CommonArgs {
    #[command(flatten)]
    output: OutputArgs,
    /// Extraction threads (default: available CPUs).
    #[arg(long, short = 'j', value_name = "N")]
    jobs: Option<NonZeroUsize>,
}

impl CommonArgs {
    fn jobs(&self) -> NonZeroUsize {
        self.jobs.unwrap_or_else(|| std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN))
    }
}

#[derive(Serialize)]
struct Row<'a> {
    #[serde(flatten)]
    locator: &'a Locator,
    /// The scan root as given on the command line (filesystem only).
    #[serde(skip_serializing_if = "Option::is_none")]
    root: Option<&'a str>,
    #[serde(skip_serializing_if = "is_utf8")]
    text_encoding: TextEncoding,
    /// The blob is in the `HEAD` tree (git only).
    #[serde(skip_serializing_if = "Option::is_none")]
    in_head: Option<bool>,
    #[serde(flatten)]
    candidate: &'a Candidate,
    #[serde(skip_serializing_if = "Option::is_none")]
    digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    occurrences: Option<&'a [Occurrence]>,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if passes a reference
fn is_utf8(e: &TextEncoding) -> bool {
    *e == TextEncoding::Utf8
}

pub fn run(target: Target) -> anyhow::Result<()> {
    let started = Instant::now();
    match target {
        Target::Fs { paths, exclude, no_default_excludes, max_file_size, common } => {
            let extractor = common.output.extractor();
            let options = FsOptions {
                max_file_bytes: max_file_size,
                exclude,
                default_excludes: !no_default_excludes,
                ..FsOptions::default()
            };
            let mut printer = Printer::new(&common.output);
            let mut total = Stats::default();
            for path in &paths {
                let source = FsSource::new(path, options.clone())?;
                let report = scan(&extractor, common.jobs(), |visit| source.walk(visit))?;
                let root = path.display().to_string();
                printer.report(&report, |doc, candidate| Row { root: Some(&root), ..Row::new(doc, candidate) })?;
                total.merge(&report.stats);
            }
            printer.finish(&total, started)
        }
        Target::Git { repo, revs, max_blob_size, locate, common } => {
            let extractor = common.output.extractor();
            let git = GitRepo::open(&repo)?;
            let options = GitOptions { revs, max_blob_bytes: max_blob_size, ..GitOptions::default() };
            let report = scan(&extractor, common.jobs(), |visit| git.blobs(&options, visit))?;
            let head = git.head_blobs()?;
            let min = Confidence::from(common.output.min_confidence);
            let located = if locate {
                let blobs: Vec<ObjectId> = report
                    .documents
                    .iter()
                    .filter(|d| d.candidates.iter().any(|c| c.confidence >= min))
                    .filter_map(|d| match &d.locator {
                        Locator::Git { blob, .. } => Some(blob.clone()),
                        Locator::Filesystem { .. } => None,
                    })
                    .collect();
                git.locate(&options.revs, &blobs).context("cannot locate blobs in history")?
            } else {
                HashMap::new()
            };
            let mut printer = Printer::new(&common.output);
            printer.report(&report, |doc, candidate| {
                let blob = match &doc.locator {
                    Locator::Git { blob, .. } => Some(blob),
                    Locator::Filesystem { .. } => None,
                };
                Row {
                    in_head: blob.map(|b| head.contains_key(b)),
                    occurrences: locate.then(|| blob.and_then(|b| located.get(b)).map_or(&[][..], Vec::as_slice)),
                    ..Row::new(doc, candidate)
                }
            })?;
            printer.finish(&report.stats, started)
        }
    }
}

impl<'a> Row<'a> {
    fn new(doc: &'a DocumentFindings, candidate: &'a Candidate) -> Self {
        Self {
            locator: &doc.locator,
            root: None,
            text_encoding: doc.encoding,
            in_head: None,
            candidate,
            digest: None,
            occurrences: None,
        }
    }
}

struct Printer<'o> {
    output: &'o OutputArgs,
    stdout: std::io::StdoutLock<'static>,
    candidates: usize,
    documents: usize,
}

impl<'o> Printer<'o> {
    fn new(output: &'o OutputArgs) -> Self {
        Self { output, stdout: std::io::stdout().lock(), candidates: 0, documents: 0 }
    }

    fn report<'r>(
        &mut self,
        report: &'r Report,
        row: impl Fn(&'r DocumentFindings, &'r Candidate) -> Row<'r>,
    ) -> anyhow::Result<()> {
        let min = Confidence::from(self.output.min_confidence);
        for doc in &report.documents {
            if doc.truncated {
                eprintln!("secrettrace: {}: limits reached, results are partial", doc.locator.path());
            }
            let mut any = false;
            for candidate in doc.candidates.iter().filter(|c| c.confidence >= min) {
                let mut out = row(doc, candidate);
                out.digest = self.output.show_digests.then(|| candidate.digest.to_hex());
                serde_json::to_writer(&mut self.stdout, &out)?;
                writeln!(self.stdout)?;
                self.candidates += 1;
                any = true;
            }
            self.documents += usize::from(any);
        }
        Ok(())
    }

    fn finish(mut self, stats: &Stats, started: Instant) -> anyhow::Result<()> {
        self.stdout.flush()?;
        #[allow(clippy::cast_precision_loss)] // display only
        let mib = stats.bytes as f64 / (1024.0 * 1024.0);
        eprintln!(
            "secrettrace: scanned {} documents ({mib:.1} MiB) in {:.1}s: {} candidates in {} documents",
            stats.documents,
            started.elapsed().as_secs_f64(),
            self.candidates,
            self.documents,
        );
        let skipped: Vec<String> = [
            (stats.skipped_binary, "binary"),
            (stats.skipped_large, "over the size limit"),
            (stats.skipped_excluded, "excluded"),
            (stats.skipped_special, "symlinks or special files"),
            (stats.skipped_missing, "missing objects"),
        ]
        .into_iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, what)| format!("{n} {what}"))
        .collect();
        if !skipped.is_empty() {
            eprintln!("secrettrace: skipped {}", skipped.join(", "));
        }
        for e in &stats.errors {
            eprintln!("secrettrace: {}: {}", e.path, e.error);
        }
        let unreported = stats.read_errors.saturating_sub(u64::try_from(stats.errors.len()).unwrap_or(u64::MAX));
        if unreported > 0 {
            eprintln!("secrettrace: … and {unreported} more read errors");
        }
        if stats.read_errors > 0 {
            bail!("{} file(s) could not be read; results are incomplete", stats.read_errors);
        }
        Ok(())
    }
}
