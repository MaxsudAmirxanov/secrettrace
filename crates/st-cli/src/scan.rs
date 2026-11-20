//! `secrettrace scan fs|git`: scanning of trees and git history.
//!
//! Without `--server` the command prints masked candidates (diagnostic). With `--server`
//! it runs the ingest protocol: the server says which digests are registered, only those
//! locations are sent, and the exit code tells CI whether registered secrets were found
//! outside their allowed locations.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write as _;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use anyhow::{Context as _, bail};
use clap::{Args, Subcommand, ValueEnum};
use serde::Serialize;
use st_core::Digest;
use st_extract::{Candidate, Confidence};
use st_source::{
    Change, DEFAULT_MAX_FILE_BYTES, DocumentFindings, FsOptions, FsSource, GitOptions, GitRepo, Locator, ObjectId,
    Occurrence, Report, Stats, TextEncoding, scan,
};

use crate::OutputArgs;
use crate::client::{Client, ServerArgs, read_token};
use crate::submit::{self, FindingOut, FindingsTotals};

/// Exit code: registered secrets found where `--fail-on` says they must not be.
pub const EXIT_FOUND: u8 = 1;

#[derive(Subcommand)]
pub enum Target {
    /// Files under directories (or single files). Symlinks and special files are skipped;
    /// `.git`, `.hg` and `.svn` are excluded by default (scan history with `scan git`).
    Fs {
        /// Directories or files to scan (exactly one with --server).
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
        #[command(flatten)]
        submit: SubmitArgs,
    },
    /// Every unique blob in the history of a repository (working tree or bare), each read once.
    Git {
        /// Repository path.
        #[arg(default_value = ".")]
        repo: PathBuf,
        /// Revisions to scan instead of all refs: `main`, `v1.0..HEAD`, `^<commit>` to skip
        /// what an earlier scan covered. Repeatable. With --server the whole `HEAD` tree is
        /// always read as well.
        #[arg(long = "rev", value_name = "REV")]
        revs: Vec<String>,
        /// Skip blobs larger than this.
        #[arg(long, value_name = "BYTES", default_value_t = DEFAULT_MAX_FILE_BYTES)]
        max_blob_size: u64,
        /// Also list the commits that added or removed each blob with candidates
        /// (one extra pass over history; always done for matches with --server).
        #[arg(long)]
        locate: bool,
        #[command(flatten)]
        common: CommonArgs,
        #[command(flatten)]
        submit: SubmitArgs,
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

/// Sending results to a server (`--server`). The API token comes from
/// `SECRETTRACE_TOKEN` or `--token-file`, never from the command line.
#[derive(Args)]
pub struct SubmitArgs {
    #[command(flatten)]
    server: ServerArgs,
    /// URI the source is recorded under (no credentials). Required for `scan fs`
    /// (e.g. `host:web-01/etc/app`); `scan git` defaults to the `origin` remote with
    /// credentials removed.
    #[arg(long, value_name = "URI", requires = "server")]
    source_uri: Option<String>,
    /// Environment name allow rules can match (`prod`, `staging`…).
    #[arg(long, env = "SECRETTRACE_ENVIRONMENT", value_name = "NAME")]
    environment: Option<String>,
    /// Read the API token from this file instead of `SECRETTRACE_TOKEN`.
    #[arg(long, value_name = "FILE", requires = "server")]
    token_file: Option<PathBuf>,
    /// When to exit with code 1.
    #[arg(long, value_enum, default_value_t = FailOn::Violations)]
    fail_on: FailOn,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailOn {
    /// A registered secret outside every allow rule of that secret.
    Violations,
    /// Any registered secret, allowed or not.
    Found,
    /// Never: report only.
    Never,
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

pub fn run(target: Target) -> anyhow::Result<ExitCode> {
    match target {
        Target::Fs { paths, exclude, no_default_excludes, max_file_size, common, submit } => {
            let options = FsOptions {
                max_file_bytes: max_file_size,
                exclude,
                default_excludes: !no_default_excludes,
                ..FsOptions::default()
            };
            if submit.server.server.is_some() {
                return fs_to_server(&paths, &options, &common, &submit);
            }
            let started = Instant::now();
            let extractor = common.output.extractor();
            let mut printer = Printer::new(&common.output, None);
            let mut total = Stats::default();
            for path in &paths {
                let source = FsSource::new(path, options.clone())?;
                let report = scan(&extractor, common.jobs(), |visit| source.walk(visit))?;
                let root = path.display().to_string();
                printer.report(&report, |doc, candidate| Row { root: Some(&root), ..Row::new(doc, candidate) })?;
                total.merge(&report.stats);
            }
            printer.finish(&total, started)?;
            fail_on_read_errors(&total)
        }
        Target::Git { repo, revs, max_blob_size, locate, common, submit } => {
            let git = GitRepo::open(&repo)?;
            if submit.server.server.is_some() {
                return git_to_server(&git, revs, max_blob_size, &common, &submit);
            }
            let started = Instant::now();
            let extractor = common.output.extractor();
            let options = GitOptions { revs, max_blob_bytes: max_blob_size, ..GitOptions::default() };
            let report = scan(&extractor, common.jobs(), |visit| git.blobs(&options, visit))?;
            let head = git.head_blobs()?;
            let min = Confidence::from(common.output.min_confidence);
            let located = if locate {
                let blobs = blobs_where(&report, |c| c.confidence >= min);
                git.locate(&options.revs, &blobs).context("cannot locate blobs in history")?
            } else {
                HashMap::new()
            };
            let mut printer = Printer::new(&common.output, None);
            printer.report(&report, |doc, candidate| {
                let blob = git_blob(doc);
                Row {
                    in_head: blob.map(|b| head.contains_key(b)),
                    occurrences: locate.then(|| blob.and_then(|b| located.get(b)).map_or(&[][..], Vec::as_slice)),
                    ..Row::new(doc, candidate)
                }
            })?;
            printer.finish(&report.stats, started)?;
            fail_on_read_errors(&report.stats)
        }
    }
}

fn fail_on_read_errors(stats: &Stats) -> anyhow::Result<ExitCode> {
    if stats.read_errors > 0 {
        bail!("{} file(s) could not be read; results are incomplete", stats.read_errors);
    }
    Ok(ExitCode::SUCCESS)
}

fn git_blob(doc: &DocumentFindings) -> Option<&ObjectId> {
    match &doc.locator {
        Locator::Git { blob, .. } => Some(blob),
        Locator::Filesystem { .. } => None,
    }
}

/// Unique blobs whose documents hold a candidate satisfying `keep`, sorted.
fn blobs_where(report: &Report, keep: impl Fn(&Candidate) -> bool) -> Vec<ObjectId> {
    let mut blobs: Vec<ObjectId> = report
        .documents
        .iter()
        .filter(|d| d.candidates.iter().any(&keep))
        .filter_map(|d| git_blob(d).cloned())
        .collect();
    blobs.sort_unstable();
    blobs.dedup();
    blobs
}

// ── server mode ─────────────────────────────────────────────────────────────

fn fs_to_server(
    paths: &[PathBuf],
    options: &FsOptions,
    common: &CommonArgs,
    args: &SubmitArgs,
) -> anyhow::Result<ExitCode> {
    let [path] = paths else { bail!("--server takes exactly one path (one source per scan)") };
    let uri = args.source_uri.as_deref().context(
        "--source-uri is required with `scan fs --server`: the name this tree is recorded under, e.g. host:web-01/etc/app",
    )?;
    let started = Instant::now();
    let source = FsSource::new(path, options.clone())?;
    let report = scan(&common.output.extractor(), common.jobs(), |visit| source.walk(visit))?;
    let root = path.display().to_string();
    let target =
        submit::Target { source_type: "filesystem", uri, environment: args.environment.as_deref(), full: true };
    send(
        args,
        common,
        &target,
        &report,
        started,
        |matched| {
            let mut out = Vec::new();
            for doc in &report.documents {
                for c in doc.candidates.iter().filter(|c| matched.contains(&c.digest)) {
                    out.push(submit::finding(c, doc.locator.path(), None, None, true));
                }
            }
            Ok(out)
        },
        |doc, candidate| Row { root: Some(&root), ..Row::new(doc, candidate) },
    )
}

fn git_to_server(
    git: &GitRepo,
    revs: Vec<String>,
    max_blob_bytes: u64,
    common: &CommonArgs,
    args: &SubmitArgs,
) -> anyhow::Result<ExitCode> {
    let uri = if let Some(uri) = &args.source_uri {
        uri.clone()
    } else {
        let origin = git.remote_url("origin")?.context("the repository has no `origin` remote; pass --source-uri")?;
        submit::strip_credentials(&origin)
    };
    let started = Instant::now();
    // The whole HEAD tree is read even when the history is limited, so the scan always
    // covers the current state and the server may mark unseen locations as gone.
    let options = GitOptions { revs, max_blob_bytes, current_tree: Some("HEAD".into()), ..GitOptions::default() };
    let report = scan(&common.output.extractor(), common.jobs(), |visit| git.blobs(&options, visit))?;
    let head = git.head_blobs()?;
    let target =
        submit::Target { source_type: "git_repo", uri: &uri, environment: args.environment.as_deref(), full: true };
    send(
        args,
        common,
        &target,
        &report,
        started,
        |matched| {
            let blobs = blobs_where(&report, |c| matched.contains(&c.digest));
            let located = git.locate(&options.revs, &blobs).context("cannot locate blobs in history")?;
            Ok(git_findings(&report, &head, matched, &located))
        },
        |doc, candidate| Row { in_head: git_blob(doc).map(|b| head.contains_key(b)), ..Row::new(doc, candidate) },
    )
}

/// Findings for matched candidates, as the worker builds them: one per path of the blob
/// in the `HEAD` tree (`in_current_state`), plus the history path when the blob is not
/// there under it; the commit is the first that added the blob (under that path if known).
fn git_findings(
    report: &Report,
    head: &HashMap<ObjectId, Vec<String>>,
    matched: &HashSet<Digest>,
    occurrences: &HashMap<ObjectId, Vec<Occurrence>>,
) -> Vec<FindingOut> {
    let mut out = Vec::new();
    for doc in &report.documents {
        let Locator::Git { blob, path } = &doc.locator else { continue };
        let head_paths = head.get(blob).map(Vec::as_slice).unwrap_or_default();
        let mut paths: Vec<(&str, bool)> = head_paths.iter().map(|p| (p.as_str(), true)).collect();
        if !head_paths.iter().any(|p| p == path) {
            paths.push((path, false));
        }
        let occ = occurrences.get(blob).map(Vec::as_slice).unwrap_or_default();
        for c in doc.candidates.iter().filter(|c| matched.contains(&c.digest)) {
            for &(p, current) in &paths {
                let commit = first_added(occ, p).map(ObjectId::as_str);
                out.push(submit::finding(c, p, Some(blob.as_str()), commit, current));
            }
        }
    }
    out
}

fn first_added<'a>(occ: &'a [Occurrence], path: &str) -> Option<&'a ObjectId> {
    let added = || occ.iter().filter(|o| o.change == Change::Added);
    added().find(|o| o.path == path).or_else(|| added().next()).map(|o| &o.commit)
}

/// Run the ingest protocol for one report, print matched rows and a summary, and turn
/// the outcome into an exit code.
#[allow(clippy::too_many_arguments)]
fn send<'r>(
    args: &SubmitArgs,
    common: &CommonArgs,
    target: &submit::Target<'_>,
    report: &'r Report,
    started: Instant,
    findings: impl FnOnce(&HashSet<Digest>) -> anyhow::Result<Vec<FindingOut>>,
    row: impl Fn(&'r DocumentFindings, &'r Candidate) -> Row<'r>,
) -> anyhow::Result<ExitCode> {
    let client = Client::new(&args.server)?;
    let token = read_token(args.token_file.as_deref())?;
    let min = Confidence::from(common.output.min_confidence);
    let digests = unique_digests(report, min);

    let scan = submit::Scan::start(&client, &token, target)?;
    eprintln!("secrettrace: scan {} of {} {} on {}", scan.id, target.source_type, target.uri, client.base());
    let exchange = || -> anyhow::Result<(HashSet<Digest>, FindingsTotals)> {
        let matched = scan.match_digests(&digests)?;
        let out = findings(&matched)?;
        let totals = if out.is_empty() { FindingsTotals::default() } else { scan.findings(&out)? };
        Ok((matched, totals))
    };
    let (matched, totals) = match exchange() {
        Ok(v) => v,
        Err(e) => {
            // Best effort: a failed scan never marks locations as gone.
            if let Err(close) = scan.complete(&BTreeMap::new(), Some("the client aborted the scan")) {
                eprintln!("secrettrace: {close:#}");
            }
            return Err(e);
        }
    };

    let mut printer = Printer::new(&common.output, Some(&matched));
    printer.report(report, row)?;
    let stats = &report.stats;
    let counters = counters(stats, digests.len(), matched.len(), started);
    let incomplete = (stats.read_errors > 0).then(|| format!("{} file(s) could not be read", stats.read_errors));
    let gone = scan.complete(&counters, incomplete.as_deref())?;
    printer.finish(stats, started)?;

    eprintln!(
        "secrettrace: {} registered secret(s) in {} location(s): {} violation(s), {} new location(s){}",
        matched.len(),
        totals.accepted,
        totals.violations,
        totals.new_locations,
        if gone > 0 { format!(", {gone} no longer present") } else { String::new() },
    );
    let fail = match args.fail_on {
        FailOn::Violations => totals.violations > 0,
        FailOn::Found => totals.accepted > 0,
        FailOn::Never => false,
    };
    if fail {
        eprintln!("secrettrace: failing (--fail-on {})", fail_on_name(args.fail_on));
        return Ok(ExitCode::from(EXIT_FOUND));
    }
    if let Some(reason) = incomplete {
        bail!("{reason}; the scan is recorded as failed");
    }
    Ok(ExitCode::SUCCESS)
}

const fn fail_on_name(f: FailOn) -> &'static str {
    match f {
        FailOn::Violations => "violations",
        FailOn::Found => "found",
        FailOn::Never => "never",
    }
}

/// Unique digests of candidates at or above `min`, in first-seen order.
fn unique_digests(report: &Report, min: Confidence) -> Vec<Digest> {
    let mut seen = HashSet::new();
    report
        .documents
        .iter()
        .flat_map(|d| &d.candidates)
        .filter(|c| c.confidence >= min)
        .map(|c| c.digest)
        .filter(|d| seen.insert(*d))
        .collect()
}

/// Scan counters for `complete` (keys of `[a-z0-9_]`, counts only).
fn counters(stats: &Stats, digests: usize, matched: usize, started: Instant) -> BTreeMap<String, u64> {
    let n = |v: usize| u64::try_from(v).unwrap_or(u64::MAX);
    [
        ("documents", stats.documents),
        ("bytes", stats.bytes),
        ("truncated", stats.truncated),
        ("skipped_binary", stats.skipped_binary),
        ("skipped_large", stats.skipped_large),
        ("skipped_excluded", stats.skipped_excluded),
        ("skipped_special", stats.skipped_special),
        ("skipped_missing", stats.skipped_missing),
        ("read_errors", stats.read_errors),
        ("unique_digests", n(digests)),
        ("matched_digests", n(matched)),
        ("duration_ms", u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v))
    .collect()
}

// ── output ──────────────────────────────────────────────────────────────────

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
    /// Print only these (server mode: the registered ones).
    only: Option<&'o HashSet<Digest>>,
    stdout: std::io::StdoutLock<'static>,
    candidates: usize,
    documents: usize,
}

impl<'o> Printer<'o> {
    fn new(output: &'o OutputArgs, only: Option<&'o HashSet<Digest>>) -> Self {
        Self { output, only, stdout: std::io::stdout().lock(), candidates: 0, documents: 0 }
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
            let shown = |c: &&Candidate| c.confidence >= min && self.only.is_none_or(|m| m.contains(&c.digest));
            for candidate in doc.candidates.iter().filter(shown) {
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

    /// Print the scan summary, skips and read errors to stderr.
    fn finish(mut self, stats: &Stats, started: Instant) -> anyhow::Result<()> {
        self.stdout.flush()?;
        #[allow(clippy::cast_precision_loss)] // display only
        let mib = stats.bytes as f64 / (1024.0 * 1024.0);
        let what = if self.only.is_some() { "registered candidates" } else { "candidates" };
        eprintln!(
            "secrettrace: scanned {} documents ({mib:.1} MiB) in {:.1}s: {} {what} in {} documents",
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_fit_the_server_rules() {
        let c = counters(&Stats::default(), 3, 1, Instant::now());
        assert!(c.len() <= 32);
        assert!(c.keys().all(|k| !k.is_empty() && k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')));
        assert_eq!(c["unique_digests"], 3);
    }
}
