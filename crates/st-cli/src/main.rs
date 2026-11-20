//! `secrettrace` CLI.
//!
//! The plaintext value is read from a hidden prompt or stdin, never from argv
//! (argv is visible in `ps` and shell history), normalized and hashed locally,
//! then zeroized. Only the digest and policy-compliant hints are printed.
//!
//! `extract` and `scan` run the candidate extractor locally and print masked findings;
//! digests are printed only on explicit request. `scan … --server` sends the scan to the
//! server (only digests, then locations of registered ones) and `register` adds a secret
//! to the registry.
//!
//! Exit codes: 0 — success; 1 — registered secrets found (`scan --server`, see
//! `--fail-on`); 2 — error (bad arguments, unreadable files, server unreachable or
//! rejecting the request): the result is not known.

mod client;
mod register;
mod scan;
mod submit;

use std::io::{IsTerminal as _, Read as _, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context as _, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use st_core::{Hints, SecretType, mask, prepare};
use st_extract::{Candidate, Confidence, Config, Extractor, looks_binary};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "secrettrace", version, about = "SecretTrace client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Compute the client-side digest and hints for a secret value.
    ///
    /// The output is safe to send to the server for registration. Treat the digest of
    /// a weak password as sensitive: it can be brute-forced.
    Digest {
        /// Secret type (affects normalization and hint policy).
        #[arg(long = "type", value_enum)]
        secret_type: CliSecretType,
        /// Read the value from stdin instead of an interactive hidden prompt.
        #[arg(long)]
        stdin: bool,
    },
    /// Show the secret candidates found in files (diagnostic; matching happens on the server).
    ///
    /// Prints one JSON object per candidate with location, detector and mask. Plaintext
    /// is never printed.
    Extract {
        /// Files to scan; `-` reads stdin.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        #[command(flatten)]
        output: OutputArgs,
    },
    /// Scan a directory tree or a git history locally and print masked candidates (JSON Lines).
    ///
    /// A summary goes to stderr. The command fails if some files could not be read, so a
    /// partial scan is never mistaken for a clean one.
    Scan {
        #[command(subcommand)]
        target: scan::Target,
    },
    /// Register a secret on the server by its digest (signs in with password and TOTP).
    ///
    /// The value is read from a hidden prompt or stdin and never leaves this machine;
    /// the password and TOTP code are read from the terminal.
    Register(register::RegisterArgs),
}

/// Output options shared by `extract` and `scan`.
#[derive(Args)]
struct OutputArgs {
    /// Also print digests. They are brute-forceable for weak passwords: do not use in CI logs.
    #[arg(long)]
    show_digests: bool,
    /// Skip context-free high-entropy tokens.
    #[arg(long)]
    no_entropy: bool,
    /// Report only candidates at or above this confidence.
    #[arg(long, value_enum, default_value_t = CliConfidence::Low)]
    min_confidence: CliConfidence,
}

impl OutputArgs {
    fn extractor(&self) -> Extractor {
        Extractor::new(Config { entropy: !self.no_entropy, ..Config::default() })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CliConfidence {
    Low,
    Medium,
    High,
}

impl From<CliConfidence> for Confidence {
    fn from(c: CliConfidence) -> Self {
        match c {
            CliConfidence::Low => Self::Low,
            CliConfidence::Medium => Self::Medium,
            CliConfidence::High => Self::High,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum CliSecretType {
    ApiKey,
    Password,
    Token,
    Certificate,
    PrivateKey,
    SshKey,
    DbConnectionString,
    Other,
}

impl From<CliSecretType> for SecretType {
    fn from(t: CliSecretType) -> Self {
        match t {
            CliSecretType::ApiKey => Self::ApiKey,
            CliSecretType::Password => Self::Password,
            CliSecretType::Token => Self::Token,
            CliSecretType::Certificate => Self::Certificate,
            CliSecretType::PrivateKey => Self::PrivateKey,
            CliSecretType::SshKey => Self::SshKey,
            CliSecretType::DbConnectionString => Self::DbConnectionString,
            CliSecretType::Other => Self::Other,
        }
    }
}

#[derive(Serialize)]
struct DigestOutput {
    #[serde(rename = "type")]
    secret_type: SecretType,
    digest: String,
    hints: Hints,
    masked: String,
}

/// Exit code for errors: the outcome is unknown (distinct from 1, "secrets found").
const EXIT_ERROR: u8 = 2;

fn main() -> ExitCode {
    let ok = |r: anyhow::Result<()>| r.map(|()| ExitCode::SUCCESS);
    let result = match Cli::parse().command {
        Command::Digest { secret_type, stdin } => ok(digest(secret_type.into(), stdin)),
        Command::Extract { paths, output } => ignore_broken_pipe(ok(extract(&paths, &output))),
        Command::Scan { target } => ignore_broken_pipe(scan::run(target)),
        Command::Register(args) => ok(register::run(&args)),
    };
    result.unwrap_or_else(|e| {
        eprintln!("secrettrace: error: {e:#}");
        ExitCode::from(EXIT_ERROR)
    })
}

/// `secrettrace extract … | head` closes the pipe early; that is not an error.
fn ignore_broken_pipe(result: anyhow::Result<ExitCode>) -> anyhow::Result<ExitCode> {
    match result {
        Err(e) if e.downcast_ref::<std::io::Error>().is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe) => {
            Ok(ExitCode::SUCCESS)
        }
        Err(e)
            if e.downcast_ref::<serde_json::Error>()
                .is_some_and(|j| j.io_error_kind() == Some(std::io::ErrorKind::BrokenPipe)) =>
        {
            Ok(ExitCode::SUCCESS)
        }
        other => other,
    }
}

/// Largest file read by `extract`; the extractor reports anything beyond as truncated.
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Serialize)]
struct ExtractOutput<'a> {
    path: String,
    #[serde(flatten)]
    candidate: &'a Candidate,
    #[serde(skip_serializing_if = "Option::is_none")]
    digest: Option<String>,
}

fn extract(paths: &[PathBuf], output: &OutputArgs) -> anyhow::Result<()> {
    let extractor = output.extractor();
    let min_confidence = Confidence::from(output.min_confidence);
    let mut stdout = std::io::stdout().lock();
    let mut failed = 0usize;
    for path in paths {
        let label = path.display().to_string();
        let bytes = match read_limited(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("secrettrace: {label}: {e:#}");
                failed += 1;
                continue;
            }
        };
        if looks_binary(&bytes) {
            eprintln!("secrettrace: {label}: binary, skipped");
            continue;
        }
        let text = Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned());
        drop(bytes);
        let result = extractor.extract(&text);
        if result.truncated {
            eprintln!("secrettrace: {label}: limits reached, results are partial");
        }
        for candidate in result.candidates.iter().filter(|c| c.confidence >= min_confidence) {
            let out = ExtractOutput {
                path: label.clone(),
                candidate,
                digest: output.show_digests.then(|| candidate.digest.to_hex()),
            };
            serde_json::to_writer(&mut stdout, &out)?;
            writeln!(stdout)?;
        }
    }
    if failed > 0 {
        bail!("{failed} file(s) could not be read");
    }
    Ok(())
}

fn read_limited(path: &std::path::Path) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(Vec::new());
    if path.as_os_str() == "-" {
        std::io::stdin().take(MAX_FILE_BYTES).read_to_end(&mut buf).context("cannot read stdin")?;
    } else {
        if path.is_dir() {
            bail!("is a directory; use `secrettrace scan fs`");
        }
        let file = std::fs::File::open(path).context("cannot open")?;
        // Pre-size the buffer: growing a Vec frees old copies without zeroizing them.
        let len = file.metadata().map_or(0, |m| m.len().min(MAX_FILE_BYTES));
        buf.reserve_exact(usize::try_from(len).unwrap_or(0));
        file.take(MAX_FILE_BYTES).read_to_end(&mut buf).context("cannot read")?;
    }
    Ok(buf)
}

fn digest(secret_type: SecretType, from_stdin: bool) -> anyhow::Result<()> {
    let value = read_value(secret_type, from_stdin)?;
    let (digest, hints) = prepare(secret_type, &value).context("value rejected")?;
    drop(value); // zeroized here

    let out = DigestOutput { secret_type, digest: digest.to_hex(), masked: mask(&hints), hints };
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, &out)?;
    writeln!(stdout)?;
    Ok(())
}

fn read_value(secret_type: SecretType, from_stdin: bool) -> anyhow::Result<Zeroizing<String>> {
    if from_stdin {
        let mut buf = Zeroizing::new(String::new());
        std::io::stdin().take(64 * 1024).read_to_string(&mut buf).context("cannot read stdin")?;
        return Ok(buf);
    }
    if !std::io::stdin().is_terminal() {
        bail!("stdin is not a terminal; pass --stdin to read the value from a pipe");
    }
    if secret_type.is_key_material() {
        bail!(
            "multi-line key material cannot be typed at a prompt; use: secrettrace digest --type {} --stdin < key.pem",
            secret_type.as_str().replace('_', "-")
        );
    }
    let value = rpassword::prompt_password("Secret value (input hidden): ").context("cannot read from terminal")?;
    Ok(Zeroizing::new(value))
}
