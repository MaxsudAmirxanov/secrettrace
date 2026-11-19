//! `secrettrace` CLI.
//!
//! The plaintext value is read from a hidden prompt or stdin, never from argv
//! (argv is visible in `ps` and shell history), normalized and hashed locally,
//! then zeroized. Only the digest and policy-compliant hints are printed.

use std::io::{IsTerminal as _, Read as _, Write as _};

use anyhow::{Context as _, bail};
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use st_core::{Hints, SecretType, mask, prepare};
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

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Digest { secret_type, stdin } => digest(secret_type.into(), stdin),
    }
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
