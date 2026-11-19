use std::io::{IsTerminal as _, Read as _};
use std::net::SocketAddr;

use anyhow::{Context as _, bail};
use clap::{Parser, Subcommand};
use st_server::app::{self, AppState, HttpLimits};
use st_server::audit::{self, AuditEvent};
use st_server::auth::{Role, session};
use st_server::config::{Config, WorkerSettings};
use st_server::{crypto, db, logging, users, worker};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "secrettrace-server", version, about = "SecretTrace API server and admin commands")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the HTTP API.
    Serve,
    /// Run server-side scans: the job queue, the scheduler and the reaper.
    Worker,
    /// Apply database migrations (uses `ST_MIGRATION_DATABASE_URL` if set).
    Migrate,
    /// Recompute the audit log hash chain and report the head hash.
    VerifyAudit,
    /// Print a new random pepper key entry (`<version>:<base64>`) to stdout.
    GenPepper {
        #[arg(long, default_value_t = 1)]
        version: u16,
    },
    /// Print a new random data-encryption key (base64, 32 bytes) for `ST_DATA_KEY`.
    GenDataKey,
    /// Create a user. The password is read from a hidden prompt (or stdin).
    CreateUser {
        #[arg(long)]
        username: String,
        #[arg(long)]
        role: Role,
        /// Read the password from stdin (for automation) instead of prompting.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Remove a user's TOTP enrollment and sessions; they enroll again at next login.
    ResetMfa {
        #[arg(long)]
        username: String,
    },
    /// Clear the failed-login counter and lock of a user.
    UnlockUser {
        #[arg(long)]
        username: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if let Some(code) = askpass_mode() {
        std::process::exit(code);
    }
    let cli = Cli::parse();

    match cli.command {
        Command::GenPepper { version } => return gen_pepper(version),
        Command::GenDataKey => {
            gen_data_key();
            return Ok(());
        }
        Command::Worker => return run_worker().await,
        _ => {}
    }

    let config = Config::from_env().context("invalid configuration")?;
    logging::init(config.log_format);

    match cli.command {
        Command::Serve => serve(config).await,
        Command::Migrate => migrate(&config).await,
        Command::VerifyAudit => verify_audit(&config).await,
        Command::CreateUser { username, role, password_stdin } => {
            create_user(&config, &username, role, password_stdin).await
        }
        Command::ResetMfa { username } => reset_mfa(&config, &username).await,
        Command::UnlockUser { username } => unlock_user(&config, &username).await,
        Command::GenPepper { .. } | Command::GenDataKey | Command::Worker => unreachable!("handled above"),
    }
}

async fn serve(config: Config) -> anyhow::Result<()> {
    let pool = db::connect_lazy(&config.database_url, config.db_max_connections)?;
    if !config.auth.cookie_secure {
        tracing::warn!("ST_COOKIE_SECURE=false: session cookies are sent over plain HTTP (development only)");
    }
    let ingest = app::IngestLimits { digests_per_hour: config.ingest_digests_per_hour, ..app::IngestLimits::default() };
    let state = AppState::new(pool, config.pepper, config.data_key, config.auth).with_ingest_limits(ingest);
    let limits = HttpLimits { request_timeout: config.request_timeout, max_body_bytes: config.max_body_bytes };
    let web = match &config.web_dir {
        Some(dir) => {
            let assets = st_server::web::WebAssets::load(dir).context("cannot load the web UI (ST_WEB_DIR)")?;
            tracing::info!(files = assets.len(), "serving the web UI");
            Some(std::sync::Arc::new(assets))
        }
        None => None,
    };
    let router = app::router_with_web(state, limits, web);

    let listener = tokio::net::TcpListener::bind(config.listen_addr)
        .await
        .with_context(|| format!("cannot bind {}", config.listen_addr))?;
    tracing::info!(addr = %config.listen_addr, "listening");
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    tracing::info!("shut down");
    Ok(())
}

/// The worker runs this binary as git's `GIT_ASKPASS`: git calls it with one argument, the
/// prompt (`Username for '…': `), and `ST_GIT_ASKPASS_FILE` set. Prompts contain spaces,
/// subcommand names never do, so a normal invocation is never taken for one.
fn askpass_mode() -> Option<i32> {
    std::env::var_os(worker::ASKPASS_FILE_VAR)?;
    let mut args = std::env::args_os().skip(1);
    let prompt = args.next()?;
    if args.next().is_some() || !prompt.to_string_lossy().contains(' ') {
        return None;
    }
    Some(worker::askpass(&prompt))
}

async fn run_worker() -> anyhow::Result<()> {
    let settings = WorkerSettings::from_env().context("invalid configuration")?;
    logging::init(settings.log_format);
    let pool = db::connect_lazy(&settings.database_url, settings.db_max_connections)?;
    if settings.worker.allow_local_repos {
        tracing::warn!("ST_WORKER_ALLOW_LOCAL_REPOS=true: local repositories can be scanned (development only)");
    }
    if settings.worker.allow_any_host && settings.worker.allowed_hosts.is_empty() {
        tracing::warn!("ST_WORKER_ALLOW_ANY_HOST=true: sources may point at any host name");
    }
    let worker = worker::Worker::new(pool, std::sync::Arc::new(settings.pepper), settings.worker);
    worker.run(shutdown_signal()).await?;
    tracing::info!("worker shut down");
    Ok(())
}

async fn migrate(config: &Config) -> anyhow::Result<()> {
    let url = config.migration_database_url.as_ref().unwrap_or(&config.database_url);
    let pool = db::connect(url, 2).await.context("cannot connect for migrations")?;
    let before = db::applied_version(&pool).await?;
    db::MIGRATOR.run(&pool).await.context("migration failed")?;
    let after = db::applied_version(&pool).await?;

    if after == before {
        tracing::info!(schema_version = after, "schema is up to date");
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    let details = serde_json::json!({ "from_version": before, "to_version": after });
    audit::record(&mut tx, &AuditEvent::system("db.migrate").details(details)).await?;
    tx.commit().await?;
    tracing::info!(from = ?before, to = ?after, "migrations applied");
    Ok(())
}

async fn verify_audit(config: &Config) -> anyhow::Result<()> {
    let pool = db::connect(&config.database_url, 2).await?;
    match audit::verify_chain(&pool).await {
        Ok(report) => {
            tracing::info!(rows = report.rows, head = report.head.as_deref().unwrap_or("-"), "audit chain OK");
            Ok(())
        }
        Err(e) => {
            tracing::error!(error = %e, "audit chain verification FAILED");
            Err(e.into())
        }
    }
}

#[allow(clippy::print_stdout)]
fn gen_pepper(version: u16) -> anyhow::Result<()> {
    anyhow::ensure!((1..=32767).contains(&version), "version must be in 1..=32767");
    let key = crypto::pepper::generate_key();
    println!("{version}:{}", key.as_str());
    Ok(())
}

async fn create_user(config: &Config, username: &str, role: Role, password_stdin: bool) -> anyhow::Result<()> {
    let password = read_new_password(password_stdin)?;
    let pool = db::connect(&config.database_url, 2).await?;
    let mut tx = pool.begin().await?;
    let id = users::create(&mut tx, username, password, role, AuditEvent::system("user.create")).await?;
    tx.commit().await?;
    tracing::info!(user_id = %id, username, role = ?role, "user created; TOTP enrollment happens at first login");
    Ok(())
}

async fn reset_mfa(config: &Config, username: &str) -> anyhow::Result<()> {
    let pool = db::connect(&config.database_url, 2).await?;
    let mut tx = pool.begin().await?;
    let user = users::find_by_username(&mut tx, username).await?.context("no such user")?;
    users::reset_mfa(&mut tx, user.id).await?;
    audit::record(&mut tx, &AuditEvent::system("user.mfa_reset").target("user", user.id.to_string())).await?;
    tx.commit().await?;
    tracing::info!(user_id = %user.id, "MFA reset; all sessions revoked");
    Ok(())
}

async fn unlock_user(config: &Config, username: &str) -> anyhow::Result<()> {
    let pool = db::connect(&config.database_url, 2).await?;
    let mut tx = pool.begin().await?;
    let user = users::find_by_username(&mut tx, username).await?.context("no such user")?;
    users::reset_failures(&mut tx, user.id).await?;
    session::delete_all_for_user(&mut tx, user.id).await?;
    audit::record(&mut tx, &AuditEvent::system("user.unlock").target("user", user.id.to_string())).await?;
    tx.commit().await?;
    tracing::info!(user_id = %user.id, "user unlocked");
    Ok(())
}

fn read_new_password(from_stdin: bool) -> anyhow::Result<Zeroizing<String>> {
    if from_stdin {
        let mut buf = Zeroizing::new(String::new());
        std::io::stdin().take(1024).read_to_string(&mut buf)?;
        let trimmed = Zeroizing::new(buf.trim_end_matches(['\n', '\r']).to_owned());
        return Ok(trimmed);
    }
    if !std::io::stdin().is_terminal() {
        bail!("stdin is not a terminal; use --password-stdin");
    }
    let first = Zeroizing::new(rpassword::prompt_password("Password: ")?);
    let second = Zeroizing::new(rpassword::prompt_password("Repeat password: ")?);
    if *first != *second {
        bail!("passwords do not match");
    }
    Ok(first)
}

#[allow(clippy::print_stdout)]
fn gen_data_key() {
    // Same format as a pepper key (base64 of 32 random bytes), but a separate secret.
    let key = crypto::pepper::generate_key();
    println!("{}", key.as_str());
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %e, "cannot listen for Ctrl+C");
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(e) => tracing::error!(error = %e, "cannot listen for SIGTERM"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
