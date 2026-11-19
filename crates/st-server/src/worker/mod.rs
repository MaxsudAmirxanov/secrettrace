//! Server-side scans of `git_repo` sources: `secrettrace-server worker`.
//!
//! - **Queue.** Jobs are `scan_jobs` rows (trigger `manual` from the API, `schedule` from
//!   the scheduler) claimed with `FOR UPDATE SKIP LOCKED`; the claim is a lease kept alive by
//!   heartbeats. A lost lease (cancelled, reaped, source deleted) stops the job and nothing
//!   of it is recorded. Failures are retried with exponential backoff up to `max_attempts`.
//! - **Scheduler.** Sources with `next_scan_at <= now()` get one queued job (never a second
//!   while one is active) and the next firing of their cron schedule.
//! - **Fetch.** One bare mirror per source, branches and tags only, hardened git (see
//!   [`fetch`]); credentials by reference from a directory, never in argv, env or the DB.
//! - **Scan.** History since the tips of the last successful scan plus the whole `HEAD`
//!   tree, so each run sees the full current state; only registered digests produce
//!   locations, recorded with the ingest logic in one transaction with the job's success
//!   and the new incremental state.

mod credentials;
mod fetch;
mod queue;
mod remote;
mod scan;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{PgPool, Row as _};
use st_core::Digest;
use tokio::sync::watch;
use tokio::task::JoinSet;
use uuid::Uuid;

pub use credentials::{ASKPASS_FILE_VAR, ASKPASS_USERNAME_VAR, DEFAULT_HTTPS_USERNAME, MAX_CREDENTIAL_BYTES, askpass};

use crate::audit;
use crate::crypto::Pepper;
use crate::error::ApiError;
use crate::ingest::{self, FindingsResponse};
use crate::model::SourceType;
use credentials::{Credential, Kind, check_host_binding};
use queue::{Claimed, Failed};
use remote::Transport;

/// Longest stored error message.
const MAX_ERROR_LEN: usize = 500;
const HOUSEKEEPING_EVERY: Duration = Duration::from_secs(3600);
/// How long shutdown waits for running jobs to hand themselves back.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// Lease owner name in `scan_jobs.locked_by`; at most 64 chars.
    pub worker_id: String,
    /// Mirrors live in `<data_dir>/repos/<source_id>.git`.
    pub data_dir: PathBuf,
    /// Per-job private directories (credential copies, git's `HOME`).
    pub tmp_dir: PathBuf,
    /// `<credentials_dir>/<credential_ref>`.
    pub credentials_dir: PathBuf,
    /// Required for ssh sources (`StrictHostKeyChecking=yes`).
    pub ssh_known_hosts: Option<PathBuf>,
    pub git: PathBuf,
    /// Program git runs as `GIT_ASKPASS` (this binary).
    pub askpass: PathBuf,
    pub concurrency: NonZeroUsize,
    pub scan_threads: NonZeroUsize,
    /// Fetch plus scan of one job.
    pub job_timeout: Duration,
    /// A running job whose heartbeat is older is reclaimed; heartbeats every fifth of it.
    pub lease_timeout: Duration,
    pub poll_interval: Duration,
    pub max_attempts: u32,
    /// First retry delay, doubled per attempt.
    pub retry_backoff: Duration,
    /// Lowercase host names sources may point at. Empty allows nothing unless
    /// `allow_any_host`; IP literals only when listed literally.
    pub allowed_hosts: Vec<String>,
    /// With an empty `allowed_hosts`: any host name (an explicit deployer decision).
    pub allow_any_host: bool,
    /// `file://` and absolute paths (tests and development only).
    pub allow_local_repos: bool,
    pub max_blob_bytes: u64,
    /// A fetch growing the mirror's objects past this is stopped.
    pub max_repo_bytes: u64,
}

/// Default [`WorkerConfig::max_repo_bytes`]: 2 GiB.
pub const DEFAULT_MAX_REPO_BYTES: u64 = 2 * 1024 * 1024 * 1024;

impl WorkerConfig {
    #[must_use]
    pub fn new(data_dir: PathBuf, credentials_dir: PathBuf) -> Self {
        Self {
            worker_id: default_worker_id(),
            data_dir,
            tmp_dir: std::env::temp_dir(),
            credentials_dir,
            ssh_known_hosts: None,
            git: PathBuf::from("git"),
            askpass: std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/usr/local/bin/secrettrace-server")),
            concurrency: NonZeroUsize::MIN,
            scan_threads: std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN),
            job_timeout: Duration::from_secs(30 * 60),
            lease_timeout: Duration::from_secs(5 * 60),
            poll_interval: Duration::from_secs(5),
            max_attempts: 3,
            retry_backoff: Duration::from_secs(60),
            allowed_hosts: Vec::new(),
            allow_any_host: false,
            allow_local_repos: false,
            max_blob_bytes: st_source::DEFAULT_MAX_FILE_BYTES,
            max_repo_bytes: DEFAULT_MAX_REPO_BYTES,
        }
    }
}

/// `<host>-<pid>-<random>`, restricted to `[A-Za-z0-9._-]`, at most 64 chars.
#[must_use]
pub fn default_worker_id() -> String {
    let host = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .unwrap_or_else(|| "worker".into());
    let host: String =
        host.trim().chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')).take(40).collect();
    let host = if host.is_empty() { "worker".to_owned() } else { host };
    format!("{host}-{}-{:08x}", std::process::id(), rand::random::<u32>())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReapReport {
    /// Expired worker leases put back in the queue.
    pub requeued: u64,
    /// Expired worker leases with no attempts left.
    pub failed: u64,
    /// API scans still running past the ingest window.
    pub api_scans_failed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeStatus {
    Succeeded,
    Failed,
    /// Back in the queue: a retry later, or released at shutdown.
    Retrying,
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct JobOutcome {
    pub job_id: Uuid,
    pub source_id: Option<Uuid>,
    pub status: OutcomeStatus,
    pub error: Option<String>,
    /// The stats stored with a successful job (empty otherwise).
    pub stats: BTreeMap<String, u64>,
}

/// A job failure as stored in `scan_jobs.error`: a fixed message or a git summary,
/// never contents or credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobError {
    pub message: String,
    pub retryable: bool,
}

impl JobError {
    fn new(message: impl Into<String>, retryable: bool) -> Self {
        let message: String =
            message.into().chars().map(|c| if c.is_control() { '?' } else { c }).take(MAX_ERROR_LEN).collect();
        Self { message, retryable }
    }

    #[must_use]
    pub fn retryable(message: impl Into<String>) -> Self {
        Self::new(message, true)
    }

    #[must_use]
    pub fn permanent(message: impl Into<String>) -> Self {
        Self::new(message, false)
    }
}

impl std::fmt::Display for JobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Why a run ended without success.
#[derive(Debug)]
enum Abort {
    Fail(JobError),
    /// The source is gone or disabled: close the job as cancelled.
    Cancel(&'static str),
    /// The job is no longer ours (cancelled through the API, reaped).
    Lost,
    Shutdown,
}

impl From<JobError> for Abort {
    fn from(e: JobError) -> Self {
        Self::Fail(e)
    }
}

/// What a scan hands to the finishing transaction.
struct ScanResults {
    findings: Vec<ingest::FindingIn>,
    unread_paths: Vec<String>,
    stats: BTreeMap<String, u64>,
    next_state: Value,
}

/// Per-source settings in `sources.config`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct SourceConfig {
    username: Option<String>,
    max_blob_bytes: Option<u64>,
}

#[derive(Clone)]
pub struct Worker {
    inner: Arc<Inner>,
}

struct Inner {
    db: PgPool,
    pepper: Arc<Pepper>,
    config: WorkerConfig,
}

impl std::fmt::Debug for Worker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Worker").field("worker_id", &self.inner.config.worker_id).finish_non_exhaustive()
    }
}

fn db_error(job: Uuid, e: &dyn std::fmt::Display) -> Abort {
    tracing::error!(job_id = %job, error = %e, "database error during scan job");
    Abort::Fail(JobError::retryable("database error"))
}

impl Worker {
    #[must_use]
    pub fn new(db: PgPool, pepper: Arc<Pepper>, config: WorkerConfig) -> Self {
        Self { inner: Arc::new(Inner { db, pepper, config }) }
    }

    #[must_use]
    pub fn config(&self) -> &WorkerConfig {
        &self.inner.config
    }

    fn id(&self) -> &str {
        &self.inner.config.worker_id
    }

    /// Loop until `shutdown` resolves: reaper and scheduler every poll interval, jobs up to
    /// `concurrency` at a time. On shutdown running jobs are handed back to the queue.
    pub async fn run(&self, shutdown: impl Future<Output = ()>) -> anyhow::Result<()> {
        let cfg = &self.inner.config;
        tracing::info!(worker_id = %cfg.worker_id, concurrency = cfg.concurrency.get(), "worker started");
        disable_core_dumps();
        let (tmp, age) = (cfg.tmp_dir.clone(), cfg.job_timeout + cfg.lease_timeout);
        match tokio::task::spawn_blocking(move || sweep_job_dirs(&tmp, age)).await {
            Ok(0) | Err(_) => {}
            Ok(n) => tracing::info!(removed = n, "removed stale job directories"),
        }
        let (stop_tx, stop_rx) = watch::channel(false);
        let mut jobs: JoinSet<()> = JoinSet::new();
        let mut last_maintenance: Option<Instant> = None;
        let mut last_housekeeping: Option<Instant> = None;
        tokio::pin!(shutdown);
        loop {
            if last_housekeeping.is_none_or(|t| t.elapsed() >= HOUSEKEEPING_EVERY) {
                last_housekeeping = Some(Instant::now());
                match self.housekeeping().await {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(removed = n, "removed mirrors of deleted sources"),
                    Err(e) => tracing::warn!(error = %e, "mirror cleanup failed"),
                }
            }
            if last_maintenance.is_none_or(|t| t.elapsed() >= cfg.poll_interval) {
                last_maintenance = Some(Instant::now());
                if let Err(e) = self.reap().await {
                    tracing::warn!(error = %e, "reaper failed");
                }
                if let Err(e) = self.schedule_due().await {
                    tracing::warn!(error = %e, "scheduler failed");
                }
            }
            while jobs.len() < cfg.concurrency.get() {
                match queue::claim(&self.inner.db, self.id()).await {
                    Ok(Some(job)) => {
                        let worker = self.clone();
                        let stop = stop_rx.clone();
                        jobs.spawn(async move {
                            if let Err(e) = worker.run_claimed(job, stop).await {
                                tracing::error!(error = %e, "scan job bookkeeping failed");
                            }
                        });
                    }
                    Ok(None) => break,
                    Err(e) => {
                        tracing::warn!(error = %e, "cannot claim a job");
                        break;
                    }
                }
            }
            tokio::select! {
                () = &mut shutdown => break,
                Some(_) = jobs.join_next(), if !jobs.is_empty() => {}
                () = tokio::time::sleep(cfg.poll_interval) => {}
            }
        }
        tracing::info!(running = jobs.len(), "worker stopping");
        let _ = stop_tx.send(true);
        let drained = tokio::time::timeout(SHUTDOWN_GRACE, async { while jobs.join_next().await.is_some() {} });
        if drained.await.is_err() {
            tracing::warn!("jobs did not stop in time; their leases will expire");
        }
        Ok(())
    }

    /// Enqueue due scheduled scans; returns how many jobs were created.
    pub async fn schedule_due(&self) -> anyhow::Result<u64> {
        queue::schedule_due(&self.inner.db, self.id()).await
    }

    /// Reclaim expired leases and fail stale API scans.
    pub async fn reap(&self) -> anyhow::Result<ReapReport> {
        let cfg = &self.inner.config;
        queue::reap(&self.inner.db, self.id(), cfg.lease_timeout, cfg.max_attempts).await
    }

    /// Claim at most one due job and run it to the end; `None` if the queue is empty.
    pub async fn run_once(&self) -> anyhow::Result<Option<JobOutcome>> {
        let Some(job) = queue::claim(&self.inner.db, self.id()).await? else { return Ok(None) };
        let (_keep, stop) = watch::channel(false);
        Ok(Some(self.run_claimed(job, stop).await?))
    }

    /// Remove mirrors whose source no longer exists (or is no longer a git repo).
    pub async fn housekeeping(&self) -> anyhow::Result<u64> {
        let repos = self.inner.config.data_dir.join("repos");
        let found = tokio::task::spawn_blocking(move || list_mirrors(&repos)).await??;
        if found.is_empty() {
            return Ok(0);
        }
        let ids: Vec<Uuid> = found.iter().map(|(id, _)| *id).collect();
        let keep: HashSet<Uuid> =
            sqlx::query_scalar::<_, Uuid>("SELECT id FROM sources WHERE id = ANY($1) AND type = 'git_repo'")
                .bind(&ids)
                .fetch_all(&self.inner.db)
                .await?
                .into_iter()
                .collect();
        let stale: Vec<PathBuf> = found.into_iter().filter(|(id, _)| !keep.contains(id)).map(|(_, p)| p).collect();
        let n = u64::try_from(stale.len()).unwrap_or(u64::MAX);
        tokio::task::spawn_blocking(move || {
            for path in stale {
                let removed = match std::fs::symlink_metadata(&path) {
                    Ok(m) if m.is_dir() => std::fs::remove_dir_all(&path),
                    Ok(_) => std::fs::remove_file(&path),
                    Err(e) => Err(e),
                };
                if let Err(e) = removed {
                    tracing::warn!(path = %path.display(), error = %e, "cannot remove stale mirror");
                }
            }
        })
        .await?;
        Ok(n)
    }

    async fn run_claimed(&self, job: Claimed, mut stop: watch::Receiver<bool>) -> anyhow::Result<JobOutcome> {
        let cfg = &self.inner.config;
        let db = &self.inner.db;
        tracing::info!(job_id = %job.id, source_id = ?job.source_id, attempt = job.attempts, "scan job started");
        let cancel = Arc::new(AtomicBool::new(false));
        let stopping = async {
            if stop.wait_for(|s| *s).await.is_err() {
                std::future::pending::<()>().await;
            }
        };
        let result = tokio::select! {
            r = tokio::time::timeout(cfg.job_timeout, self.execute(&job, &cancel)) => {
                r.unwrap_or_else(|_| Err(Abort::Fail(JobError::retryable("scan timed out"))))
            }
            () = self.lease_watch(&job) => Err(Abort::Lost),
            () = stopping => Err(Abort::Shutdown),
        };
        // Stops a scan still running on a blocking thread.
        cancel.store(true, Ordering::Relaxed);

        let (status, error, job_stats) = match result {
            Ok(saved) => (OutcomeStatus::Succeeded, None, saved),
            Err(Abort::Fail(e)) => {
                match queue::fail(db, self.id(), &job, &e, cfg.max_attempts, cfg.retry_backoff).await? {
                    Failed::Retrying => (OutcomeStatus::Retrying, Some(e.message), BTreeMap::new()),
                    Failed::Final => (OutcomeStatus::Failed, Some(e.message), BTreeMap::new()),
                    Failed::Lost => self.lost(job.id).await?,
                }
            }
            Err(Abort::Cancel(reason)) => {
                if queue::cancel(db, &job, reason).await? {
                    (OutcomeStatus::Cancelled, Some(reason.to_owned()), BTreeMap::new())
                } else {
                    self.lost(job.id).await?
                }
            }
            Err(Abort::Lost) => self.lost(job.id).await?,
            Err(Abort::Shutdown) => {
                queue::release(db, &job).await?;
                (OutcomeStatus::Retrying, Some("worker shutting down".to_owned()), BTreeMap::new())
            }
        };
        match &error {
            None => tracing::info!(job_id = %job.id, status = ?status, "scan job finished"),
            Some(e) => tracing::warn!(job_id = %job.id, status = ?status, error = %e, "scan job did not succeed"),
        }
        Ok(JobOutcome { job_id: job.id, source_id: job.source_id, status, error, stats: job_stats })
    }

    /// The outcome of a job this worker lost, as the database now has it.
    async fn lost(&self, job: Uuid) -> anyhow::Result<(OutcomeStatus, Option<String>, BTreeMap<String, u64>)> {
        let (status, error) = queue::status_of(&self.inner.db, job).await?.unwrap_or(("cancelled".into(), None));
        let status = match status.as_str() {
            "succeeded" => OutcomeStatus::Succeeded,
            "failed" => OutcomeStatus::Failed,
            "queued" => OutcomeStatus::Retrying,
            _ => OutcomeStatus::Cancelled,
        };
        Ok((status, error, BTreeMap::new()))
    }

    /// Heartbeats until the lease is lost (then returns); never returns while it is held.
    async fn lease_watch(&self, claimed: &Claimed) {
        let job = claimed.id;
        let every = (self.inner.config.lease_timeout / 5).max(Duration::from_millis(100));
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await;
        loop {
            tick.tick().await;
            match queue::heartbeat(&self.inner.db, &claimed.lease, job).await {
                Ok(true) => {}
                Ok(false) => {
                    tracing::info!(job_id = %job, "lease lost; stopping the job");
                    return;
                }
                Err(e) => tracing::warn!(job_id = %job, error = %e, "heartbeat failed"),
            }
        }
    }

    #[allow(clippy::too_many_lines)] // one linear pipeline: source → fetch → scan → match → record
    async fn execute(&self, job: &Claimed, cancel: &Arc<AtomicBool>) -> Result<BTreeMap<String, u64>, Abort> {
        let cfg = &self.inner.config;
        let db = &self.inner.db;
        let Some(source_id) = job.source_id else { return Err(Abort::Cancel("source deleted")) };
        let row =
            sqlx::query("SELECT type, uri, credential_ref, config, scan_state, enabled FROM sources WHERE id = $1")
                .bind(source_id)
                .fetch_optional(db)
                .await
                .map_err(|e| db_error(job.id, &e))?;
        let Some(row) = row else { return Err(Abort::Cancel("source deleted")) };
        let get = |e: sqlx::Error| db_error(job.id, &e);
        if !row.try_get::<bool, _>("enabled").map_err(get)? {
            return Err(Abort::Cancel("source disabled"));
        }
        if row.try_get::<SourceType, _>("type").map_err(get)? != SourceType::GitRepo {
            return Err(JobError::permanent("only git_repo sources can be scanned by the server").into());
        }
        let uri: String = row.try_get("uri").map_err(get)?;
        let credential_ref: Option<String> = row.try_get("credential_ref").map_err(get)?;
        let source_config: SourceConfig =
            serde_json::from_value(row.try_get::<Value, _>("config").map_err(get)?).unwrap_or_default();
        let stored = scan::parse_state(&row.try_get::<Value, _>("scan_state").map_err(get)?);

        let policy = remote::HostPolicy {
            allowed: &cfg.allowed_hosts,
            allow_any: cfg.allow_any_host,
            allow_local: cfg.allow_local_repos,
        };
        let remote = remote::parse(&uri, policy)?;
        let known_hosts = match remote.transport {
            Transport::Ssh => Some(
                cfg.ssh_known_hosts
                    .as_deref()
                    .filter(|p| p.is_file())
                    .ok_or_else(|| JobError::permanent("ssh known_hosts file is not configured"))?,
            ),
            _ => None,
        };
        let username = source_config.username.as_deref().filter(|u| !u.is_empty());
        if username.is_some_and(|u| u.len() > 64 || u.chars().any(|c| c.is_control() || c.is_whitespace())) {
            return Err(JobError::permanent("invalid source username").into());
        }
        let max_blob_bytes = source_config.max_blob_bytes.filter(|&n| n > 0).unwrap_or(cfg.max_blob_bytes);

        // Registry state before anything is read: a secret registered later is covered by
        // the next scan, which then sees a different watermark and reads all history.
        let registry = self.registry_watermark().await.map_err(|e| db_error(job.id, &e))?;
        let full = job.full_scan || stored.registry.as_deref() != Some(registry.as_str());
        let old_tips = if full { Vec::new() } else { stored.tips };

        // One job per mirror at a time, across workers sharing the data dir.
        let repos = prepare_repos_dir(&cfg.data_dir)?;
        let _lock = acquire_mirror(&repos.join(format!("{source_id}.lock"))).await?;
        let mirror = repos.join(format!("{source_id}.git"));

        // Fetch, with the credential (if any) copied into a private dir removed right after.
        {
            std::fs::create_dir_all(&cfg.tmp_dir)
                .map_err(|_| JobError::retryable("cannot create a temporary directory"))?;
            let home = tempfile::Builder::new()
                .prefix("st-job-")
                .tempdir_in(&cfg.tmp_dir)
                .map_err(|_| JobError::retryable("cannot create a temporary directory"))?;
            let kind = match remote.transport {
                Transport::Https => Some(Kind::Token),
                Transport::Ssh => Some(Kind::SshKey),
                Transport::Local => None,
            };
            let credential = match (credential_ref.as_deref(), kind) {
                (Some(name), Some(kind)) => {
                    check_host_binding(&cfg.credentials_dir, name, &remote.host)?;
                    Some(Credential::load(&cfg.credentials_dir, name, kind)?)
                }
                _ => None,
            };
            let copy = credential.as_ref().map(|c| c.write_private_copy(home.path())).transpose()?;
            let is_key = credential.as_ref().is_some_and(|c| c.kind == Kind::SshKey);
            drop(credential);
            let env = fetch::GitEnv {
                git: &cfg.git,
                uri: &uri,
                remote: &remote,
                home: home.path(),
                askpass: &cfg.askpass,
                token_file: copy.clone().filter(|_| !is_key),
                username,
                ssh_key: copy.filter(|_| is_key),
                known_hosts,
                max_repo_bytes: cfg.max_repo_bytes,
            };
            env.sync_mirror(&mirror).await?;
        }

        let scanned = {
            let (git_bin, repo_dir, threads, stop) =
                (cfg.git.clone(), mirror.clone(), cfg.scan_threads, Arc::clone(cancel));
            tokio::task::spawn_blocking(move || {
                scan::scan_mirror(&git_bin, &repo_dir, &old_tips, max_blob_bytes, threads, &stop)
            })
            .await
            .map_err(|_| JobError::retryable("scan failed"))?
            .map_err(|e| e.map_or(Abort::Lost, Abort::Fail))?
        };

        let digests = scan::unique_digests(&scanned.report);
        let matched: HashSet<Digest> = if digests.is_empty() {
            HashSet::new()
        } else {
            let mut conn = db.acquire().await.map_err(|e| db_error(job.id, &e))?;
            let found =
                ingest::registered(&mut conn, &self.inner.pepper, &digests).await.map_err(|e| db_error(job.id, &e))?;
            found.keys().filter_map(|&i| digests.get(i).copied()).collect()
        };
        let blobs = scan::matched_blobs(&scanned.report, &matched);
        let occurrences = if blobs.is_empty() {
            HashMap::new()
        } else {
            let (git_bin, repo_dir, stop) = (cfg.git.clone(), mirror.clone(), Arc::clone(cancel));
            tokio::task::spawn_blocking(move || {
                st_source::GitRepo::open_with(&repo_dir, git_bin)
                    .and_then(|repo| repo.with_cancel(stop).locate(&[], &blobs))
            })
            .await
            .map_err(|_| JobError::retryable("scan failed"))?
            .map_err(|e| scan::source_error(&e))?
        };
        let findings = scan::findings(&scanned, &matched, &occurrences);

        let mut stats = scan::source_stats(&scanned.report.stats);
        stats.insert("incremental".into(), u64::from(scanned.incremental));
        stats.insert("candidates".into(), u64::try_from(scanned.report.candidates()).unwrap_or(u64::MAX));
        stats.insert("matched".into(), u64::try_from(matched.len()).unwrap_or(u64::MAX));
        let next_state = scan::state_json(&scanned.tips, &registry);
        let results = ScanResults { findings, unread_paths: scanned.unread_paths, stats, next_state };
        self.finish(job, source_id, &uri, results).await
    }

    /// `count:max(created_at):pepper versions` of the registry. Secret values never change
    /// after creation, so a new or deleted secret, or a pepper change, changes it.
    async fn registry_watermark(&self) -> Result<String, sqlx::Error> {
        let row = sqlx::query("SELECT count(*) AS n, max(created_at) AS latest FROM secrets")
            .fetch_one(&self.inner.db)
            .await?;
        let n: i64 = row.try_get("n")?;
        let latest: Option<chrono::DateTime<chrono::Utc>> = row.try_get("latest")?;
        let mut peppers: Vec<u16> = self.inner.pepper.versions().collect();
        peppers.sort_unstable();
        let peppers: Vec<String> = peppers.iter().map(ToString::to_string).collect();
        Ok(scan::watermark(n, latest.map(|t| t.timestamp_micros()), &peppers.join(",")))
    }

    /// Record everything in one transaction, only if the job is still ours.
    async fn finish(
        &self,
        job: &Claimed,
        source_id: Uuid,
        uri: &str,
        results: ScanResults,
    ) -> Result<BTreeMap<String, u64>, Abort> {
        let ScanResults { findings, unread_paths, mut stats, next_state } = results;
        let err = |e: &dyn std::fmt::Display| db_error(job.id, e);
        let mut tx = self.inner.db.begin().await.map_err(|e| err(&e))?;
        // Source before job: the API locks them in this order too (disable, delete).
        let source: Option<String> = sqlx::query_scalar("SELECT uri FROM sources WHERE id = $1 FOR UPDATE")
            .bind(source_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| err(&e))?;
        if source.as_deref() != Some(uri) {
            return Err(Abort::Cancel("source deleted"));
        }
        let Some((started_at, environment)) =
            queue::lock_own(&mut tx, &job.lease, job.id).await.map_err(|e| err(&e))?
        else {
            return Err(Abort::Lost);
        };
        let target = ingest::Job {
            id: job.id,
            source_id,
            source_type: SourceType::GitRepo,
            uri: uri.to_owned(),
            environment,
            full_scan: true,
            started_at,
        };
        let counts = if findings.is_empty() {
            FindingsResponse::default()
        } else {
            ingest::record_findings(&mut tx, &self.inner.pepper, &target, &findings)
                .await
                .map_err(|e: ApiError| err(&e))?
        };
        // Each run sees the whole current state: rows earlier worker scans reported as
        // current and this one did not are no longer present. API-token rows are untouched,
        // and so are paths still in HEAD whose blob this run could not read (too large,
        // binary, missing): not seeing a secret there is no evidence it is gone.
        let no_longer_present = sqlx::query(
            "UPDATE locations l SET in_current_state = false
             FROM scan_jobs pj
             WHERE l.source_id = $1 AND l.in_current_state AND l.last_job_id IS DISTINCT FROM $2
               AND l.last_seen < $3 AND pj.id = l.last_job_id AND pj.trigger IN ('manual', 'schedule')
               AND NOT (coalesce(l.locator->>'path', '') = ANY($4))",
        )
        .bind(source_id)
        .bind(job.id)
        .bind(started_at)
        .bind(&unread_paths)
        .execute(&mut *tx)
        .await
        .map_err(|e| err(&e))?
        .rows_affected();

        stats.insert("accepted".into(), counts.accepted);
        stats.insert("new_locations".into(), counts.new_locations);
        stats.insert("updated_locations".into(), counts.updated_locations);
        stats.insert("violations".into(), counts.violations);
        stats.insert("no_longer_present".into(), no_longer_present);
        let stats_json = serde_json::to_value(&stats).map_err(|e| err(&e))?;

        sqlx::query("UPDATE sources SET scan_state = $2, last_scan_at = now() WHERE id = $1")
            .bind(source_id)
            .bind(&next_state)
            .execute(&mut *tx)
            .await
            .map_err(|e| err(&e))?;
        sqlx::query(
            "UPDATE scan_jobs SET status = 'succeeded', finished_at = now(), stats = $2, error = NULL,
                    locked_at = now()
             WHERE id = $1",
        )
        .bind(job.id)
        .bind(&stats_json)
        .execute(&mut *tx)
        .await
        .map_err(|e| err(&e))?;
        let mut details = json!({ "source_id": source_id, "status": "succeeded" });
        if let (Some(d), Value::Object(s)) = (details.as_object_mut(), stats_json) {
            d.extend(s);
        }
        let event = queue::event(self.id(), "scan.finish").target("scan_job", job.id.to_string()).details(details);
        audit::record(&mut tx, &event).await.map_err(|e| err(&e))?;
        tx.commit().await.map_err(|e| err(&e))?;
        Ok(stats)
    }
}

/// Attempts and pause of [`acquire_mirror`]: about two seconds in total.
const MIRROR_LOCK_ATTEMPTS: u32 = 20;
const MIRROR_LOCK_PAUSE: Duration = Duration::from_millis(100);

/// [`lock_mirror`], retried briefly. A `flock` belongs to the open file description, so a
/// child process forked (by any thread of this process) while the previous holder still
/// had the file open keeps the lock alive until that child calls `exec`. That window is
/// short; without a retry it shows up as a spurious "mirror is busy" and a minute of backoff.
async fn acquire_mirror(path: &Path) -> Result<std::fs::File, JobError> {
    let mut attempt = 1;
    loop {
        match lock_mirror(path) {
            Err(e) if e.message == "mirror is busy" && attempt < MIRROR_LOCK_ATTEMPTS => {
                attempt += 1;
                tokio::time::sleep(MIRROR_LOCK_PAUSE).await;
            }
            other => return other,
        }
    }
}

/// Exclusive lock on `<repos>/<source_id>.lock`, held while fetching and scanning.
fn lock_mirror(path: &Path) -> Result<std::fs::File, JobError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|_| JobError::retryable("cannot lock the mirror"))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(JobError::retryable("mirror is busy")),
        Err(std::fs::TryLockError::Error(_)) => Err(JobError::retryable("cannot lock the mirror")),
    }
}

/// No core dumps: a crash must not write scanned contents or credentials to disk.
pub fn disable_core_dumps() {
    #[cfg(unix)]
    {
        let none = rustix::process::Rlimit { current: Some(0), maximum: Some(0) };
        if let Err(e) = rustix::process::setrlimit(rustix::process::Resource::Core, none) {
            tracing::warn!(error = %e, "cannot disable core dumps");
        }
    }
}

/// Remove `st-job-*` directories in `tmp_dir` left by a crashed run: ours (same uid),
/// real directories (not symlinks), untouched for longer than `older_than`.
fn sweep_job_dirs(tmp_dir: &Path, older_than: Duration) -> u64 {
    let Ok(entries) = std::fs::read_dir(tmp_dir) else { return 0 };
    #[cfg(unix)]
    let uid = rustix::process::geteuid().as_raw();
    let mut removed = 0;
    for entry in entries.flatten() {
        if !entry.file_name().to_str().is_some_and(|n| n.starts_with("st-job-")) {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue }; // does not follow symlinks
        #[cfg(unix)]
        let ours = {
            use std::os::unix::fs::MetadataExt as _;
            meta.uid() == uid
        };
        #[cfg(not(unix))]
        let ours = true;
        let old = meta.modified().ok().and_then(|m| m.elapsed().ok()).is_some_and(|age| age > older_than);
        if meta.is_dir() && ours && old && std::fs::remove_dir_all(entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// `<data_dir>/repos`, created private (0700) if missing.
fn prepare_repos_dir(data_dir: &Path) -> Result<PathBuf, JobError> {
    let repos = data_dir.join("repos");
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(&repos).map_err(|_| JobError::retryable("cannot create the data directory"))?;
    Ok(repos)
}

/// Entries of `<repos>` named `<uuid>.git` (anything else is left alone).
fn list_mirrors(repos: &Path) -> std::io::Result<Vec<(Uuid, PathBuf)>> {
    let entries = match std::fs::read_dir(repos) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(id) = name
            .to_str()
            .and_then(|n| n.strip_suffix(".git").or_else(|| n.strip_suffix(".lock")))
            .and_then(|n| Uuid::parse_str(n).ok())
        else {
            continue;
        };
        out.push((id, entry.path()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_errors_are_bounded_and_printable() {
        let e = JobError::retryable(format!("git fetch failed: {}\n{}", "x".repeat(600), "\u{1b}"));
        assert_eq!(e.message.chars().count(), MAX_ERROR_LEN);
        assert!(!e.message.chars().any(char::is_control));
        assert!(e.retryable && !JobError::permanent("x").retryable);
    }

    #[test]
    fn worker_ids_are_safe() {
        let id = default_worker_id();
        assert!(id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)), "{id}");
    }

    #[test]
    fn stale_job_dirs_are_swept() {
        let tmp = tempfile::TempDir::new().unwrap_or_else(|e| panic!("{e}"));
        std::fs::create_dir(tmp.path().join("st-job-old")).unwrap_or_else(|e| panic!("{e}"));
        std::fs::create_dir(tmp.path().join("other")).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(sweep_job_dirs(tmp.path(), Duration::from_secs(3600)), 0, "too recent");
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(sweep_job_dirs(tmp.path(), Duration::from_millis(1)), 1);
        assert!(tmp.path().join("other").exists());
    }

    #[test]
    fn mirror_lock_is_exclusive() {
        let d = tempfile::TempDir::new().unwrap_or_else(|e| panic!("{e}"));
        let path = d.path().join("x.lock");
        let held = lock_mirror(&path).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(lock_mirror(&path).map(|_| ()).err().map(|e| e.message).as_deref(), Some("mirror is busy"));
        drop(held);
        assert!(lock_mirror(&path).is_ok());
    }

    #[test]
    fn only_uuid_named_mirrors_are_listed() {
        let dir = tempfile::TempDir::new().unwrap_or_else(|e| panic!("{e}"));
        let id = Uuid::new_v4();
        std::fs::create_dir(dir.path().join(format!("{id}.git"))).unwrap_or_else(|e| panic!("{e}"));
        std::fs::create_dir(dir.path().join("notes")).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(dir.path().join("x.git"), "").unwrap_or_else(|e| panic!("{e}"));
        let found = list_mirrors(dir.path()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(found.iter().map(|(i, _)| *i).collect::<Vec<_>>(), vec![id]);
        assert!(list_mirrors(&dir.path().join("missing")).unwrap_or_else(|e| panic!("{e}")).is_empty());
    }
}
