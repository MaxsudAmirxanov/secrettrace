//! The job queue in Postgres: claim with `FOR UPDATE SKIP LOCKED`, a lease refreshed by
//! heartbeats, retries with backoff, the reaper and the scheduler.
//!
//! Every state change of a running job is conditional on `status = 'running' AND
//! locked_by = <this worker>`: a job cancelled through the API, reclaimed by the reaper
//! or whose source was deleted is never overwritten by a worker that lost it.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{PgConnection, PgPool, Row as _};
use uuid::Uuid;

use super::{JobError, ReapReport};
use crate::audit::{self, AuditEvent};
use crate::schedule::Schedule;

/// A job this worker holds the lease of.
#[derive(Debug, Clone)]
pub struct Claimed {
    pub id: Uuid,
    pub source_id: Option<Uuid>,
    /// Including this run.
    pub attempts: i32,
    /// Requested full history pass (`scan_jobs.full_scan`).
    pub full_scan: bool,
    /// `scan_jobs.locked_by` of this claim: `<worker_id>/<claim uuid>`. A stale run of the
    /// same worker (after a reclaim and a new claim) no longer matches it.
    pub lease: String,
}

/// The lease token of one claim.
#[must_use]
pub fn lease_token(worker_id: &str, claim: Uuid) -> String {
    format!("{worker_id}/{claim}")
}

/// Longest retry delay.
const MAX_BACKOFF: Duration = Duration::from_secs(6 * 3600);
/// Sources handled per scheduler round.
const SCHEDULE_BATCH: i64 = 100;

/// `base * 2^(attempts-1)`, capped.
#[must_use]
pub fn backoff(base: Duration, attempts: i32) -> Duration {
    let exp = u32::try_from(attempts.saturating_sub(1)).unwrap_or(0).min(20);
    base.saturating_mul(1u32 << exp).min(MAX_BACKOFF)
}

pub fn event(worker_id: &str, action: &str) -> AuditEvent {
    let mut e = AuditEvent::system(action);
    e.actor_id = format!("worker:{worker_id}");
    e
}

pub async fn claim(db: &PgPool, worker_id: &str) -> Result<Option<Claimed>, sqlx::Error> {
    let lease = lease_token(worker_id, Uuid::new_v4());
    let row = sqlx::query(
        "UPDATE scan_jobs SET status = 'running', locked_by = $1, locked_at = now(), started_at = now(),
                attempts = attempts + 1, error = NULL
         WHERE id = (SELECT id FROM scan_jobs
                     WHERE status = 'queued' AND trigger IN ('manual', 'schedule') AND run_after <= now()
                     ORDER BY run_after, created_at
                     FOR UPDATE SKIP LOCKED LIMIT 1)
         RETURNING id, source_id, attempts, full_scan",
    )
    .bind(&lease)
    .fetch_optional(db)
    .await?;
    row.map(|r| {
        Ok(Claimed {
            id: r.try_get("id")?,
            source_id: r.try_get("source_id")?,
            attempts: r.try_get("attempts")?,
            full_scan: r.try_get("full_scan")?,
            lease: lease.clone(),
        })
    })
    .transpose()
}

/// Refresh the lease; `false` once the job is no longer ours to run.
pub async fn heartbeat(db: &PgPool, lease: &str, job: Uuid) -> Result<bool, sqlx::Error> {
    let n =
        sqlx::query("UPDATE scan_jobs SET locked_at = now() WHERE id = $1 AND status = 'running' AND locked_by = $2")
            .bind(job)
            .bind(lease)
            .execute(db)
            .await?
            .rows_affected();
    Ok(n == 1)
}

/// Lock the job row inside a transaction and check it is still ours.
pub async fn lock_own(
    conn: &mut PgConnection,
    lease: &str,
    job: Uuid,
) -> Result<Option<(DateTime<Utc>, Option<String>)>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT started_at, environment FROM scan_jobs
         WHERE id = $1 AND status = 'running' AND locked_by = $2 FOR UPDATE",
    )
    .bind(job)
    .bind(lease)
    .fetch_optional(conn)
    .await?;
    row.map(|r| {
        Ok((r.try_get::<Option<DateTime<Utc>>, _>("started_at")?.unwrap_or_else(Utc::now), r.try_get("environment")?))
    })
    .transpose()
}

/// Outcome of a failed run as stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failed {
    Retrying,
    Final,
    /// The job was no longer ours.
    Lost,
}

pub async fn fail(
    db: &PgPool,
    worker_id: &str,
    job: &Claimed,
    err: &JobError,
    max_attempts: u32,
    base_backoff: Duration,
) -> anyhow::Result<Failed> {
    let retry = err.retryable && u32::try_from(job.attempts).unwrap_or(u32::MAX) < max_attempts;
    let delay = backoff(base_backoff, job.attempts).as_secs_f64();
    let mut tx = db.begin().await?;
    let row = sqlx::query(
        "UPDATE scan_jobs SET
             status = CASE WHEN $3 THEN 'queued'::job_status ELSE 'failed'::job_status END,
             run_after = CASE WHEN $3 THEN now() + make_interval(secs => $4) ELSE run_after END,
             finished_at = CASE WHEN $3 THEN NULL ELSE now() END,
             started_at = CASE WHEN $3 THEN NULL ELSE started_at END,
             locked_by = NULL, locked_at = NULL, error = $5
         WHERE id = $1 AND status = 'running' AND locked_by = $2
         RETURNING source_id",
    )
    .bind(job.id)
    .bind(&job.lease)
    .bind(retry)
    .bind(delay)
    .bind(&err.message)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else { return Ok(Failed::Lost) };
    let source_id: Option<Uuid> = row.try_get("source_id")?;
    let (action, details) = if retry {
        ("scan.retry", json!({ "source_id": source_id, "attempt": job.attempts, "retry_in_secs": delay.round() }))
    } else {
        ("scan.finish", json!({ "source_id": source_id, "status": "failed", "attempts": job.attempts }))
    };
    audit::record(&mut tx, &event(worker_id, action).target("scan_job", job.id.to_string()).details(details)).await?;
    tx.commit().await?;
    Ok(if retry { Failed::Retrying } else { Failed::Final })
}

/// Close a job as cancelled (source deleted or disabled before it ran).
pub async fn cancel(db: &PgPool, job: &Claimed, reason: &str) -> Result<bool, sqlx::Error> {
    let n = sqlx::query(
        "UPDATE scan_jobs SET status = 'cancelled', finished_at = now(), locked_by = NULL, locked_at = NULL, error = $3
         WHERE id = $1 AND status = 'running' AND locked_by = $2",
    )
    .bind(job.id)
    .bind(&job.lease)
    .bind(reason)
    .execute(db)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Shutdown: hand the job back without consuming the attempt.
pub async fn release(db: &PgPool, job: &Claimed) -> Result<bool, sqlx::Error> {
    let n = sqlx::query(
        "UPDATE scan_jobs SET status = 'queued', attempts = greatest(attempts - 1, 0), locked_by = NULL,
                locked_at = NULL, started_at = NULL, run_after = now()
         WHERE id = $1 AND status = 'running' AND locked_by = $2",
    )
    .bind(job.id)
    .bind(&job.lease)
    .execute(db)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Current status and error of a job (after this worker lost it).
pub async fn status_of(db: &PgPool, job: Uuid) -> Result<Option<(String, Option<String>)>, sqlx::Error> {
    let row = sqlx::query("SELECT status::text AS status, error FROM scan_jobs WHERE id = $1")
        .bind(job)
        .fetch_optional(db)
        .await?;
    row.map(|r| Ok((r.try_get("status")?, r.try_get("error")?))).transpose()
}

/// Reclaim expired worker leases; fail API scans left running past the ingest window.
pub async fn reap(
    db: &PgPool,
    worker_id: &str,
    lease_timeout: Duration,
    max_attempts: u32,
) -> anyhow::Result<ReapReport> {
    let mut tx = db.begin().await?;
    let rows = sqlx::query(
        "WITH expired AS (
             SELECT id FROM scan_jobs
             WHERE status = 'running' AND trigger IN ('manual', 'schedule')
               AND locked_at < now() - make_interval(secs => $1)
             FOR UPDATE SKIP LOCKED)
         UPDATE scan_jobs j SET
             status = CASE WHEN j.attempts >= $2 THEN 'failed'::job_status ELSE 'queued'::job_status END,
             finished_at = CASE WHEN j.attempts >= $2 THEN now() END,
             started_at = CASE WHEN j.attempts >= $2 THEN j.started_at END,
             run_after = now(), locked_by = NULL, locked_at = NULL, error = 'worker lease expired'
         FROM expired e WHERE j.id = e.id
         RETURNING j.status::text AS status",
    )
    .bind(lease_timeout.as_secs_f64())
    .bind(i32::try_from(max_attempts).unwrap_or(i32::MAX))
    .fetch_all(&mut *tx)
    .await?;
    let mut report = ReapReport { requeued: 0, failed: 0, api_scans_failed: 0 };
    for r in rows {
        if r.try_get::<String, _>("status")? == "failed" {
            report.failed += 1;
        } else {
            report.requeued += 1;
        }
    }
    report.api_scans_failed = sqlx::query(
        "UPDATE scan_jobs SET status = 'failed', finished_at = now(), error = 'abandoned: not completed within 24 h'
         WHERE status = 'running' AND trigger IN ('ci', 'agent')
           AND started_at < now() - make_interval(hours => $1)",
    )
    .bind(crate::ingest::JOB_MAX_AGE_HOURS)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if report != (ReapReport { requeued: 0, failed: 0, api_scans_failed: 0 }) {
        let details = json!({
            "requeued": report.requeued, "failed": report.failed, "api_scans_failed": report.api_scans_failed,
        });
        audit::record(&mut tx, &event(worker_id, "scan.reap").details(details)).await?;
    }
    tx.commit().await?;
    Ok(report)
}

/// Enqueue scans of due scheduled sources (one active job per source at most) and move
/// `next_scan_at` to the next firing after now: missed firings collapse into one.
pub async fn schedule_due(db: &PgPool, worker_id: &str) -> anyhow::Result<u64> {
    let mut tx = db.begin().await?;
    let due = sqlx::query(
        "SELECT id, schedule_cron, environment FROM sources
         WHERE enabled AND type = 'git_repo' AND next_scan_at <= now()
         ORDER BY next_scan_at FOR UPDATE SKIP LOCKED LIMIT $1",
    )
    .bind(SCHEDULE_BATCH)
    .fetch_all(&mut *tx)
    .await?;
    let mut created = 0;
    for row in due {
        let source_id: Uuid = row.try_get("id")?;
        let schedule = row.try_get::<Option<String>, _>("schedule_cron")?.and_then(|s| Schedule::parse(&s).ok());
        let Some(schedule) = schedule else {
            tracing::warn!(source_id = %source_id, "source has no valid schedule; not scheduling it");
            sqlx::query("UPDATE sources SET next_scan_at = NULL WHERE id = $1")
                .bind(source_id)
                .execute(&mut *tx)
                .await?;
            continue;
        };
        let environment: Option<String> = row.try_get("environment")?;
        let job: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO scan_jobs (source_id, trigger, status, environment)
             VALUES ($1, 'schedule', 'queued', $2) ON CONFLICT DO NOTHING RETURNING id",
        )
        .bind(source_id)
        .bind(&environment)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(job) = job {
            created += 1;
            let details = json!({ "source_id": source_id, "trigger": "schedule" });
            audit::record(
                &mut tx,
                &event(worker_id, "scan.enqueue").target("scan_job", job.to_string()).details(details),
            )
            .await?;
        }
        sqlx::query("UPDATE sources SET next_scan_at = $2 WHERE id = $1")
            .bind(source_id)
            .bind(schedule.next_after(Utc::now()))
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(created)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_tokens_are_unique_per_claim_and_fit_the_column() {
        let id = "a".repeat(64);
        let (a, b) = (lease_token(&id, Uuid::new_v4()), lease_token(&id, Uuid::new_v4()));
        assert_ne!(a, b);
        assert!(a.starts_with(&format!("{id}/")) && a.len() <= 128, "{a}");
        assert!(Uuid::parse_str(a.rsplit('/').next().unwrap_or_default()).is_ok());
    }

    #[test]
    fn backoff_doubles_and_is_capped() {
        let base = Duration::from_secs(60);
        assert_eq!(backoff(base, 1), Duration::from_secs(60));
        assert_eq!(backoff(base, 2), Duration::from_secs(120));
        assert_eq!(backoff(base, 3), Duration::from_secs(240));
        assert_eq!(backoff(base, 0), Duration::from_secs(60));
        assert_eq!(backoff(base, 40), MAX_BACKOFF);
        assert_eq!(backoff(Duration::MAX, 5), MAX_BACKOFF);
    }
}
