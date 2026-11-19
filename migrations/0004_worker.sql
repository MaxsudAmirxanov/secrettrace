-- Stage 9: server-side scans (worker queue, scheduler, credentials by reference).

-- Sources managed through the API. `type` and `uri` are immutable once created.
ALTER TABLE sources
    -- Environment of the locations a worker scan reports (allow rules may match on it).
    ADD COLUMN environment  text CHECK (char_length(environment) BETWEEN 1 AND 64),
    -- When the scheduler next enqueues a scan; NULL without a schedule or when disabled.
    ADD COLUMN next_scan_at timestamptz,
    -- Worker-owned incremental state, e.g. {"v":1,"tips":["<commit>",…]}. Never contents.
    ADD COLUMN scan_state   jsonb NOT NULL DEFAULT '{}',
    ADD CONSTRAINT sources_credential_ref_format CHECK (credential_ref ~ '^[A-Za-z0-9_-]{1,64}$'),
    ADD CONSTRAINT sources_schedule_len CHECK (char_length(schedule_cron) BETWEEN 1 AND 100);

CREATE INDEX sources_due_idx ON sources (next_scan_at) WHERE enabled AND next_scan_at IS NOT NULL;

-- Worker jobs (trigger 'manual' or 'schedule') wait in the queue until `run_after`
-- (retry backoff). `locked_by` / `locked_at` are the worker's lease: it refreshes
-- `locked_at` while it runs, a lease older than the timeout is reclaimed.
ALTER TABLE scan_jobs
    ADD COLUMN run_after timestamptz NOT NULL DEFAULT now();

DROP INDEX scan_jobs_queue_idx;
CREATE INDEX scan_jobs_queue_idx ON scan_jobs (run_after, created_at)
    WHERE status = 'queued' AND trigger IN ('manual', 'schedule');
CREATE INDEX scan_jobs_running_idx ON scan_jobs (locked_at) WHERE status = 'running';
CREATE INDEX scan_jobs_source_idx ON scan_jobs (source_id, created_at DESC);

-- At most one queued or running worker job per source: no pile-up behind a slow scan,
-- and two workers never fetch into the same mirror.
CREATE UNIQUE INDEX scan_jobs_worker_active_uniq ON scan_jobs (source_id)
    WHERE status IN ('queued', 'running') AND trigger IN ('manual', 'schedule');
