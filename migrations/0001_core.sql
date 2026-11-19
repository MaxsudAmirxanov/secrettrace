-- SecretTrace core schema (MVP).
-- Runs as the schema owner (ST_MIGRATION_DATABASE_URL). The runtime role `st_app`
-- is created by deploy/postgres/init and receives least-privilege grants below.
-- No column in this schema ever holds a plaintext secret value.

CREATE EXTENSION IF NOT EXISTS citext;

CREATE TYPE user_role     AS ENUM ('admin', 'operator', 'viewer');
CREATE TYPE secret_type   AS ENUM ('api_key', 'password', 'token', 'certificate', 'private_key',
                                   'ssh_key', 'db_connection_string', 'other');
CREATE TYPE secret_status AS ENUM ('active', 'expired', 'revoked', 'rotated');
CREATE TYPE source_type   AS ENUM ('git_repo', 'filesystem', 'docker_image', 'k8s', 'ci_log', 'app_log', 'wiki');
CREATE TYPE job_status    AS ENUM ('queued', 'running', 'succeeded', 'failed', 'cancelled');
CREATE TYPE alert_sev     AS ENUM ('low', 'medium', 'high', 'critical');
CREATE TYPE alert_status  AS ENUM ('open', 'acknowledged', 'resolved', 'false_positive');

-- ── users & access ────────────────────────────────────────────────────────
CREATE TABLE users (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username        citext UNIQUE NOT NULL CHECK (char_length(username) BETWEEN 1 AND 64),
    password_hash   text NOT NULL,                 -- argon2id PHC string
    role            user_role NOT NULL,
    totp_secret_enc bytea,                         -- AES-256-GCM, key outside the DB
    mfa_enabled     boolean NOT NULL DEFAULT false,
    is_active       boolean NOT NULL DEFAULT true,
    failed_logins   int NOT NULL DEFAULT 0,
    locked_until    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_login_at   timestamptz
);

CREATE TABLE sessions (
    token_hash  bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),  -- sha256(cookie)
    user_id     uuid NOT NULL REFERENCES users ON DELETE CASCADE,
    mfa_passed  boolean NOT NULL DEFAULT false,
    csrf_hash   bytea NOT NULL,
    ip          inet,
    user_agent  text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL
);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);
CREATE INDEX sessions_user_idx ON sessions (user_id);

CREATE TABLE api_tokens (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name         text NOT NULL,
    kind         text NOT NULL CHECK (kind IN ('agent', 'ci', 'automation')),
    token_hash   bytea UNIQUE NOT NULL CHECK (octet_length(token_hash) = 32),  -- shown once
    token_prefix text NOT NULL,
    scopes       text[] NOT NULL,
    cert_cn      text,                             -- bound mTLS client certificate CN
    created_by   uuid REFERENCES users ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz,
    revoked_at   timestamptz,
    last_used_at timestamptz
);

-- ── registry ─────────────────────────────────────────────────────────────
CREATE TABLE secrets (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name           text NOT NULL UNIQUE CHECK (char_length(name) BETWEEN 1 AND 200),
    type           secret_type NOT NULL,
    owner          text NOT NULL CHECK (char_length(owner) BETWEEN 1 AND 200),
    purpose        text CHECK (char_length(purpose) <= 2000),
    fingerprint    bytea NOT NULL CHECK (octet_length(fingerprint) = 32),
    pepper_version smallint NOT NULL CHECK (pepper_version > 0),
    hint_prefix    text CHECK (char_length(hint_prefix) <= 16),
    hint_suffix    text CHECK (char_length(hint_suffix) = 4),
    value_length   int CHECK (value_length > 0),
    expires_at     timestamptz,
    status         secret_status NOT NULL DEFAULT 'active',
    created_by     uuid REFERENCES users ON DELETE SET NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT secrets_fingerprint_uniq UNIQUE (pepper_version, fingerprint),
    CONSTRAINT secrets_hints_need_prefix CHECK (
        (value_length IS NULL AND hint_suffix IS NULL) OR hint_prefix IS NOT NULL),
    CONSTRAINT secrets_no_hints_for_low_entropy CHECK (
        type NOT IN ('password', 'db_connection_string') OR hint_prefix IS NULL)
);
CREATE INDEX secrets_status_expiry_idx ON secrets (status, expires_at);

CREATE TABLE secret_allow_rules (
    id           bigserial PRIMARY KEY,
    secret_id    uuid NOT NULL REFERENCES secrets ON DELETE CASCADE,
    source_type  source_type,                      -- NULL = any source type
    uri_pattern  text NOT NULL CHECK (char_length(uri_pattern) BETWEEN 1 AND 512),  -- glob
    path_pattern text CHECK (char_length(path_pattern) <= 512),
    environment  text CHECK (char_length(environment) <= 64),
    comment      text CHECK (char_length(comment) <= 500),
    CONSTRAINT allow_rules_uniq UNIQUE NULLS NOT DISTINCT
        (secret_id, source_type, uri_pattern, path_pattern, environment)
);

-- ── sources & scanning ───────────────────────────────────────────────────
CREATE TABLE sources (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name           text UNIQUE NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    type           source_type NOT NULL,
    uri            text NOT NULL CHECK (char_length(uri) <= 2048),
    config         jsonb NOT NULL DEFAULT '{}',
    credential_ref text,                           -- NAME of a secret file/env var, never a value
    schedule_cron  text,
    enabled        boolean NOT NULL DEFAULT true,
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_scan_at   timestamptz
);

CREATE TABLE scan_jobs (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id    uuid REFERENCES sources ON DELETE SET NULL,
    trigger      text NOT NULL CHECK (trigger IN ('schedule', 'manual', 'ci', 'agent')),
    status       job_status NOT NULL DEFAULT 'queued',
    requested_by uuid REFERENCES users ON DELETE SET NULL,
    attempts     int NOT NULL DEFAULT 0,
    locked_by    text,
    locked_at    timestamptz,
    stats        jsonb NOT NULL DEFAULT '{}',
    error        text,                             -- never contains file contents
    created_at   timestamptz NOT NULL DEFAULT now(),
    started_at   timestamptz,
    finished_at  timestamptz
);
CREATE INDEX scan_jobs_queue_idx ON scan_jobs (created_at) WHERE status = 'queued';

CREATE TABLE locations (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id        uuid NOT NULL REFERENCES secrets ON DELETE CASCADE,
    source_id        uuid REFERENCES sources ON DELETE SET NULL,
    source_type      source_type NOT NULL,
    uri              text NOT NULL CHECK (char_length(uri) <= 2048),
    locator          jsonb NOT NULL,               -- {path,line,column,commit,blob,ref,encoding}
    locator_key      bytea NOT NULL CHECK (octet_length(locator_key) = 32),
    environment      text,
    in_current_state boolean NOT NULL,
    is_allowed       boolean NOT NULL,
    allow_rule_id    bigint REFERENCES secret_allow_rules ON DELETE SET NULL,
    first_seen       timestamptz NOT NULL DEFAULT now(),
    last_seen        timestamptz NOT NULL DEFAULT now(),
    last_job_id      uuid REFERENCES scan_jobs ON DELETE SET NULL,
    CONSTRAINT locations_uniq UNIQUE (secret_id, locator_key)
);
CREATE INDEX locations_secret_allowed_idx ON locations (secret_id, is_allowed);
CREATE INDEX locations_source_idx ON locations (source_id);

-- ── alerts ───────────────────────────────────────────────────────────────
CREATE TABLE alerts (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    rule            text NOT NULL,
    severity        alert_sev NOT NULL,
    status          alert_status NOT NULL DEFAULT 'open',
    secret_id       uuid REFERENCES secrets ON DELETE CASCADE,
    location_id     uuid REFERENCES locations ON DELETE SET NULL,
    dedup_key       text NOT NULL,
    context         jsonb NOT NULL DEFAULT '{}',   -- masked data only
    occurrences     int NOT NULL DEFAULT 1,
    acknowledged_by uuid REFERENCES users ON DELETE SET NULL,
    note            text CHECK (char_length(note) <= 2000),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    resolved_at     timestamptz
);
CREATE UNIQUE INDEX alerts_open_dedup_idx ON alerts (dedup_key) WHERE status IN ('open', 'acknowledged');
CREATE INDEX alerts_list_idx ON alerts (status, severity, created_at DESC);

CREATE TABLE notification_channels (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    type           text NOT NULL CHECK (type IN ('telegram', 'webhook', 'email')),
    name           text UNIQUE NOT NULL,
    config         jsonb NOT NULL,                 -- chat_id / url; never tokens
    credential_ref text,
    min_severity   alert_sev NOT NULL DEFAULT 'medium',
    enabled        boolean NOT NULL DEFAULT true
);

CREATE TABLE alert_deliveries (                    -- transactional outbox
    id              bigserial PRIMARY KEY,
    alert_id        uuid NOT NULL REFERENCES alerts ON DELETE CASCADE,
    channel_id      uuid NOT NULL REFERENCES notification_channels ON DELETE CASCADE,
    status          text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed')),
    attempts        int NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error      text,
    sent_at         timestamptz,
    CONSTRAINT alert_deliveries_uniq UNIQUE (alert_id, channel_id)
);
CREATE INDEX alert_deliveries_due_idx ON alert_deliveries (next_attempt_at) WHERE status = 'pending';

-- ── audit log (append-only, hash chain maintained by the application) ────
CREATE TABLE audit_log (
    id          bigserial PRIMARY KEY,
    ts          timestamptz NOT NULL,
    actor_type  text NOT NULL CHECK (actor_type IN ('user', 'token', 'system')),
    actor_id    text NOT NULL,
    action      text NOT NULL CHECK (char_length(action) BETWEEN 1 AND 100),
    target_type text,
    target_id   text,
    ip          inet,
    request_id  text,
    details     jsonb NOT NULL DEFAULT '{}',
    prev_hash   bytea CHECK (octet_length(prev_hash) = 32),
    hash        bytea NOT NULL CHECK (octet_length(hash) = 32)
);

-- ── least-privilege grants for the runtime role ─────────────────────────
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'st_app') THEN
        EXECUTE format('GRANT CONNECT ON DATABASE %I TO st_app', current_database());
        GRANT USAGE ON SCHEMA public TO st_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO st_app;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO st_app;
        REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM st_app;
        REVOKE ALL ON _sqlx_migrations FROM st_app;
    ELSE
        RAISE WARNING 'role st_app does not exist; runtime grants skipped';
    END IF;
END
$$;
