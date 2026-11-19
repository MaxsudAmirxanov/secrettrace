-- Stage 4: authentication details.

-- Last accepted TOTP time step: a code can be used only once (RFC 6238 §5.2).
ALTER TABLE users ADD COLUMN totp_last_step bigint;

-- Idle timeout for sessions in addition to the absolute expiry.
ALTER TABLE sessions ADD COLUMN last_seen_at timestamptz NOT NULL DEFAULT now();

-- Token prefixes are shown in the UI and used for log correlation; keep them unique.
ALTER TABLE api_tokens ADD CONSTRAINT api_tokens_prefix_uniq UNIQUE (token_prefix);
ALTER TABLE api_tokens ADD CONSTRAINT api_tokens_name_len CHECK (char_length(name) BETWEEN 1 AND 100);

-- CSRF tokens are derived from the session token (SHA-256 with a domain tag) and
-- verified against the cookie on each request; nothing needs to be stored.
ALTER TABLE sessions DROP COLUMN csrf_hash;
