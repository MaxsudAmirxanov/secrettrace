-- Canary tokens (honeytokens): bait that nobody uses legitimately, so any use is a leak.
-- `url`: a unique link; `api_key`: a fake key next to an endpoint on the canary listener.
-- Only an HMAC of the token is stored (keyed with ST_CANARY_KEY): a database dump alone
-- does not tell an attacker which of the keys he found are canaries.
CREATE TYPE canary_kind AS ENUM ('url', 'api_key');

CREATE TABLE canaries (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text UNIQUE NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    kind        canary_kind NOT NULL,
    lookup      bytea UNIQUE NOT NULL CHECK (octet_length(lookup) = 32),
    -- Where the canary was planted ("alice's laptop ~/.aws/credentials"); free text.
    planted_at  text CHECK (char_length(planted_at) <= 500),
    memo        text CHECK (char_length(memo) <= 2000),
    -- api_key canaries are also registered secrets: a scan that finds one anywhere is a leak.
    secret_id   uuid REFERENCES secrets ON DELETE SET NULL,
    enabled     boolean NOT NULL DEFAULT true,
    hit_count   bigint NOT NULL DEFAULT 0,
    last_hit_at timestamptz,
    created_by  uuid REFERENCES users ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Requests that carried a canary. Stored rows are capped per canary (the counter is not):
-- the listener faces the internet and must not become a way to fill the database.
CREATE TABLE canary_hits (
    id         bigserial PRIMARY KEY,
    canary_id  uuid NOT NULL REFERENCES canaries ON DELETE CASCADE,
    at         timestamptz NOT NULL DEFAULT now(),
    ip         inet,
    method     text NOT NULL CHECK (char_length(method) BETWEEN 1 AND 16),
    host       text CHECK (char_length(host) <= 255),
    -- Request target with the token replaced by `{token}`, cut to 512 chars.
    path       text NOT NULL CHECK (char_length(path) <= 512),
    user_agent text CHECK (char_length(user_agent) <= 256),
    -- Where the token was found: path, query, bearer, basic, header.
    via        text NOT NULL CHECK (via IN ('path', 'query', 'bearer', 'basic', 'header'))
);
CREATE INDEX canary_hits_canary_idx ON canary_hits (canary_id, at DESC);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'st_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON canaries, canary_hits TO st_app;
        GRANT USAGE, SELECT ON SEQUENCE canary_hits_id_seq TO st_app;
    ELSE
        RAISE WARNING 'role st_app does not exist; runtime grants skipped';
    END IF;
END
$$;
