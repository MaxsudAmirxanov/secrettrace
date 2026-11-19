-- Stage 8: ingest of scan results from agents and CI.

-- A scan belongs to the API token that started it; other tokens cannot touch it.
ALTER TABLE scan_jobs
    ADD COLUMN api_token_id uuid REFERENCES api_tokens ON DELETE SET NULL,
    ADD COLUMN full_scan    boolean NOT NULL DEFAULT false,
    ADD COLUMN environment  text CHECK (char_length(environment) BETWEEN 1 AND 64);

-- Sources reported by clients are found (or auto-created) by type and URI.
CREATE UNIQUE INDEX sources_type_uri_uniq ON sources (type, uri);

ALTER TABLE locations
    ADD CONSTRAINT locations_environment_len CHECK (char_length(environment) BETWEEN 1 AND 64);

-- Completing a full scan clears `in_current_state` of locations the scan did not see.
CREATE INDEX locations_source_current_idx ON locations (source_id) WHERE in_current_state;
