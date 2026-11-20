-- Stage 13: TLS edge. An API token can be bound to the client certificate it must arrive
-- with (CN verified by the mTLS proxy), to the sources it may report (type and a URI glob)
-- and to the environment its scans are recorded under. Unset means unrestricted.
ALTER TABLE api_tokens
    ADD COLUMN source_type        source_type,
    ADD COLUMN source_uri_pattern text,
    ADD COLUMN environment        text,
    ADD CONSTRAINT api_tokens_cert_cn_format CHECK (cert_cn ~ '^[A-Za-z0-9._-]{1,64}$'),
    ADD CONSTRAINT api_tokens_uri_pattern_len CHECK (char_length(source_uri_pattern) BETWEEN 1 AND 2048),
    ADD CONSTRAINT api_tokens_environment_format CHECK (environment ~ '^[A-Za-z0-9._-]{1,64}$');
