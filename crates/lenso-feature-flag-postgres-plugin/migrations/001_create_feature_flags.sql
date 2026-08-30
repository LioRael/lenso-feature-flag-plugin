CREATE TABLE feature_flags (
    organization_id text NOT NULL,
    flag_key text NOT NULL,
    name text NOT NULL,
    description text,
    value_type text NOT NULL,
    archived boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    archived_at timestamptz,
    row_seq bigserial NOT NULL UNIQUE,
    PRIMARY KEY (organization_id, flag_key),
    CHECK (value_type IN ('boolean', 'string', 'integer', 'double', 'json'))
);

CREATE INDEX feature_flags_list_idx ON feature_flags (organization_id, archived, row_seq);

CREATE TABLE feature_environments (
    organization_id text NOT NULL,
    environment_key text NOT NULL,
    name text NOT NULL,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, environment_key)
);

CREATE TABLE feature_rulesets (
    organization_id text NOT NULL,
    flag_key text NOT NULL,
    environment_key text NOT NULL,
    ruleset_revision bigint NOT NULL CHECK (ruleset_revision > 0),
    ruleset_json jsonb NOT NULL,
    published_by text NOT NULL,
    published_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, flag_key, environment_key, ruleset_revision),
    FOREIGN KEY (organization_id, flag_key) REFERENCES feature_flags (organization_id, flag_key),
    FOREIGN KEY (organization_id, environment_key) REFERENCES feature_environments (organization_id, environment_key)
);

CREATE INDEX feature_rulesets_latest_idx
    ON feature_rulesets (organization_id, flag_key, environment_key, ruleset_revision DESC);

CREATE TABLE feature_evaluation_receipts (
    receipt_id uuid PRIMARY KEY,
    caller_instance text NOT NULL,
    actor_subject text NOT NULL,
    operation text NOT NULL,
    evaluation_id text NOT NULL,
    organization_id text NOT NULL,
    flag_key text NOT NULL,
    environment_key text NOT NULL,
    variant_key text NOT NULL,
    reason text NOT NULL,
    ruleset_revision bigint NOT NULL CHECK (ruleset_revision > 0),
    context_hash text NOT NULL,
    evaluated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_seq bigserial NOT NULL UNIQUE,
    UNIQUE (caller_instance, actor_subject, operation, evaluation_id, flag_key),
    CHECK (reason IN ('target_match', 'percentage_rollout', 'fallthrough'))
);

CREATE INDEX feature_receipts_list_idx
    ON feature_evaluation_receipts (organization_id, row_seq);

CREATE TABLE feature_commands (
    caller_instance text NOT NULL,
    actor_subject text NOT NULL,
    operation text NOT NULL,
    idempotency_key text NOT NULL,
    request_hash bytea NOT NULL,
    response_json jsonb,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (caller_instance, actor_subject, operation, idempotency_key)
);
