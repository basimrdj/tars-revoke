PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

INSERT OR IGNORE INTO schema_meta(key, value) VALUES ('schema_version', '1');

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    state TEXT NOT NULL,
    root_path TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    CHECK (state IN ('DECLARED','RUNNING','PAUSED','COMPLETED','FAILED','CANCELLED'))
) STRICT;

CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    worktree_path TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (run_id, name),
    CHECK (state IN ('DECLARED','RUNNING','PAUSED','COMPLETED','FAILED','CANCELLED'))
) STRICT;

CREATE TABLE IF NOT EXISTS agent_sessions (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    agent_id TEXT NOT NULL REFERENCES agents(id),
    provider TEXT NOT NULL,
    external_session_id TEXT,
    state TEXT NOT NULL,
    started_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    ended_at TEXT,
    process_id INTEGER,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    CHECK (state IN ('DECLARED','RUNNING','PAUSED','COMPLETED','FAILED','CANCELLED'))
) STRICT;

CREATE TABLE IF NOT EXISTS evidence_sources (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    name TEXT NOT NULL,
    uri TEXT NOT NULL,
    issuer TEXT NOT NULL,
    public_key TEXT,
    signature_algorithm TEXT,
    pinned_identity TEXT NOT NULL,
    created_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (run_id, uri)
) STRICT;

CREATE TABLE IF NOT EXISTS artifacts (
    digest TEXT PRIMARY KEY,
    size INTEGER NOT NULL CHECK (size >= 0),
    media_type TEXT NOT NULL,
    relative_path TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
) STRICT;

CREATE TABLE IF NOT EXISTS evidence_records (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    source_id TEXT NOT NULL REFERENCES evidence_sources(id),
    source_uri TEXT NOT NULL,
    source_version INTEGER NOT NULL CHECK (source_version >= 0),
    observed_at TEXT NOT NULL,
    valid_at TEXT NOT NULL,
    digest TEXT NOT NULL,
    signature_status TEXT NOT NULL,
    verification_status TEXT NOT NULL,
    artifact_digest TEXT REFERENCES artifacts(digest),
    normalized_premises_json TEXT NOT NULL DEFAULT '[]',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (source_id, source_version),
    UNIQUE (source_id, digest),
    CHECK (signature_status IN ('MISSING','VALID','INVALID')),
    CHECK (verification_status IN ('PENDING','VERIFIED','REJECTED'))
) STRICT;

CREATE TABLE IF NOT EXISTS premises (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    scope TEXT NOT NULL,
    subject TEXT NOT NULL,
    relation TEXT NOT NULL,
    value_json TEXT NOT NULL,
    value_digest TEXT NOT NULL,
    semantics TEXT NOT NULL,
    state TEXT NOT NULL,
    valid_at TEXT NOT NULL,
    invalid_at TEXT,
    invalidated_by_evidence_id TEXT REFERENCES evidence_records(id),
    replaces_premise_id TEXT REFERENCES premises(id),
    created_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    CHECK (semantics IN ('SINGLE','SET','TEMPORAL')),
    CHECK (state IN ('PROPOSED','ACTIVE','DISPUTED','INVALIDATED','SUPERSEDED')),
    CHECK ((state = 'INVALIDATED' AND invalid_at IS NOT NULL) OR state != 'INVALIDATED')
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS uq_active_single_premise
ON premises(run_id, scope, subject, relation)
WHERE semantics = 'SINGLE' AND state = 'ACTIVE';

CREATE UNIQUE INDEX IF NOT EXISTS uq_active_set_premise
ON premises(run_id, scope, subject, relation, value_digest)
WHERE semantics = 'SET' AND state = 'ACTIVE';

CREATE INDEX IF NOT EXISTS idx_premises_lookup
ON premises(run_id, scope, subject, relation, state, valid_at);

CREATE TABLE IF NOT EXISTS premise_evidence (
    premise_id TEXT NOT NULL REFERENCES premises(id),
    evidence_id TEXT NOT NULL REFERENCES evidence_records(id),
    role TEXT NOT NULL,
    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    created_at TEXT NOT NULL,
    PRIMARY KEY (premise_id, evidence_id, role),
    CHECK (role IN ('SUPPORTS','CONTRADICTS','INVALIDATES'))
) STRICT;

CREATE TABLE IF NOT EXISTS graph_nodes (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    kind TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    created_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (run_id, kind, entity_id),
    CHECK (kind IN ('EVIDENCE','PREMISE','WARRANT','ACTION','EFFECT','EXPERIMENT','TEST','RECEIPT'))
) STRICT;

CREATE TABLE IF NOT EXISTS dependency_edges (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    source_node_id TEXT NOT NULL REFERENCES graph_nodes(id),
    target_node_id TEXT NOT NULL REFERENCES graph_nodes(id),
    edge_type TEXT NOT NULL,
    strength TEXT NOT NULL,
    scope TEXT NOT NULL,
    declared_by TEXT NOT NULL,
    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    created_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (run_id, source_node_id, target_node_id, edge_type, scope),
    CHECK (source_node_id != target_node_id),
    CHECK (edge_type IN ('REQUIRES','SUPPORTS','PRODUCED_BY','MATERIALIZES','REPLACES','VERIFIES')),
    CHECK (strength IN ('HARD','SOFT'))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_dependency_edges_out
ON dependency_edges(run_id, source_node_id, strength, edge_type, scope);

CREATE INDEX IF NOT EXISTS idx_dependency_edges_in
ON dependency_edges(run_id, target_node_id, strength, edge_type, scope);

CREATE TABLE IF NOT EXISTS warrants (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    agent_id TEXT REFERENCES agents(id),
    scope TEXT NOT NULL,
    authorized_targets_json TEXT NOT NULL,
    state TEXT NOT NULL,
    risk TEXT NOT NULL,
    revision_epoch INTEGER NOT NULL DEFAULT 0 CHECK (revision_epoch >= 0),
    artifact_hashes_json TEXT NOT NULL DEFAULT '{}',
    required_tests_json TEXT NOT NULL DEFAULT '[]',
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    revoke_cause TEXT,
    replaces_warrant_id TEXT REFERENCES warrants(id),
    metadata_json TEXT NOT NULL DEFAULT '{}',
    CHECK (state IN ('DECLARED','PREPARED','AUTHORIZED','REVOKE_PENDING','REVOKED','EXPIRED')),
    CHECK (risk IN ('LOW','MEDIUM','HIGH','CRITICAL'))
) STRICT;

CREATE TABLE IF NOT EXISTS warrant_premises (
    warrant_id TEXT NOT NULL REFERENCES warrants(id),
    premise_id TEXT NOT NULL REFERENCES premises(id),
    premise_digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (warrant_id, premise_id)
) STRICT;

CREATE TABLE IF NOT EXISTS action_intents (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    agent_id TEXT NOT NULL REFERENCES agents(id),
    warrant_id TEXT NOT NULL REFERENCES warrants(id),
    scope TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    premise_vector_json TEXT NOT NULL,
    artifact_vector_json TEXT NOT NULL DEFAULT '{}',
    risk TEXT NOT NULL,
    reversibility TEXT NOT NULL,
    state TEXT NOT NULL,
    not_before TEXT,
    lease_id TEXT,
    idempotency_key TEXT NOT NULL,
    replaces_action_id TEXT REFERENCES action_intents(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    dispatched_at TEXT,
    completed_at TEXT,
    failure_reason TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (run_id, idempotency_key),
    CHECK (action_type IN ('FILE_EDIT','LOCAL_COMMIT','COMMAND','DATABASE_MIGRATION','PUSH','EXTERNAL','EXPERIMENT','TEST','REPAIR')),
    CHECK (risk IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    CHECK (reversibility IN ('REVERSIBLE','IRREVERSIBLE','CONDITIONAL')),
    CHECK (state IN ('DECLARED','PREPARED','AUTHORIZED','DISPATCHING','EXECUTED','REVOKE_PENDING','REVOKED','ROLLED_BACK','QUARANTINED','CONTAINMENT_REQUIRED','FAILED'))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_actions_run_state ON action_intents(run_id, state, agent_id);
CREATE INDEX IF NOT EXISTS idx_actions_warrant ON action_intents(warrant_id, state);

CREATE TABLE IF NOT EXISTS effects (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    action_id TEXT NOT NULL REFERENCES action_intents(id),
    scope TEXT NOT NULL,
    target TEXT NOT NULL,
    effect_type TEXT NOT NULL,
    before_hash TEXT,
    after_hash TEXT,
    forward_artifact_digest TEXT REFERENCES artifacts(digest),
    reverse_artifact_digest TEXT REFERENCES artifacts(digest),
    reversibility TEXT NOT NULL,
    compensation_handler TEXT,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    dispatched_at TEXT,
    compensated_at TEXT,
    compensation_attempts INTEGER NOT NULL DEFAULT 0 CHECK (compensation_attempts >= 0),
    idempotency_key TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (run_id, idempotency_key),
    CHECK (effect_type IN ('FILE_EDIT','LOCAL_COMMIT','COMMAND','DATABASE_MIGRATION','PUSH','EXTERNAL')),
    CHECK (reversibility IN ('REVERSIBLE','IRREVERSIBLE','CONDITIONAL')),
    CHECK (state IN ('DECLARED','PREPARED','AUTHORIZED','DISPATCHING','EXECUTED','REVOKE_PENDING','REVOKED','ROLLED_BACK','QUARANTINED','CONTAINMENT_REQUIRED','FAILED'))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_effects_action ON effects(action_id, state);
CREATE INDEX IF NOT EXISTS idx_effects_run_state ON effects(run_id, state);

CREATE TABLE IF NOT EXISTS dispatch_reconciliations (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    action_id TEXT NOT NULL UNIQUE REFERENCES action_intents(id),
    effect_id TEXT NOT NULL UNIQUE REFERENCES effects(id),
    adapter TEXT NOT NULL,
    outcome TEXT NOT NULL,
    expected_json TEXT NOT NULL,
    observed_json TEXT NOT NULL,
    reason TEXT NOT NULL,
    reconciled_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    CHECK (outcome IN ('APPLIED','NOT_APPLIED','CONFLICT','UNKNOWN'))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_dispatch_reconciliations_run
ON dispatch_reconciliations(run_id, reconciled_at, id);

CREATE TABLE IF NOT EXISTS execution_leases (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    action_id TEXT NOT NULL UNIQUE REFERENCES action_intents(id),
    effect_id TEXT NOT NULL UNIQUE REFERENCES effects(id),
    warrant_id TEXT NOT NULL REFERENCES warrants(id),
    epoch INTEGER NOT NULL CHECK (epoch >= 0),
    token_digest TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    revoked_at TEXT,
    idempotency_key TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (run_id, idempotency_key),
    CHECK (state IN ('ACTIVE','CONSUMED','REVOKED','EXPIRED'))
) STRICT;

CREATE TABLE IF NOT EXISTS revocation_cases (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    premise_id TEXT NOT NULL REFERENCES premises(id),
    trigger_evidence_id TEXT NOT NULL REFERENCES evidence_records(id),
    state TEXT NOT NULL,
    reason TEXT NOT NULL,
    opened_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    closed_at TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    CHECK (state IN ('OPEN','FROZEN','INVENTORIED','COMPENSATING','EXPERIMENTING','REPAIRING','VERIFYING','RESUMED','ATTESTED','CLOSED','ESCALATED'))
) STRICT;

CREATE TABLE IF NOT EXISTS revocation_members (
    case_id TEXT NOT NULL REFERENCES revocation_cases(id),
    node_id TEXT NOT NULL REFERENCES graph_nodes(id),
    member_kind TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    dependency_path_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (case_id, node_id),
    CHECK (member_kind IN ('WARRANT','ACTION','EFFECT','EXPERIMENT','TEST'))
) STRICT;

CREATE TABLE IF NOT EXISTS experiment_candidates (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    case_id TEXT NOT NULL REFERENCES revocation_cases(id),
    hypotheses_json TEXT NOT NULL,
    predictions_json TEXT NOT NULL,
    argv_json TEXT NOT NULL,
    fixture_refs_json TEXT NOT NULL DEFAULT '[]',
    touched_files_json TEXT NOT NULL DEFAULT '[]',
    risk TEXT NOT NULL,
    estimated_runtime_ms INTEGER NOT NULL CHECK (estimated_runtime_ms >= 0),
    command_count INTEGER NOT NULL CHECK (command_count > 0),
    state TEXT NOT NULL,
    rejection_reason TEXT,
    score_json TEXT,
    created_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    CHECK (risk IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    CHECK (state IN ('PROPOSED','ACCEPTED','REJECTED','SELECTED','RUNNING','PASSED','FAILED'))
) STRICT;

CREATE TABLE IF NOT EXISTS experiment_runs (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    case_id TEXT NOT NULL REFERENCES revocation_cases(id),
    candidate_id TEXT NOT NULL REFERENCES experiment_candidates(id),
    action_id TEXT REFERENCES action_intents(id),
    state TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    exit_code INTEGER,
    stdout_artifact_digest TEXT REFERENCES artifacts(digest),
    stderr_artifact_digest TEXT REFERENCES artifacts(digest),
    environment_digest TEXT NOT NULL,
    observed_outcome_json TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    CHECK (state IN ('PROPOSED','ACCEPTED','REJECTED','SELECTED','RUNNING','PASSED','FAILED'))
) STRICT;

CREATE TABLE IF NOT EXISTS test_runs (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    case_id TEXT REFERENCES revocation_cases(id),
    action_id TEXT REFERENCES action_intents(id),
    kind TEXT NOT NULL,
    argv_json TEXT NOT NULL,
    state TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    exit_code INTEGER,
    stdout_artifact_digest TEXT REFERENCES artifacts(digest),
    stderr_artifact_digest TEXT REFERENCES artifacts(digest),
    environment_digest TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    CHECK (kind IN ('TARGETED','FULL','PREFLIGHT','REGRESSION')),
    CHECK (state IN ('PENDING','RUNNING','PASSED','FAILED','ERROR','CANCELLED'))
) STRICT;

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    kind TEXT NOT NULL,
    aggregate_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    UNIQUE (run_id, sequence)
) STRICT;

CREATE TABLE IF NOT EXISTS outbox (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    event_id TEXT NOT NULL REFERENCES events(id),
    topic TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    state TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at TEXT NOT NULL,
    locked_at TEXT,
    published_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (event_id, topic),
    CHECK (state IN ('PENDING','CLAIMED','PUBLISHED','FAILED','DEAD'))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_outbox_delivery ON outbox(state, available_at, id);

CREATE TABLE IF NOT EXISTS receipts (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    case_id TEXT REFERENCES revocation_cases(id),
    state TEXT NOT NULL,
    artifact_digest TEXT REFERENCES artifacts(digest),
    canonical_digest TEXT NOT NULL,
    event_head_digest TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    verified_at TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (run_id, case_id, canonical_digest),
    CHECK (state IN ('DRAFT','FINAL','VERIFIED','INVALID'))
) STRICT;

CREATE TRIGGER IF NOT EXISTS trg_events_no_update
BEFORE UPDATE ON events BEGIN
    SELECT RAISE(ABORT, 'events are immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_events_no_delete
BEFORE DELETE ON events BEGIN
    SELECT RAISE(ABORT, 'events are immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_invalidated_premise_terminal
BEFORE UPDATE OF state ON premises
WHEN OLD.state IN ('INVALIDATED','SUPERSEDED') AND NEW.state != OLD.state
BEGIN
    SELECT RAISE(ABORT, 'terminal premise revision cannot transition');
END;

CREATE TRIGGER IF NOT EXISTS trg_revoked_action_terminal
BEFORE UPDATE OF state ON action_intents
WHEN OLD.state IN ('REVOKED','ROLLED_BACK','QUARANTINED','CONTAINMENT_REQUIRED')
     AND NEW.state NOT IN ('REVOKED','ROLLED_BACK','QUARANTINED','CONTAINMENT_REQUIRED')
BEGIN
    SELECT RAISE(ABORT, 'revoked action lineage is terminal');
END;
