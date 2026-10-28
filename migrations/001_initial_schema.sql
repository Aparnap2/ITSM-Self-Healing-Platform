-- 001_initial_schema.sql
-- Phase 3 durable schema per PRD §5.1 (entities), §2.3 (event reliability rules),
-- and ADR-0002 (inbox/outbox durable publishing).
-- Idempotent: safe to re-apply (IF NOT EXISTS / DROP-then-CREATE for triggers).
-- All timestamps are timestamptz (UTC normalized at the boundary).

BEGIN;

-- ---------------------------------------------------------------------------
-- incidents — canonical incident model (PRD §5.1 Incident)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    id                  UUID PRIMARY KEY,
    source_system       TEXT NOT NULL,
    source_incident_id  TEXT NOT NULL,
    external_event_id   TEXT,
    title               TEXT NOT NULL,
    description         TEXT NOT NULL,
    service_name        TEXT NOT NULL,
    severity            TEXT NOT NULL
        CHECK (severity IN ('P1', 'P2', 'P3', 'P4')),
    status              TEXT NOT NULL
        CHECK (status IN ('NEW', 'TRIAGED', 'IN_PROGRESS', 'WAITING_APPROVAL',
                          'RESOLVED', 'ESCALATED', 'REJECTED')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    correlation_id      UUID NOT NULL,
    current_workflow_id UUID,
    resolution_summary  TEXT,
    audit_reference     TEXT,
    CONSTRAINT uq_incidents_source UNIQUE (source_system, source_incident_id)
);

-- External event deduplication (PRD §5.1): unique per source when present.
CREATE UNIQUE INDEX IF NOT EXISTS uq_incidents_external_event
    ON incidents (source_system, external_event_id)
    WHERE external_event_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_incidents_status ON incidents (status);
CREATE INDEX IF NOT EXISTS ix_incidents_correlation ON incidents (correlation_id);

-- ---------------------------------------------------------------------------
-- event_inbox — dedup on (source_system, external_event_id) (ADR-0002)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS event_inbox (
    id                UUID PRIMARY KEY,
    source_system     TEXT NOT NULL,
    external_event_id TEXT NOT NULL,
    payload_hash      TEXT NOT NULL,
    received_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    status            TEXT NOT NULL
        CHECK (status IN ('RECEIVED', 'PROCESSING', 'PROCESSED',
                          'REJECTED', 'DEAD_LETTERED')),
    attempt_count     INT NOT NULL DEFAULT 0,
    last_error        TEXT,
    CONSTRAINT uq_inbox_source_event UNIQUE (source_system, external_event_id)
);

-- Queue-polling index for unprocessed inbox rows.
CREATE INDEX IF NOT EXISTS ix_inbox_unprocessed
    ON event_inbox (received_at)
    WHERE status IN ('RECEIVED', 'PROCESSING');

-- ---------------------------------------------------------------------------
-- outbox — transactional outbox (ADR-0002)
-- status: pending (retryable, includes leased in-flight rows) /
--         published (broker acked) / failed (terminal, needs reconciliation)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS outbox (
    id              UUID PRIMARY KEY,
    event_type      TEXT NOT NULL,
    aggregate_id    UUID NOT NULL,
    payload         JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at    TIMESTAMPTZ,
    attempts        INT NOT NULL DEFAULT 0,
    last_error      TEXT,
    status          TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'published', 'failed')),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Queue-polling index: partial, only pending rows, oldest first.
CREATE INDEX IF NOT EXISTS ix_outbox_pending
    ON outbox (created_at, id)
    WHERE status = 'pending';

-- ---------------------------------------------------------------------------
-- action_intents — intent persisted BEFORE any side effect (FR-07, invariant
-- "no side effect before durable action intent"). idempotency_key UNIQUE.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS action_intents (
    id                 UUID PRIMARY KEY,
    incident_id        UUID NOT NULL REFERENCES incidents(id),
    workflow_id        UUID,
    action_type        TEXT NOT NULL,
    resource_id        TEXT NOT NULL,
    idempotency_key    TEXT NOT NULL UNIQUE,
    proposal_hash      TEXT NOT NULL,
    status             TEXT NOT NULL
        CHECK (status IN ('INTENT_RECORDED', 'RUNNING', 'SUCCEEDED', 'FAILED',
                          'OUTCOME_UNKNOWN', 'RECONCILED', 'CANCELLED')),
    attempt_number     INT NOT NULL DEFAULT 1,
    intent_recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at         TIMESTAMPTZ,
    finished_at        TIMESTAMPTZ,
    adapter_name       TEXT NOT NULL,
    result_code        TEXT,
    result_summary     TEXT,
    result_evidence_id UUID
);

CREATE INDEX IF NOT EXISTS ix_action_intents_incident
    ON action_intents (incident_id);

-- ---------------------------------------------------------------------------
-- approvals — proposal-hash-bound, expiring, single-use (FR-06)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS approvals (
    id                UUID PRIMARY KEY,
    incident_id       UUID NOT NULL REFERENCES incidents(id),
    workflow_id       UUID,
    proposal_hash     TEXT NOT NULL,
    action_type       TEXT NOT NULL,
    resource_id       TEXT NOT NULL,
    parameters_hash   TEXT NOT NULL,
    status            TEXT NOT NULL
        CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED',
                          'INVALIDATED')),
    requested_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ NOT NULL,
    decided_at        TIMESTAMPTZ,
    approver_id       TEXT,
    decision_reason   TEXT,
    replay_nonce_hash TEXT NOT NULL
);

-- Expiry sweep index for pending approvals.
CREATE INDEX IF NOT EXISTS ix_approvals_pending
    ON approvals (expires_at)
    WHERE status = 'PENDING';

-- ---------------------------------------------------------------------------
-- audit_events — APPEND-ONLY. UPDATE and DELETE raise an exception via
-- trigger (fail-closed durable audit capacity, FR-10, safety invariant
-- "terminal outcomes must have the required audit records").
-- Note: TRUNCATE is not blocked by row triggers; do not grant TRUNCATE to
-- the application role.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_events (
    id               UUID PRIMARY KEY,
    occurred_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    correlation_id   UUID NOT NULL,
    incident_id      UUID,
    workflow_id      UUID,
    actor_type       TEXT NOT NULL
        CHECK (actor_type IN ('SYSTEM', 'WORKER', 'POLICY', 'APPROVER',
                              'ADAPTER', 'VERIFIER')),
    actor_id         TEXT NOT NULL,
    event_type       TEXT NOT NULL,
    entity_type      TEXT,
    entity_id        UUID,
    payload_redacted JSONB NOT NULL DEFAULT '{}'::jsonb,
    previous_hash    TEXT,
    event_hash       TEXT
);

CREATE INDEX IF NOT EXISTS ix_audit_correlation ON audit_events (correlation_id);
CREATE INDEX IF NOT EXISTS ix_audit_incident ON audit_events (incident_id);

CREATE OR REPLACE FUNCTION audit_events_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION
        'audit_events is append-only: % not permitted (event %)',
        TG_OP, COALESCE(OLD.id::text, 'unknown');
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_events_append_only ON audit_events;
CREATE TRIGGER trg_audit_events_append_only
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_append_only();

-- ---------------------------------------------------------------------------
-- workflow_state — short-lived orchestration snapshot (PRD §3.3)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS workflow_state (
    id               UUID PRIMARY KEY,
    incident_id      UUID NOT NULL REFERENCES incidents(id),
    workflow_version TEXT NOT NULL,
    status           TEXT NOT NULL
        CHECK (status IN ('PENDING', 'RUNNING', 'WAITING_APPROVAL',
                          'SUCCEEDED', 'FAILED', 'ESCALATED', 'CANCELLED')),
    current_node     TEXT NOT NULL,
    checkpoint_ref   TEXT,
    attempt_count    INT NOT NULL DEFAULT 0,
    started_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at      TIMESTAMPTZ,
    correlation_id   UUID NOT NULL,
    last_error_code  TEXT
);

CREATE INDEX IF NOT EXISTS ix_workflow_state_incident
    ON workflow_state (incident_id);
CREATE INDEX IF NOT EXISTS ix_workflow_state_active
    ON workflow_state (updated_at)
    WHERE status IN ('PENDING', 'RUNNING', 'WAITING_APPROVAL');

COMMIT;
