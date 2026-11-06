-- 002_source_events.sql
-- Task 6: canonical source event store + ingestion infrastructure.
-- Tenant-isolated, immutable source events with append-only trigger.
-- Rebuildable projections and downstream business state are DEFERRED to later
-- tasks (access facts, findings, investigations, reviews, control mappings).

BEGIN;

-- ---------------------------------------------------------------------------
-- source_events — immutable canonical evidence (one row per ingested event).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS source_events (
    id                      UUID PRIMARY KEY,
    tenant_id               UUID NOT NULL,
    source                  TEXT NOT NULL,
    source_event_id         TEXT,
    idempotency_key         TEXT NOT NULL,
    source_schema_version   TEXT,
    canonical_schema_version TEXT NOT NULL,
    event_type              TEXT NOT NULL,
    event_category          TEXT NOT NULL
        CHECK (event_category IN ('auth', 'data', 'config', 'access', 'identity')),
    event_time              TIMESTAMPTZ NOT NULL,
    observed_at             TIMESTAMPTZ NOT NULL,
    ingested_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id                TEXT,
    principal_id            TEXT,
    session_id              TEXT,
    action                  TEXT NOT NULL,
    resource_type           TEXT,
    resource_id             TEXT,
    outcome                 TEXT,
    permission_context      JSONB NOT NULL DEFAULT '{}'::jsonb,
    payload_hash            TEXT NOT NULL,
    raw_evidence_reference  TEXT,
    correlation_metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT uq_source_events_tenant_identity
        UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS ix_source_events_tenant_time
    ON source_events (tenant_id, event_time);
CREATE INDEX IF NOT EXISTS ix_source_events_tenant_source
    ON source_events (tenant_id, source);

-- Append-only trigger (immutable evidence).
CREATE OR REPLACE FUNCTION source_events_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION
        'source_events is append-only: % not permitted (event %)',
        TG_OP, COALESCE(OLD.id::text, 'unknown');
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_source_events_append_only ON source_events;
CREATE TRIGGER trg_source_events_append_only
    BEFORE UPDATE OR DELETE ON source_events
    FOR EACH ROW EXECUTE FUNCTION source_events_append_only();

-- ---------------------------------------------------------------------------
-- source_checkpoints — mutable operational ingestion progress (per tenant/source).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS source_checkpoints (
    tenant_id       UUID NOT NULL,
    source          TEXT NOT NULL,
    checkpoint_token TEXT NOT NULL,
    last_event_time TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, source)
);

-- ---------------------------------------------------------------------------
-- Tenant isolation on existing inbox/outbox (best-effort ALTER).
-- ---------------------------------------------------------------------------
ALTER TABLE event_inbox ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE outbox ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- Tenant-scoped uniqueness on inbox (drop old global constraint is not safe;
-- add a new partial index instead).
CREATE INDEX IF NOT EXISTS ix_inbox_tenant_source_event
    ON event_inbox (tenant_id, source_system, external_event_id);

COMMIT;
