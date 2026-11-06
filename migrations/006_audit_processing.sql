-- 006_audit_processing.sql (Phase 7): findings severity aligns with domain
-- Severity (P1..P4), plus a processing-records table for durable, tenant-scoped
-- idempotency of the detection consumer.

BEGIN;

-- Align findings.severity CHECK with the domain Severity enum (P1..P4).
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_severity_check;
ALTER TABLE findings
    ADD CONSTRAINT findings_severity_check
    CHECK (severity IN ('P1', 'P2', 'P3', 'P4'));

-- Durable processing record for the detection consumer. Unique on
-- (tenant, source, event, processing_version) so redelivery / concurrent
-- delivery cannot produce duplicate findings.
CREATE TABLE IF NOT EXISTS processing_records (
    id                  UUID PRIMARY KEY,
    tenant_id           UUID NOT NULL,
    source              TEXT NOT NULL,
    event_id            UUID NOT NULL,
    processing_version  TEXT NOT NULL,
    status              TEXT NOT NULL
        CHECK (status IN ('PROCESSING', 'COMPLETED', 'FAILED')),
    started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at        TIMESTAMPTZ,
    finding_ids         UUID[] NOT NULL DEFAULT '{}',
    last_error          TEXT,
    CONSTRAINT uq_processing_record UNIQUE (tenant_id, source, event_id, processing_version)
);

CREATE INDEX IF NOT EXISTS ix_processing_records_tenant_event
    ON processing_records (tenant_id, event_id);

COMMIT;