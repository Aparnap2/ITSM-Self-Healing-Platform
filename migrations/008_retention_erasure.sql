-- 008_retention_erasure.sql (security slice)
-- Explicit retention policy, legal hold and erasure bookkeeping.
--
-- Design rules:
--   * Append-only evidence (source_events) is NEVER updated or deleted here.
--     Erasure of the referenced raw payload is recorded as a tombstone so the
--     integrity hash stays verifiable while the payload is acknowledged gone.
--   * Derived, rebuildable projections (access_facts) may be deleted.
--   * Findings and reviewer decisions are retained as audit records; retention
--     may anonymize their free-text later, but this migration adds no cascade.
--   * Every erasure is tenant-scoped and requires a recorded request.

BEGIN;

CREATE TABLE IF NOT EXISTS retention_policies (
    id              UUID PRIMARY KEY,
    tenant_id       UUID,
    data_class      TEXT NOT NULL CHECK (data_class IN (
                        'RAW_EVIDENCE', 'CANONICAL_EVENT', 'DERIVED_PROJECTION',
                        'FINDING', 'INVESTIGATION', 'REVIEW_DECISION',
                        'OPERATIONAL_LOG')),
    retention_days  INTEGER NOT NULL CHECK (retention_days > 0),
    on_expiry       TEXT NOT NULL CHECK (on_expiry IN ('ANONYMIZE', 'DELETE_DERIVED', 'RETAIN')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One platform default per data class, and one override per tenant.
CREATE UNIQUE INDEX IF NOT EXISTS uq_retention_default
    ON retention_policies (data_class) WHERE tenant_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_retention_tenant
    ON retention_policies (tenant_id, data_class) WHERE tenant_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS legal_holds (
    id          UUID PRIMARY KEY,
    tenant_id   UUID NOT NULL,
    data_class  TEXT,
    reason      TEXT NOT NULL,
    placed_by   TEXT NOT NULL,
    placed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    released_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_legal_holds_tenant
    ON legal_holds (tenant_id, data_class);

CREATE TABLE IF NOT EXISTS erasure_requests (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    requested_by    TEXT NOT NULL,
    reason          TEXT NOT NULL,
    data_classes    TEXT[] NOT NULL,
    status          TEXT NOT NULL DEFAULT 'REQUESTED'
                        CHECK (status IN ('REQUESTED', 'BLOCKED', 'COMPLETED')),
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_erasure_requests_tenant
    ON erasure_requests (tenant_id, requested_at);

-- Minimal integrity metadata that survives erasure of the payload itself.
CREATE TABLE IF NOT EXISTS erasure_tombstones (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    data_class      TEXT NOT NULL,
    record_id       UUID,
    integrity_hash  TEXT NOT NULL,
    detail          TEXT,
    erase_request_id UUID NOT NULL REFERENCES erasure_requests(id),
    erased_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_erasure_tombstones_tenant
    ON erasure_tombstones (tenant_id, erased_at);

-- Tenant-owned erasure bookkeeping gets the same RLS treatment as findings.
DO $$
DECLARE
    target TEXT;
    tables TEXT[] := ARRAY['erasure_requests', 'erasure_tombstones'];
    predicate CONSTANT TEXT :=
        'tenant_id = NULLIF(current_setting(''itsm.tenant_id'', true), '''')::uuid';
BEGIN
    FOREACH target IN ARRAY tables LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', target);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', target);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', target);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I USING (%s) WITH CHECK (%s)',
            target, predicate, predicate
        );
    END LOOP;
END $$;

COMMIT;
