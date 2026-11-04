-- 012_retention_scheduler.sql (security hardening slice)
-- Durable, resumable retention/erasure execution state.
--
-- The scheduler claims a request with a lease, so a crashed process cannot
-- leave a request permanently stuck in PROCESSING. Expired leases are
-- reclaimable; every attempt is counted; failures back off and eventually
-- become FAILED (an escalation signal), never a silent success.
--
-- RLS is also completed for the retention policy and legal-hold tables:
--   * platform defaults (tenant_id IS NULL) are readable by every tenant,
--     but a tenant session can only write its own overrides;
--   * legal holds are strictly tenant-scoped.
--
-- This file is idempotent.

BEGIN;

ALTER TABLE erasure_requests
    ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_error TEXT,
    ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS lease_until TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

ALTER TABLE erasure_requests DROP CONSTRAINT IF EXISTS erasure_requests_status_check;
ALTER TABLE erasure_requests
    ADD CONSTRAINT erasure_requests_status_check
    CHECK (status IN ('REQUESTED', 'PROCESSING', 'BLOCKED', 'COMPLETED', 'FAILED'));

CREATE INDEX IF NOT EXISTS ix_erasure_requests_due
    ON erasure_requests (next_attempt_at, requested_at)
    WHERE status IN ('REQUESTED', 'PROCESSING');

-- ---------------------------------------------------------------------------
-- RLS for retention configuration/holds.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    predicate CONSTANT TEXT :=
        'tenant_id = NULLIF(current_setting(''itsm.tenant_id'', true), '''')::uuid';
BEGIN
    ALTER TABLE retention_policies ENABLE ROW LEVEL SECURITY;
    ALTER TABLE retention_policies FORCE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation ON retention_policies;
    CREATE POLICY tenant_isolation ON retention_policies
        USING (tenant_id IS NULL OR tenant_id =
            NULLIF(current_setting('itsm.tenant_id', true), '')::uuid)
        WITH CHECK (tenant_id =
            NULLIF(current_setting('itsm.tenant_id', true), '')::uuid);

    ALTER TABLE legal_holds ENABLE ROW LEVEL SECURITY;
    ALTER TABLE legal_holds FORCE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation ON legal_holds;
    EXECUTE format(
        'CREATE POLICY tenant_isolation ON legal_holds USING (%s) WITH CHECK (%s)',
        predicate, predicate
    );
END $$;

COMMIT;
