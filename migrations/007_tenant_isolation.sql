-- 007_tenant_isolation.sql (security slice)
-- PostgreSQL row-level security for tenant-owned tables.
--
-- Contract:
--   * The application sets the tenant ONCE per transaction with
--     set_config('itsm.tenant_id', <uuid>, true)  -- is_local = true
--     (see src/itsm_agent/adapters/persistence/tenant.py).
--   * Unset / empty context  -> NULLIF(...) is NULL -> no rows / writes denied.
--     This is fail-closed, not "see everything".
--   * FORCE ROW LEVEL SECURITY makes the policy apply to the table OWNER too.
--     Only a SUPERUSER or a role with BYPASSRLS escapes it, and the application
--     must run as a dedicated NOBYPASSRLS role (see docs/security-boundaries.md).
--   * event_inbox / outbox are system transport tables: rows written before
--     this migration have a NULL tenant_id and become invisible to every
--     tenant-scoped reader. The outbox relay therefore runs one scoped pass per
--     tenant (PsycopgTenantRepository.list_tenant_ids), not a cross-tenant scan.

BEGIN;

-- ---------------------------------------------------------------------------
-- Tenant registry: allows system components (outbox relay, retention) to
-- enumerate tenants without reading tenant-owned business rows. Contains no
-- business data; reading it is not a cross-tenant disclosure.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
    id          UUID PRIMARY KEY,
    name        TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- evidence_references was the only tenant-owned table without a tenant column.
-- Backfill from its finding so RLS can be applied; NOT NULL fails closed if an
-- orphan row exists (preferable to silently assigning the wrong tenant).
-- ---------------------------------------------------------------------------
ALTER TABLE evidence_references ADD COLUMN IF NOT EXISTS tenant_id UUID;
UPDATE evidence_references er
   SET tenant_id = f.tenant_id
  FROM findings f
 WHERE er.finding_id = f.id
   AND er.tenant_id IS NULL;
ALTER TABLE evidence_references ALTER COLUMN tenant_id SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'uq_evidence_references_tenant_id'
    ) THEN
        ALTER TABLE evidence_references
            ADD CONSTRAINT uq_evidence_references_tenant_id UNIQUE (tenant_id, id);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'uq_findings_tenant_id'
    ) THEN
        -- Needed as the target of the composite tenant-bound foreign keys.
        ALTER TABLE findings ADD CONSTRAINT uq_findings_tenant_id UNIQUE (tenant_id, id);
    END IF;
    -- Tenant-bound parent reference: a child row cannot point at a finding in
    -- another tenant even if the API filter were bypassed.
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_evidence_references_tenant_finding'
    ) THEN
        ALTER TABLE evidence_references
            ADD CONSTRAINT fk_evidence_references_tenant_finding
            FOREIGN KEY (tenant_id, finding_id)
            REFERENCES findings (tenant_id, id);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_review_decisions_tenant_finding'
    ) THEN
        ALTER TABLE review_decisions
            ADD CONSTRAINT fk_review_decisions_tenant_finding
            FOREIGN KEY (tenant_id, finding_id)
            REFERENCES findings (tenant_id, id);
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Row-level security: one policy per tenant-owned table.
--
-- Business tables use a strict predicate. The two transport tables also hold
-- pre-tenant legacy rows (tenant_id IS NULL) written by the incident webhook,
-- which has no tenant concept. Those rows are visible only to a session with
-- NO tenant context (the legacy system path); any tenant-scoped session sees
-- only its own rows. Neither context can see the other's rows, and a
-- tenant-scoped INSERT of a NULL tenant is still rejected by WITH CHECK.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    target TEXT;
    business_tables TEXT[] := ARRAY[
        'source_events',
        'source_checkpoints',
        'identity_mappings',
        'access_facts',
        'findings',
        'evidence_references',
        'coverage_status',
        'review_decisions',
        'processing_records'
    ];
    transport_tables TEXT[] := ARRAY['event_inbox', 'outbox'];
    strict_predicate CONSTANT TEXT :=
        'tenant_id = NULLIF(current_setting(''itsm.tenant_id'', true), '''')::uuid';
    transport_predicate CONSTANT TEXT :=
        '(tenant_id = NULLIF(current_setting(''itsm.tenant_id'', true), '''')::uuid'
        ' OR (tenant_id IS NULL'
        ' AND NULLIF(current_setting(''itsm.tenant_id'', true), '''') IS NULL))';
BEGIN
    FOREACH target IN ARRAY business_tables LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', target);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', target);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', target);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I USING (%s) WITH CHECK (%s)',
            target, strict_predicate, strict_predicate
        );
    END LOOP;

    FOREACH target IN ARRAY transport_tables LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', target);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', target);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', target);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I USING %s WITH CHECK %s',
            target, transport_predicate, transport_predicate
        );
    END LOOP;
END $$;

COMMIT;
