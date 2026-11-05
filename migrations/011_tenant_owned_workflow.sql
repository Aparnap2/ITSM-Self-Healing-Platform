-- 011_tenant_owned_workflow.sql (security hardening slice)
-- Tenant ownership + RLS for the incident/remediation tables that were
-- previously outside the tenant boundary:
--   incidents, workflow_state, action_intents, approvals, audit_events.
--
-- Backfill policy (deterministic, no guessing across tenants):
--   1. Match an incident to a canonical source event by external_event_id.
--   2. If exactly one non-system tenant exists, assign remaining legacy rows
--      to it.
--   3. Otherwise assign remaining legacy rows to a dedicated ``system``
--      tenant (fixed UUID). Those rows remain reachable only by a session
--      that explicitly sets that tenant context; no reviewer is a member.
--
-- After backfill every column is NOT NULL, so new code cannot create a
-- tenant-less business row. Composite foreign keys make cross-tenant
-- parent/child references impossible even if an application filter is wrong.
--
-- This file is idempotent.

BEGIN;

-- ---------------------------------------------------------------------------
-- System tenant used by the legacy incident workflow and pre-tenant rows.
-- ---------------------------------------------------------------------------
INSERT INTO tenants (id, name)
VALUES ('00000000-0000-0000-0000-000000000001', 'system-legacy')
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- incidents
-- ---------------------------------------------------------------------------
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE incidents i
   SET tenant_id = se.tenant_id
  FROM source_events se
 WHERE i.tenant_id IS NULL
   AND i.external_event_id IS NOT NULL
   AND se.source_event_id = i.external_event_id;

DO $$
DECLARE
    tenants_count INTEGER;
    chosen_tenant UUID;
BEGIN
    IF EXISTS (SELECT 1 FROM incidents WHERE tenant_id IS NULL) THEN
        -- The system tenant itself is excluded: it is infrastructure, not a
        -- customer. Counting it would make the "single-tenant deployment"
        -- branch unreachable, because it is inserted just above.
        SELECT count(*) INTO tenants_count
          FROM tenants
         WHERE id <> '00000000-0000-0000-0000-000000000001';
        IF tenants_count = 1 THEN
            SELECT id INTO chosen_tenant
              FROM tenants
             WHERE id <> '00000000-0000-0000-0000-000000000001';
        ELSE
            chosen_tenant := '00000000-0000-0000-0000-000000000001';
        END IF;
        UPDATE incidents SET tenant_id = chosen_tenant WHERE tenant_id IS NULL;
    END IF;
END $$;

ALTER TABLE incidents ALTER COLUMN tenant_id SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'uq_incidents_tenant_id'
    ) THEN
        ALTER TABLE incidents ADD CONSTRAINT uq_incidents_tenant_id UNIQUE (tenant_id, id);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS ix_incidents_tenant_status
    ON incidents (tenant_id, status);

-- ---------------------------------------------------------------------------
-- workflow_state
-- ---------------------------------------------------------------------------
ALTER TABLE workflow_state ADD COLUMN IF NOT EXISTS tenant_id UUID;
UPDATE workflow_state ws
   SET tenant_id = i.tenant_id
  FROM incidents i
 WHERE ws.tenant_id IS NULL AND ws.incident_id = i.id;
UPDATE workflow_state
   SET tenant_id = '00000000-0000-0000-0000-000000000001'
 WHERE tenant_id IS NULL;
ALTER TABLE workflow_state ALTER COLUMN tenant_id SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_workflow_state_tenant_incident'
    ) THEN
        ALTER TABLE workflow_state
            ADD CONSTRAINT fk_workflow_state_tenant_incident
            FOREIGN KEY (tenant_id, incident_id)
            REFERENCES incidents (tenant_id, id);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS ix_workflow_state_tenant
    ON workflow_state (tenant_id, updated_at);

-- ---------------------------------------------------------------------------
-- action_intents
-- ---------------------------------------------------------------------------
ALTER TABLE action_intents ADD COLUMN IF NOT EXISTS tenant_id UUID;
UPDATE action_intents ai
   SET tenant_id = i.tenant_id
  FROM incidents i
 WHERE ai.tenant_id IS NULL AND ai.incident_id = i.id;
UPDATE action_intents
   SET tenant_id = '00000000-0000-0000-0000-000000000001'
 WHERE tenant_id IS NULL;
ALTER TABLE action_intents ALTER COLUMN tenant_id SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_action_intents_tenant_incident'
    ) THEN
        ALTER TABLE action_intents
            ADD CONSTRAINT fk_action_intents_tenant_incident
            FOREIGN KEY (tenant_id, incident_id)
            REFERENCES incidents (tenant_id, id);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS ix_action_intents_tenant
    ON action_intents (tenant_id, intent_recorded_at);

-- ---------------------------------------------------------------------------
-- approvals
-- ---------------------------------------------------------------------------
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS tenant_id UUID;
UPDATE approvals a
   SET tenant_id = i.tenant_id
  FROM incidents i
 WHERE a.tenant_id IS NULL AND a.incident_id = i.id;
UPDATE approvals
   SET tenant_id = '00000000-0000-0000-0000-000000000001'
 WHERE tenant_id IS NULL;
ALTER TABLE approvals ALTER COLUMN tenant_id SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_approvals_tenant_incident'
    ) THEN
        ALTER TABLE approvals
            ADD CONSTRAINT fk_approvals_tenant_incident
            FOREIGN KEY (tenant_id, incident_id)
            REFERENCES incidents (tenant_id, id);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS ix_approvals_tenant
    ON approvals (tenant_id, requested_at);

-- ---------------------------------------------------------------------------
-- audit_events (append-only)
-- ---------------------------------------------------------------------------
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS tenant_id UUID;
UPDATE audit_events ae
   SET tenant_id = i.tenant_id
  FROM incidents i
 WHERE ae.tenant_id IS NULL AND ae.incident_id = i.id;
UPDATE audit_events
   SET tenant_id = '00000000-0000-0000-0000-000000000001'
 WHERE tenant_id IS NULL;
ALTER TABLE audit_events ALTER COLUMN tenant_id SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_audit_events_tenant_incident'
    ) THEN
        ALTER TABLE audit_events
            ADD CONSTRAINT fk_audit_events_tenant_incident
            FOREIGN KEY (tenant_id, incident_id)
            REFERENCES incidents (tenant_id, id);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS ix_audit_events_tenant
    ON audit_events (tenant_id, occurred_at);

-- ---------------------------------------------------------------------------
-- Row-level security: strict predicate, same contract as migration 007.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    target TEXT;
    tables TEXT[] := ARRAY[
        'incidents',
        'workflow_state',
        'action_intents',
        'approvals',
        'audit_events'
    ];
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
