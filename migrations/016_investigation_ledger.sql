-- 016_investigation_ledger.sql
-- Append-only ledger for the selective agentic investigation stage.
--
-- The investigation stage is *advisory*: a model proposes, deterministic
-- policy and the independent verifier remain in charge. These two tables
-- therefore record what was asked, what was proposed and how the stage ended
-- -- nothing more. They never carry authority over the finding lifecycle.
--
-- Storage contract (mirrors migrations 002/007/015):
--   * append-only  -- UPDATE/DELETE are rejected by a trigger, and the
--                     runtime role holds SELECT + INSERT only;
--   * tenant-isolated -- RLS ENABLE + FORCE with the strict predicate
--                     ``tenant_id = NULLIF(current_setting('itsm.tenant_id', true), '')::uuid``;
--   * cross-tenant references are impossible -- a request/proposal may only
--                     point at a finding (and a request) of the same tenant.
--
-- A request is recorded as a *state ledger*: the canonical row carries the
-- request identity (``id = investigation_id``) and a terminal row is appended
-- when the stage concludes. Rows are never rewritten.
--
-- Idempotent: safe to re-run.

BEGIN;

-- ---------------------------------------------------------------------------
-- investigation_requests -- what was asked, and how the stage ended.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS investigation_requests (
    id                    UUID PRIMARY KEY,
    tenant_id             UUID NOT NULL,
    finding_id            UUID NOT NULL REFERENCES findings (id),
    requested_by          TEXT NOT NULL,
    question              TEXT NOT NULL,
    evidence_snapshot_ids UUID[] NOT NULL,
    max_tool_calls        INT NOT NULL,
    max_model_calls       INT NOT NULL,
    status                TEXT NOT NULL
        CHECK (status IN ('REQUESTED', 'COMPLETED', 'SKIPPED', 'FAILED')),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_investigation_requests_tenant_id UNIQUE (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS ix_investigation_requests_tenant_finding
    ON investigation_requests (tenant_id, finding_id);

-- ---------------------------------------------------------------------------
-- investigation_proposals -- the model's opinion, stored verbatim.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS investigation_proposals (
    id                     UUID PRIMARY KEY,
    tenant_id              UUID NOT NULL,
    request_id             UUID NOT NULL REFERENCES investigation_requests (id),
    finding_id             UUID NOT NULL REFERENCES findings (id),
    hypothesis             TEXT NOT NULL,
    supporting_evidence    UUID[] NOT NULL,
    contradicting_evidence UUID[] NOT NULL,
    missing_evidence       TEXT[] NOT NULL,
    uncertainty            TEXT NOT NULL,
    recommended_disposition TEXT NOT NULL,
    model_calls_used       INT NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_investigation_proposals_tenant_id UNIQUE (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS ix_investigation_proposals_tenant_finding
    ON investigation_proposals (tenant_id, finding_id);

-- ---------------------------------------------------------------------------
-- Tenant-bound foreign keys: a child row cannot point at a parent row that
-- belongs to another tenant, even if the application filter were bypassed.
-- The composite keys are only added when the corresponding parent unique
-- constraint exists (migration 007 provides findings(tenant_id, id)).
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conname = 'uq_findings_tenant_id'
           AND conrelid = 'findings'::regclass
    ) THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
             WHERE conname = 'fk_investigation_requests_tenant_finding'
        ) THEN
            ALTER TABLE investigation_requests
                ADD CONSTRAINT fk_investigation_requests_tenant_finding
                FOREIGN KEY (tenant_id, finding_id)
                REFERENCES findings (tenant_id, id);
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
             WHERE conname = 'fk_investigation_proposals_tenant_finding'
        ) THEN
            ALTER TABLE investigation_proposals
                ADD CONSTRAINT fk_investigation_proposals_tenant_finding
                FOREIGN KEY (tenant_id, finding_id)
                REFERENCES findings (tenant_id, id);
        END IF;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'fk_investigation_proposals_tenant_request'
    ) THEN
        ALTER TABLE investigation_proposals
            ADD CONSTRAINT fk_investigation_proposals_tenant_request
            FOREIGN KEY (tenant_id, request_id)
            REFERENCES investigation_requests (tenant_id, id);
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Append-only triggers: the ledger is the audit trail and must not be
-- rewritten after the fact.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION investigation_requests_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION
        'investigation_requests is append-only: % not permitted (request %)',
        TG_OP, COALESCE(OLD.id::text, 'unknown');
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_investigation_requests_append_only ON investigation_requests;
CREATE TRIGGER trg_investigation_requests_append_only
    BEFORE UPDATE OR DELETE ON investigation_requests
    FOR EACH ROW EXECUTE FUNCTION investigation_requests_append_only();

CREATE OR REPLACE FUNCTION investigation_proposals_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION
        'investigation_proposals is append-only: % not permitted (proposal %)',
        TG_OP, COALESCE(OLD.id::text, 'unknown');
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_investigation_proposals_append_only ON investigation_proposals;
CREATE TRIGGER trg_investigation_proposals_append_only
    BEFORE UPDATE OR DELETE ON investigation_proposals
    FOR EACH ROW EXECUTE FUNCTION investigation_proposals_append_only();

-- ---------------------------------------------------------------------------
-- Row-level security: strict predicate, same contract as migration 007.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    strict_predicate CONSTANT TEXT :=
        'tenant_id = NULLIF(current_setting(''itsm.tenant_id'', true), '''')::uuid';
BEGIN
    EXECUTE 'ALTER TABLE investigation_requests ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE investigation_requests FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON investigation_requests';
    EXECUTE format(
        'CREATE POLICY tenant_isolation ON investigation_requests '
        'USING (%s) WITH CHECK (%s)',
        strict_predicate, strict_predicate
    );

    EXECUTE 'ALTER TABLE investigation_proposals ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE investigation_proposals FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON investigation_proposals';
    EXECUTE format(
        'CREATE POLICY tenant_isolation ON investigation_proposals '
        'USING (%s) WITH CHECK (%s)',
        strict_predicate, strict_predicate
    );
END $$;

-- ---------------------------------------------------------------------------
-- Runtime least privilege: the runtime role may append and read the ledger
-- but never rewrite or remove it (the trigger is defence in depth, not the
-- primary control).
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public'
           AND c.relname = 'investigation_requests'
           AND c.relkind = 'r'
    ) THEN
        EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON public.investigation_requests FROM itsm_app';
        EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON public.investigation_requests FROM PUBLIC';
        EXECUTE 'GRANT SELECT, INSERT ON public.investigation_requests TO itsm_app';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public'
           AND c.relname = 'investigation_proposals'
           AND c.relkind = 'r'
    ) THEN
        EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON public.investigation_proposals FROM itsm_app';
        EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON public.investigation_proposals FROM PUBLIC';
        EXECUTE 'GRANT SELECT, INSERT ON public.investigation_proposals TO itsm_app';
    END IF;
END $$;

COMMIT;
