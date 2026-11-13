-- 015_findings_lifecycle.sql
-- Finding lifecycle: explicit, audited status transitions (PRD question 9:
-- "Is the finding resolved and independently verified?").
--
-- Before this migration a finding's ``status`` was a free-text column that
-- detection wrote as ``OPEN`` and that nothing else could legitimately
-- change. There was no state machine, no transition record, and therefore no
-- audit trail for a lifecycle decision.
--
-- This migration adds:
--   * ``ACKNOWLEDGED``, ``VERIFIED`` and ``ACCEPTED_RISK`` to the allowed
--     ``findings.status`` values (``findings_status_lifecycle_check``), so a
--     lifecycle change cannot silently write a status outside the domain
--     vocabulary;
--   * ``findings.verified_by`` / ``findings.verified_at`` — who independently
--     verified a closed-out finding, and when;
--   * ``finding_transitions`` — an append-only, tenant-isolated ledger of
--     every transition (from, to, actor, reason, verifier). The ledger is the
--     audit trail; it is never updated or deleted.
--
-- The transition graph itself lives in ``itsm_agent.domain.finding_lifecycle``
-- (pure, no I/O). This file only enforces the storage contract.
--
-- Idempotent: safe to re-run.

BEGIN;

-- ---------------------------------------------------------------------------
-- findings.status vocabulary
-- ---------------------------------------------------------------------------
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_status_check;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'findings_status_lifecycle_check'
    ) THEN
        ALTER TABLE findings
            ADD CONSTRAINT findings_status_lifecycle_check
            CHECK (
                status IN (
                    'OPEN',
                    'ACKNOWLEDGED',
                    'INVESTIGATING',
                    'CONFIRMED',
                    'RESOLVED',
                    'VERIFIED',
                    'FALSE_POSITIVE',
                    'ACCEPTED_RISK',
                    'ESCALATED'
                )
            );
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Independent verification bookkeeping
-- ---------------------------------------------------------------------------
ALTER TABLE findings ADD COLUMN IF NOT EXISTS verified_by TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;

-- ---------------------------------------------------------------------------
-- finding_transitions: append-only lifecycle ledger
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS finding_transitions (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    finding_id      UUID NOT NULL REFERENCES findings (id),
    from_status     TEXT NOT NULL,
    to_status       TEXT NOT NULL,
    actor_id        TEXT NOT NULL,
    verifier_id     TEXT,
    reason          TEXT NOT NULL,
    transitioned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_finding_transitions_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT ck_finding_transitions_statuses CHECK (
        from_status IN (
            'OPEN', 'ACKNOWLEDGED', 'INVESTIGATING', 'CONFIRMED', 'RESOLVED',
            'VERIFIED', 'FALSE_POSITIVE', 'ACCEPTED_RISK', 'ESCALATED'
        )
        AND to_status IN (
            'OPEN', 'ACKNOWLEDGED', 'INVESTIGATING', 'CONFIRMED', 'RESOLVED',
            'VERIFIED', 'FALSE_POSITIVE', 'ACCEPTED_RISK', 'ESCALATED'
        )
    )
);

CREATE INDEX IF NOT EXISTS ix_finding_transitions_tenant_finding
    ON finding_transitions (tenant_id, finding_id, transitioned_at DESC);

-- Append-only trigger: the lifecycle ledger is the audit trail and must not
-- be rewritten after the fact.
CREATE OR REPLACE FUNCTION finding_transitions_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION
        'finding_transitions is append-only: % not permitted (transition %)',
        TG_OP, COALESCE(OLD.id::text, 'unknown');
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_finding_transitions_append_only ON finding_transitions;
CREATE TRIGGER trg_finding_transitions_append_only
    BEFORE UPDATE OR DELETE ON finding_transitions
    FOR EACH ROW EXECUTE FUNCTION finding_transitions_append_only();

-- ---------------------------------------------------------------------------
-- Row-level security: strict predicate, same contract as migration 007.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    strict_predicate CONSTANT TEXT :=
        'tenant_id = NULLIF(current_setting(''itsm.tenant_id'', true), '''')::uuid';
BEGIN
    EXECUTE 'ALTER TABLE finding_transitions ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE finding_transitions FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON finding_transitions';
    EXECUTE format(
        'CREATE POLICY tenant_isolation ON finding_transitions '
        'USING (%s) WITH CHECK (%s)',
        strict_predicate, strict_predicate
    );
END $$;

-- ---------------------------------------------------------------------------
-- Runtime least privilege: the runtime role may append and read transitions
-- but never rewrite or remove them (the trigger is defence in depth, not the
-- primary control).
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public'
           AND c.relname = 'finding_transitions'
           AND c.relkind = 'r'
    ) THEN
        EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON public.finding_transitions FROM itsm_app';
        EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON public.finding_transitions FROM PUBLIC';
        EXECUTE 'GRANT SELECT, INSERT ON public.finding_transitions TO itsm_app';
    END IF;
END $$;

COMMIT;
