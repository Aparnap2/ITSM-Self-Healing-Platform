-- 017_review_decisions_append_only.sql
--
-- H1: reviewer decisions are audit history. They must be append-only at the
-- storage level, not merely by application convention.
--
-- Before this migration ``review_decisions`` was created by 005 without any
-- append-only contract and migration 010 granted the runtime role
-- ``SELECT, INSERT, UPDATE, DELETE`` on every table. Nothing prevented the
-- runtime role from rewriting or removing a reviewer decision, which would
-- silently corrupt the audit trail that the two-reviewer lifecycle depends on.
--
-- This migration closes that gap with two independent layers:
--   1. Privileges (primary runtime enforcement): revoke UPDATE, DELETE and
--      TRUNCATE from ``itsm_app``. The application can only INSERT and SELECT.
--   2. Trigger (defense in depth): reject UPDATE/DELETE even if a privileged
--      application path or future role change re-grants the privilege. This
--      does NOT protect against a database owner or superuser deliberately
--      disabling the trigger; privileges are the enforcement boundary.
--
-- Idempotent: safe to re-run against a populated database.

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. Runtime privileges: INSERT + SELECT only.
-- ---------------------------------------------------------------------------
REVOKE UPDATE, DELETE, TRUNCATE ON review_decisions FROM itsm_app;
GRANT SELECT, INSERT ON review_decisions TO itsm_app;

-- ---------------------------------------------------------------------------
-- 2. Append-only trigger (defense in depth).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION review_decisions_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION
        'review_decisions is append-only: % not permitted (decision %)',
        TG_OP, COALESCE(OLD.id::text, 'unknown');
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_review_decisions_append_only ON review_decisions;
CREATE TRIGGER trg_review_decisions_append_only
    BEFORE UPDATE OR DELETE ON review_decisions
    FOR EACH ROW EXECUTE FUNCTION review_decisions_append_only();

-- ---------------------------------------------------------------------------
-- 3. erasure_tombstones was granted REVOKE in 010 but never had a trigger.
--    Add one for catalog-level consistency with the other append-only tables.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION erasure_tombstones_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION
        'erasure_tombstones is append-only: % not permitted (tombstone %)',
        TG_OP, COALESCE(OLD.id::text, 'unknown');
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_erasure_tombstones_append_only ON erasure_tombstones;
CREATE TRIGGER trg_erasure_tombstones_append_only
    BEFORE UPDATE OR DELETE ON erasure_tombstones
    FOR EACH ROW EXECUTE FUNCTION erasure_tombstones_append_only();

COMMIT;
