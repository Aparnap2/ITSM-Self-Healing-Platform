-- 010_runtime_role.sql (security hardening slice)
-- Dedicated least-privileged runtime database role + server-side reviewer
-- authorization directory.
--
-- Separation of duties:
--   * migrations are applied by an owner/administration role (the role that
--     runs this file),
--   * the application connects as ``itsm_app``: NOSUPERUSER, NOBYPASSRLS,
--     NOCREATEDB, NOCREATEROLE, and no TRUNCATE / UPDATE / DELETE on the
--     append-only evidence tables.
--
-- The role is created NOLOGIN on purpose: credentials are attached by the
-- deployment system (``ALTER ROLE itsm_app LOGIN PASSWORD ...``) and are never
-- committed here. Tests may ``SET ROLE itsm_app`` or create a login copy.
--
-- This file is idempotent.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'itsm_app') THEN
        CREATE ROLE itsm_app
            NOLOGIN
            NOSUPERUSER
            NOBYPASSRLS
            NOCREATEDB
            NOCREATEROLE
            INHERIT;
    END IF;
END $$;

GRANT USAGE ON SCHEMA public TO itsm_app;

-- Broad DML on business tables; narrowed immediately below for append-only
-- and administration-only tables.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO itsm_app;
REVOKE TRUNCATE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA public FROM itsm_app;

-- Append-only records: the runtime role may read and append, never rewrite.
REVOKE UPDATE, DELETE ON source_events FROM itsm_app;
REVOKE UPDATE, DELETE ON audit_events FROM itsm_app;
REVOKE UPDATE, DELETE ON erasure_tombstones FROM itsm_app;

-- Authorization data is owned by the administration plane. The API only
-- reads it; it must not be able to grant itself roles or tenants.
CREATE TABLE IF NOT EXISTS reviewer_authorizations (
    issuer                  TEXT NOT NULL,
    subject                 TEXT NOT NULL,
    tenant_ids              UUID[] NOT NULL,
    roles                   TEXT[] NOT NULL,
    active                  BOOLEAN NOT NULL DEFAULT TRUE,
    authorization_version   TEXT NOT NULL,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (issuer, subject),
    CONSTRAINT reviewer_authorizations_tenants_not_empty
        CHECK (cardinality(tenant_ids) > 0),
    CONSTRAINT reviewer_authorizations_roles_not_empty
        CHECK (cardinality(roles) > 0)
);

CREATE INDEX IF NOT EXISTS ix_reviewer_authorizations_subject
    ON reviewer_authorizations (subject);

-- The runtime role (itsm_app) may READ the directory but never write it.
-- The GRANT above already granted DML on all tables; revoke the writes here.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE
    ON reviewer_authorizations FROM itsm_app;
GRANT SELECT ON reviewer_authorizations TO itsm_app;

-- Future tables created by the migration role inherit the same runtime
-- grants. Objects created by a different owner must be granted explicitly.
DO $$
BEGIN
    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public '
        'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO itsm_app',
        current_user
    );
    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public '
        'REVOKE TRUNCATE, REFERENCES, TRIGGER ON TABLES FROM itsm_app',
        current_user
    );
END $$;

COMMIT;
