-- 003_identity_mappings.sql (Task 11)
-- Tenant-isolated identity mapping store with validity intervals.

BEGIN;

CREATE TABLE IF NOT EXISTS identity_mappings (
    id                  UUID PRIMARY KEY,
    tenant_id           UUID NOT NULL,
    source_system       TEXT NOT NULL,
    source_identifier   TEXT NOT NULL,
    internal_identity_id UUID NOT NULL,
    confidence          TEXT NOT NULL CHECK (confidence IN ('HIGH', 'MEDIUM', 'LOW', 'UNRESOLVED')),
    provenance          TEXT NOT NULL,
    valid_from          TIMESTAMPTZ NOT NULL,
    valid_to            TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_identity_mapping UNIQUE (tenant_id, source_system, source_identifier, valid_from)
);

CREATE INDEX IF NOT EXISTS ix_identity_mappings_tenant_internal
    ON identity_mappings (tenant_id, internal_identity_id);
CREATE INDEX IF NOT EXISTS ix_identity_mappings_tenant_source
    ON identity_mappings (tenant_id, source_system, source_identifier);

COMMIT;
