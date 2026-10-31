-- 004_detection.sql (Task 12): access facts, findings, evidence references, coverage.

BEGIN;

CREATE TABLE IF NOT EXISTS access_facts (
    id                  UUID PRIMARY KEY,
    tenant_id           UUID NOT NULL,
    source_event_id     UUID NOT NULL,
    principal_id        TEXT,
    resource_id         TEXT,
    action              TEXT NOT NULL,
    permission_context  JSONB NOT NULL DEFAULT '{}'::jsonb,
    granted_at          TIMESTAMPTZ,
    observed_at         TIMESTAMPTZ NOT NULL,
    fact_hash           TEXT NOT NULL,
    CONSTRAINT uq_access_fact UNIQUE (tenant_id, source_event_id, fact_hash)
);

CREATE INDEX IF NOT EXISTS ix_access_facts_tenant_principal
    ON access_facts (tenant_id, principal_id);

CREATE TABLE IF NOT EXISTS findings (
    id                  UUID PRIMARY KEY,
    tenant_id           UUID NOT NULL,
    finding_type        TEXT NOT NULL,
    severity            TEXT NOT NULL CHECK (severity IN ('P1', 'P2', 'P3', 'P4')),
    status              TEXT NOT NULL CHECK (status IN ('OPEN', 'INVESTIGATING', 'CONFIRMED', 'FALSE_POSITIVE', 'RESOLVED', 'ESCALATED')),
    title               TEXT NOT NULL,
    description         TEXT NOT NULL,
    detected_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    rule_version        TEXT NOT NULL,
    risk_score          INT NOT NULL DEFAULT 0,
    outcome             TEXT NOT NULL CHECK (outcome IN ('VIOLATION', 'SUSPICIOUS', 'COVERAGE_GAP', 'INCONCLUSIVE')),
    CONSTRAINT uq_finding UNIQUE (tenant_id, finding_type, title)
);

CREATE TABLE IF NOT EXISTS evidence_references (
    id                  UUID PRIMARY KEY,
    finding_id          UUID NOT NULL REFERENCES findings(id),
    source_event_id     UUID,
    access_fact_id      UUID REFERENCES access_facts(id),
    content_hash        TEXT NOT NULL,
    excerpt             TEXT,
    trust_level         TEXT NOT NULL,
    collected_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS coverage_status (
    id                  UUID PRIMARY KEY,
    tenant_id           UUID NOT NULL,
    source              TEXT NOT NULL,
    last_event_time     TIMESTAMPTZ,
    expected_cadence_seconds INT,
    status              TEXT NOT NULL CHECK (status IN ('HEALTHY', 'SILENT', 'DEGRADED', 'UNKNOWN')),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_coverage UNIQUE (tenant_id, source)
);

COMMIT;
