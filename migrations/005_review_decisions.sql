-- 005_review_decisions.sql (Task 14)
BEGIN;

CREATE TABLE IF NOT EXISTS review_decisions (
    id            UUID PRIMARY KEY,
    tenant_id     UUID NOT NULL,
    finding_id    UUID NOT NULL,
    reviewer_id   TEXT NOT NULL,
    decision      TEXT NOT NULL CHECK (decision IN ('CONFIRMED', 'FALSE_POSITIVE', 'ACCEPTED_RISK', 'NEEDS_MORE_EVIDENCE')),
    decided_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    rationale     TEXT NOT NULL,
    evidence_pack_ref TEXT
);

CREATE INDEX IF NOT EXISTS ix_review_decisions_finding ON review_decisions (finding_id);

COMMIT;
