# Controlled Pilot (Task 17)

## Simulated organization

- One AWS account (Moto): CloudTrail management events.
- One PostgreSQL (pgAudit): privilege changes + access.
- One GitHub org: membership/permission changes.
- One identity/approval source (controlled import).

## Scenarios seeded

1. Normal user activity (benign).
2. Suspicious privilege escalation (AssumeRole to admin).
3. Activity without approval evidence.
4. Identity ambiguity (shared service account).
5. Delayed and missing events (coverage gap).

## Measurements

- Detection precision on seeded violations.
- False-positive rate on benign stream.
- Source coverage and evidence completeness.
- Manual investigation time reduction (qualitative).

## Known limitations

- Simulated only; no real tenant data.
- LLM investigation optional; core detection deterministic.
