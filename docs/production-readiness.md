# Production Readiness (Task 18)

## Deployment

- Docker Compose for local; CI via GitHub Actions.
- Env vars documented in .env.example (no secrets committed).

## Database

- Forward-only migrations via migrations/apply.py.
- Rollback: restore from backup; no down migrations.
- Backup: pg_dump scheduled; test restore periodically.

## Credential rotation

- Source credentials via env; rotate by updating env and restarting workers.
- No secrets in Git, logs, traces, or audit payloads.

## Runbooks

- docs/runbooks/SOP-01-start-environment.md
- docs/runbooks/SOP-02-ingestion-failure.md
- docs/runbooks/SOP-03-dlq-replay.md
- docs/runbooks/SOP-04-checkpoint-recovery.md
- docs/runbooks/SOP-05-tenant-provisioning.md

## Security review

- Tenant isolation tests (tests/integration/test_tenant_isolation.py).
- Redaction tests (tests/unit/test_redaction.py).
- Prompt injection: evidence passed as data; references validated.
- Residual risks documented in docs/security-boundaries.md.

## Dependency and license audit

- Moto (Apache-2.0), LocalStack (optional, license unverified), Mockoon (MIT).
- pip-audit runs in CI (`make audit-deps`); Trivy adds OS/library, secret, and
  misconfiguration scanning for both the source tree and the built image.
- PRs also run zizmor workflow auditing; dependency review is disabled until Dependency Graph is enabled.
- See `docs/security-ci.md` for the full gate map.

## CI qualification

- Gates: ruff format/check, mypy `--strict`, gitleaks, zizmor, Bandit,
  pip-audit, Trivy (fs + image), Docker build, compose config validation,
  OWASP ZAP baseline DAST, and pytest
  (unit/contract/security/integration/fault-injection/scenarios/e2e).
- `ci-summary` fails on a missing JUnit report, a failed test, or any required
  job that did not succeed (via `${{ toJSON(needs) }}`), so a silent skip
  cannot present as green.
- Migration safety is covered by
  `tests/integration/test_migration_safety.py` (fresh install, upgrade,
  backfill determinism, data preservation, failure recovery).

## Clean-environment deployment

- `make` targets + compose; verified by fresh clone + docker compose up.

## Demo walkthrough

- Ingest CloudTrail/pgAudit/GitHub events, run detection, inspect finding, view
  evidence bundle, record reviewer decision.

## Release decision

- Portfolio baseline: simulators only; no real production data/credentials.
- Known limitations stated in PRD and docs.
- A green pipeline is necessary but not sufficient: the exact-SHA evidence
  record and disqualifying conditions are in `docs/release-qualification.md`.
- This document is a readiness assessment, not a claim that the platform is
  production ready.

## Known limitations

- No real enterprise deployment; LocalStack license unverified.
- Compliance output is evidence, not certification.
