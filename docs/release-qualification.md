# Release qualification

This document defines what "release qualified" means for this repository,
how to prove it from CI evidence, and what a green pipeline still does not
prove. It is a companion to `docs/security-ci.md` and
`docs/production-readiness.md`; it is not a production-readiness claim.

## Status and scope

- Portfolio baseline: simulators only (Mockoon, Moto, the in-process
  infrastructure simulator). No real production data, credentials, or
  external SaaS mutations.
- **Recorded qualification (observed 2026-11-15).** The vehicle is PR #16
  (`feat/detection-precision` into `main`), squash-merged on 2026-11-15 as
  `2ebd7ef3ba426c6021bacc5054a74eb798edb510`. The `push` run `43672858417`
  on `main` has `headSha`
  `2ebd7ef3ba426c6021bacc5054a74eb798edb510`, event `push`, conclusion
  `success`, and **15/15 jobs `success`, 0 failures**. The PR's own run
  `43672469226` on `ffa188da6d4117331e61dc3b9469e2bdb3f7d906` is also
  15/15 `success`. Local bulk run (strict; real PostgreSQL and NATS) at that
  commit passed: **696 tests** — unit 468, contract 40, security 45,
  integration 140, fault injection 18, scenarios 24, e2e 12; ruff clean;
  `mypy --strict` across 173 files; Bandit clean; `pip-audit` reports no known
  vulnerabilities.
- **Superseded record (observed 2026-11-14).** The vehicle was PR #15
  (`feat/finding-lifecycle-clean` into `main`), squash-merged on 2026-11-13 as
  `fc49556fe2d18114c20c74920f683f2b9063c288`. The `push` run `43367043262`
  on `main` has `headSha`
  `fc49556fe2d18114c20c74920f683f2b9063c288`, event `push`, conclusion
  `success`, and **15/15 jobs `success`, 0 failures**. Local `make verify-ci`
  (strict; real PostgreSQL and NATS) at that commit passed: unit 373,
  contract 40, security 45, integration 136, fault injection 18, scenarios
  24, e2e 12; ruff clean; `mypy --strict` across 166 files; Bandit clean.
- **Superseded record (observed 2026-11-06).** The vehicle was PR #9
  (`feat/access-audit-foundation`), squash-merged on 2026-11-06 as
  `57c9d8cd049dd243d13c7610c5fe75270a687af2`; `push` run `42214887310`,
  all 15 jobs `success`, 444 unique tests, 0 failures + errors, 0 skipped,
  and all seven mandatory JUnit artifacts present and unexpired. Items 1-5
  were satisfied. Item 6 was **not**: `main` had no branch protection then,
  so repository governance was recorded as an unverified gap. Branch
  protection is enabled now (item 6); the 2026-11-14 record above supersedes
  this one.
- PR #14 was closed as superseded. Its commit range contained secret-shaped
  test fixtures that the gitleaks gate flagged. The branch was rebuilt so no
  commit contains a secret-shaped literal: the redaction fixture now
  assembles its key at runtime and the reviewer credential carries a neutral
  name (`35e112c`). The scan gate was not weakened and nothing was
  allowlisted.
- Re-verify before citing:
  `gh run view 43672858417 --json headSha,event,conclusion,jobs` and
  `gh api repos/<owner>/<repo>/actions/runs/43672858417/artifacts`.
- A later run supersedes this record; a green `pull_request` run on the head
  branch is supporting evidence, not the qualified run.

## Definition of release qualified

A release is qualified only when **all** of the following are true:

1. **Exact CI run.** There is a completed `CI` workflow run triggered by
   `push` on `main` whose `headSha` equals the PR's merge commit SHA. A
   `pull_request` run on the head branch is supporting evidence, not the
   qualified run, because its SHA is not the merge commit.
2. **All required jobs succeeded.** Every job in the required set below has
   `conclusion = success`. `cancelled`, `timed_out`, `failure`,
   `action_required`, `neutral`, `stale`, or an unexplained `skipped` is a
   failure for qualification.
3. **The summary passed.** The `ci-summary` job is `success`, its rendered
   summary reports 0 failures + errors, no missing mandatory report, and a
   non-zero unique test count.
4. **Artifacts retained.** The seven mandatory JUnit artifacts exist for that
   run and are not expired at review time. They are uploaded with an
   explicit `retention-days` (30, from `ARTIFACT_RETENTION_DAYS` in
   `.github/workflows/ci.yml`), and the CI summary prints the expiry it
   derives from that value. `sbom` and `dast-report` are supporting
   evidence: they are uploaded with `if-no-files-found: warn`
   (`.github/workflows/ci.yml`), so their absence does not fail CI. If either
   is missing, record it as an evidence gap rather than calling the run fully
   evidenced.
5. **No weakened gates.** The workflow and summary tooling at the merge SHA
   still contain every required job and the same mandatory report list; no
   `continue-on-error`, no `if: false`, and no new optional job that bypasses
   the summary.
6. **Branch protection.** Protection on `main` was enabled on 2026-11-13
   (owner-approved). The 15 CI job names in the Required gates table are
   required status checks with `strict: true` (the branch must be up to date
   before merging); pull requests are required; `enforce_admins: true`; force
   pushes and branch deletion are blocked. Required approving reviews is
   **0**: the repository is solo-maintained and GitHub does not let a PR
   author approve their own PR, so requiring one approval would block all
   work. Raise the required approving review count to **1** when an
   independent reviewer with write access exists. Protection is enabled, but
   it is not a substitute for independent human review; this qualification
   does not claim that independent review occurred.

The release decision is recorded by filling the evidence table in this
document and attaching it to the PR or release ticket.

## Required gates

The required set is the `ci-summary` `needs` list in
`.github/workflows/ci.yml`, plus `ci-summary` itself. It is named explicitly
in `tools/ci_summary.py` (`REQUIRED_JOBS`) and checked against the run's
`needs` payload, so a job that is missing from the workflow fails the summary
instead of silently narrowing the gate.

**All 15 jobs are required, `dast` included.** `tools/ci_summary.py`'s
`--optional-jobs` defaults to an empty list, so a `dast` job that is
`skipped` (or that fails) fails the CI summary. The only way to relax a gate
is for the owner to name the job explicitly, and the summary prints the
owner-marked optional list so the relaxation is visible in the evidence.

| Gate | Job id | Workflow job name | Blocking signal | Artifact |
| --- | --- | --- | --- | --- |
| Formatting and lint | `lint` | Lint & Format | non-zero exit | none |
| Static typing | `typecheck` | Type Check (mypy --strict) | non-zero exit | none |
| Secret scanning | `secret-scan` | Secret Scan (gitleaks) | any finding | none (job log) |
| Workflow security | `workflow-security` | Workflow Security (zizmor) | finding at/above medium severity + high confidence | none |
| Supply chain, SAST, SBOM | `supply-chain` | Supply Chain (pip-audit, bandit, SBOM) | Bandit/pip-audit/Trivy fs finding | `sbom` |
| Build and compose | `build` | Build & Compose Config | build/config failure; Trivy image CRITICAL/HIGH (fixed) | none (job log) |
| DAST | `dast` | DAST (OWASP ZAP baseline, isolated target) | configured FAIL rule | `dast-report` |
| Unit tests | `unit-tests` | Unit Tests | any failure | `unit-junit` |
| Contract tests | `contract-tests` | Contract Tests (simulators, offline) | any failure | `contract-junit` |
| Security invariants | `security-invariants` | Security Invariant Tests | any failure | `security-junit` |
| Integration | `integration-tests` | Integration Tests | any failure; migration harness red | `integration-junit` |
| Fault injection | `fault-injection-tests` | Fault Injection Tests | any failure | `fault-injection-junit` |
| E2E | `e2e-tests` | E2E Tests | any failure | `e2e-junit` |
| Scenario harness | `scenarios` | Scenario Harness | any failure | `scenarios-junit` |
| Summary | `ci-summary` | CI Verification Summary | missing report, any failure, non-success required job | run summary page |

Sources: `.github/workflows/ci.yml`, `tools/ci_summary.py`
(`REQUIRED_JOBS`, `EXPECTED_REPORTS`), `docs/security-ci.md`,
`docs/ci/README.md`.

The 15 job names in the "Workflow job name" column are also the required
status checks on the protected `main` branch (item 6).

## Evidence table

Fill this in from the qualified run. Use `success` / `failure` / `skipped` /
`cancelled` exactly as GitHub reports it. Do not paraphrase a result into
"green".

The table below is the **2026-11-06 record** (run `42214887310`, PR #9),
kept as the last fully inventoried evidence set. It is superseded by the
2026-11-14 record above: that run reports 15/15 jobs `success` with 0
failures, but its artifacts were not re-inventoried during this refresh, so
the table is not restated for it. Re-inventory run `43672858417` with step 4
below before citing the newer run as artifact-backed.

| Gate | Job name | Result | Artifact/link | Notes |
| --- | --- | --- | --- | --- |
| Formatting and lint | Lint & Format | `success` | run `42214887310` | |
| Static typing | Type Check (mypy --strict) | `success` | run `42214887310` | 148 source files |
| Secret scanning | Secret Scan (gitleaks) | `success` | `gitleaks-results.sarif` | no finding |
| Workflow security | Workflow Security (zizmor) | `success` | run `42214887310` | |
| Supply chain, SAST, SBOM | Supply Chain (pip-audit, bandit, SBOM) | `success` | `sbom` | Bandit/pip-audit/Trivy clean |
| Build and compose | Build & Compose Config | `success` | run `42214887310` | |
| DAST | DAST (OWASP ZAP baseline, isolated target) | `success` | `dast-report` | no FAIL rule |
| Unit tests | Unit Tests | `success` | `unit-junit` | 246 tests, 0 failed |
| Contract tests | Contract Tests (simulators, offline) | `success` | `contract-junit` | 40 tests, 0 failed |
| Security invariants | Security Invariant Tests | `success` | `security-junit` | 45 tests, 0 failed |
| Integration | Integration Tests | `success` | `integration-junit` | 113 tests, 0 failed; includes migration harness |
| Fault injection | Fault Injection Tests | `success` | `fault-injection-junit` | 18 tests, 0 failed |
| E2E | E2E Tests | `success` | `e2e-junit` | 9 tests, 0 failed |
| Scenario harness | Scenario Harness | `success` | `scenarios-junit` | 24 tests, 0 failed |
| Summary | CI Verification Summary | `success` | run `42214887310` | 444 unique tests, 0 failures + errors, 0 missing groups |
| Run binding | `headSha` = `57c9d8cd049dd243d13c7610c5fe75270a687af2` | `success` | run `42214887310` | event `push` on `main` |

## Disqualifying conditions

Any one of these makes the run **not qualified**. Do not average, waive, or
call it "mostly green".

- Any required job has a conclusion other than `success`.
- `ci-summary` is red, or its summary contains
  "Missing mandatory group(s) — this run is not qualified." or
  "Required job(s) did not succeed — this run is not qualified." or
  "This run is not qualified."
  (`tools/ci_summary.py`).
- Any of the seven mandatory JUnit reports is missing:
  `unit-junit.xml`, `contract-junit.xml`, `security-junit.xml`,
  `integration-junit.xml`, `fault-injection-junit.xml`,
  `scenarios-junit.xml`, `e2e-junit.xml` (`tools/ci_summary.py`,
  `EXPECTED_REPORTS`).
- A mandatory report collected zero tests, or skipped every one of its tests,
  or carries a provenance stamp for a different SHA, run or attempt.
- gitleaks reports a finding.
- Trivy reports a CRITICAL or HIGH vulnerability that is fixed
  (`ignore-unfixed: true` is the only permitted exclusion), in either the
  filesystem or the image scan.
- Bandit reports a finding, or pip-audit reports a known vulnerability.
- zizmor reports a finding at/above medium severity with high confidence.
- DAST reports a FAIL rule from `ci/zap-baseline.conf`.
- The migration harness is red: `tests/integration/test_migration_safety.py`
  (fresh install, upgrade, backfill, data preservation, failure recovery).
- An RLS or privilege regression is red:
  `tests/integration/test_runtime_database_safety.py`,
  `tests/integration/test_rls_tenant_isolation.py`,
  `tests/integration/test_tenant_propagation.py`.
- The run's `headSha` is not the merge commit SHA, or the run is a
  `pull_request` run rather than the `push` run on `main`.
- Any required artifact is expired or absent for that run.
- The workflow at the merge SHA contains `continue-on-error`, an `if: false`
  gate, a removed required job, or an expanded `--optional-jobs` list.
- Branch protection is configured and the merge violates it. Protection is
  enabled on `main` (item 6); a satisfied required-check gate is a merge
  gate, not independent human review, so this qualification does not claim
  that independent review occurred.
- A secret appears in the diff, logs, artifacts, or audit payloads.

## How to verify

Use `<run-id>`, `<merge-sha>`, and `<owner>/<repo>` placeholders. Never
paste a real token into a ticket.

### 1. Resolve the merge commit

```sh
gh pr view 15 --json number,state,mergeCommit,headRefOid,mergeStateStatus,url
```

For a merged PR, `mergeCommit.oid` is the SHA the qualification run must
match. Record it as `<merge-sha>`.

### 2. Find the push run on `main`

```sh
gh run list --workflow CI --branch main --limit 20 \
  --json databaseId,headSha,event,status,conclusion,createdAt,url
```

Select the completed run with `event = "push"` and `headSha = <merge-sha>`.
If there is no such run, the merge is not qualified.

### 3. Inspect the run and every job

```sh
gh run view <run-id> \
  --json headSha,event,status,conclusion,url,jobs \
  --jq '{sha: .headSha, event: .event, conclusion: .conclusion,
         jobs: [.jobs[] | {name: .name, conclusion: .conclusion, url: .url}]}'
```

Cross-check the PR rollup. Exit code `8` means checks are still pending.

```sh
gh pr checks 15 --json name,state,bucket,link
```

### 4. Inventory artifacts and retention

```sh
gh api "repos/<owner>/<repo>/actions/runs/<run-id>/artifacts" \
  --jq '.artifacts[] | {name, size_in_bytes, expired, expires_at}'
```

Expected artifact names: `sbom`, `dast-report`, `image-digest`, `unit-junit`,
`contract-junit`, `security-junit`, `integration-junit`,
`fault-injection-junit`, `e2e-junit`, `scenarios-junit`
(`.github/workflows/ci.yml`).

Each `*-junit` artifact carries three files: the JUnit XML, the
`<suite>.collect.txt` preflight record, and the `<suite>.meta` provenance
stamp. A missing sidecar fails the CI summary.

### 5. Download and re-check the JUnit set

```sh
mkdir -p reports/qualification
gh run download <run-id> -p '*-junit' -D reports/qualification
find reports/qualification -name '*-junit.xml' -exec cp {} reports/qualification/ \;
find reports/qualification -name '*.collect.txt' -exec cp {} reports/qualification/ \;
find reports/qualification -name '*.meta' -exec cp {} reports/qualification/ \;
python3 tools/ci_summary.py \
  --reports reports/qualification \
  --sha <merge-sha> \
  --run-id <run-id> \
  --run-attempt 1 \
  --retention-days 30 \
  --no-require-needs
```

`gh run download` extracts each artifact into its own directory; the `cp`
step flattens them for `tools/ci_summary.py`, which expects the seven report
filenames — and, since the anti-vacuity and provenance rules were added, the
matching `*.collect.txt` and `*.meta` sidecars — in one directory.

The local recomputation cannot see job conclusions: `NEEDS_RESULTS` is only
populated inside the workflow. `--no-require-needs` is therefore required for
a local re-check; without it the summary fails closed on the missing job
results. Use step 3 for job results and the run's summary page for the
authoritative `ci-summary` output.

### 6. Verify the gates were not weakened

```sh
git show <merge-sha>:.github/workflows/ci.yml | grep -nE 'continue-on-error|if: *false'
# Expected: no output (exit 1).

git show <merge-sha>:.github/workflows/ci.yml \
  | sed -n '/^  ci-summary:/,/^    steps:/p' | grep -E '^      - '
# Expected: the fourteen required jobs listed above.
```

```sh
git diff origin/main...<merge-sha> -- .github/workflows/ci.yml tools/ci_summary.py
```

Review the diff for removed jobs, changed `needs`, changed `EXPECTED_REPORTS`,
or a wider `--optional-jobs`. A gate that was weakened is a disqualifier even
if the run is green.

### 7. Verify branch protection (requires admin access)

```sh
gh api "repos/<owner>/<repo>/branches/main/protection" \
  --jq '{required_checks: .required_status_checks.contexts,
         strict: .required_status_checks.strict,
         pull_requests: .required_pull_request_reviews,
         approving_reviews: .required_approving_review_count,
         enforce_admins: .enforce_admins.enabled,
         force_pushes: .allow_force_pushes.enabled,
         deletions: .allow_deletions.enabled}'
```

A `403` here means the caller lacks admin access; record that as an
unverified item, not as a pass.

The expected policy is the one in item 6: the 15 job names from the
Required gates table, `strict: true`, pull requests required,
`enforce_admins: true`, force pushes and deletions blocked, and
`approving_reviews: 0` while the repository is solo-maintained.

## Where the summary comes from

`ci-summary` runs `tools/ci_summary.py` with the run's reports, commit SHA,
run id, run attempt, PR head SHA and the declared retention window
(`.github/workflows/ci.yml`). It:

- requires all seven JUnit reports (`EXPECTED_REPORTS`), each present,
  non-empty, parseable, with a non-zero test count and at least one executed
  test;
- requires the collect preflight record and the provenance stamp for every
  report, and checks that the stamp matches this commit, run and attempt;
- requires the declared retention window;
- checks `NEEDS_RESULTS` and fails when a required job is absent from the
  payload or did not reach `success` (no job is optional by default);
- writes a Markdown table to `GITHUB_STEP_SUMMARY`, which renders on the
  run's summary page;
- exits non-zero on any of the above.

The summary is the artifact of record. A green job list without a green
`ci-summary` is not qualified.

## What a green pipeline does not prove

Green CI is **necessary but not sufficient**. This repository remains a
simulator-only, portfolio baseline. A qualified run does not prove:

- that a deployed process serves HTTP correctly or reaches its database
  (`docs/security-ci.md:30-46`);
- that a production database role is `NOBYPASSRLS`: the startup assertion
  exists (`src/itsm_agent/adapters/persistence/privileges.py`), but the
  deployment must be the one that ran it (`docs/security-boundaries.md:87-93`);
- that the HMAC bearer is an identity provider: there is no key rotation,
  revocation list, or clock-skew allowance
  (`docs/security-boundaries.md:113-115`);
- that retention deletes raw evidence from object storage: the packaged
  scheduler (`python -m itsm_agent.workers.retention`) tombstones it and
  deletes derived rows, but bucket lifecycle rules are still required
  (`src/itsm_agent/privacy/scheduler.py`,
  `tests/integration/test_retention_scheduler_lifecycle.py`);
- that NATS is highly available: the repository tests a single node
  (`docs/nats-stream-config.md:30-33`);
- that a real Jira Service Management or ServiceNow adapter works: neither is
  implemented; Mockoon is the acceptance connector (`README.md`);
- that the required status checks are correctly scoped or meaningful: the
  gate proves the checks ran and reported success, not that they cover the
  change. No independent human review has occurred, and the required
  approving review count on `main` is 0;
- that the detection engine's false-positive behaviour is characterised
  beyond the measured pilot artifact: `docs/pilot.md` measures the
  deterministic detection layer only (recall 0.8889 over all malicious
  scenarios, 1.0000 over rule-supported ones, false-positive rate 0.2857 over
  benign scenarios), and the agentic layer is not exercised by those numbers
  (`docs/pilot.md:133-136`);
- that the agentic investigation stage works: it is wired
  (`src/itsm_agent/application/audit_consumer.py:79,193`) but off by default
  (`investigation_enabled: bool = False`), and the offline suite drives a
  fake model, not the LLM path.

No statement in this document should be read as "production ready". The
qualification is evidence about one CI run on one commit under simulators.

## Known limitations of this qualification

- The evidence table is manual. Nothing prevents an operator from recording
  a result that was not observed; the run URL and `headSha` are the audit
  anchor.
- `gh pr checks` may include non-required checks; only the required job set
  counts.
- Artifact retention is declared explicitly (30 days) but is still
  GitHub-configured; an expired artifact cannot be re-downloaded, and a
  qualified run whose artifacts expired is no longer reviewable. Record
  `expires_at` at qualification time. `sbom` and `dast-report` can be absent
  without failing their jobs; absence is an evidence gap, not a green
  artifact.
- The local `tools/ci_summary.py` recomputation cannot evaluate job
  conclusions without `NEEDS_RESULTS`; it is a report-integrity check, not a
  substitute for step 3.
- Branch protection verification requires repository admin access that an
  agent or contributor may not have.
- `main` requires **0** approving reviews (solo-maintained repository;
  GitHub does not let a PR author approve their own PR). The required-check
  gate is mechanical, not independent human review; raise it to **1** when an
  independent reviewer with write access exists.
- The protection policy was enabled on 2026-11-13, the same day as the
  qualified merge. The merge SHA, the run ID and the policy state are
  verifiable; the exact enablement time relative to the merge is not.
- DAST is required in `tools/ci_summary.py` (no default exemption). A
  skipped or failed DAST fails the CI summary and therefore the
  qualification.
