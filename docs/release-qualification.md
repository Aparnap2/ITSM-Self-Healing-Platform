# Release qualification

This document defines what "release qualified" means for this repository,
how to prove it from CI evidence, and what a green pipeline still does not
prove. It is a companion to `docs/security-ci.md` and
`docs/production-readiness.md`; it is not a production-readiness claim.

## Status and scope

- Portfolio baseline: simulators only (Mockoon, Moto, the in-process
  infrastructure simulator). No real production data, credentials, or
  external SaaS mutations.
- The vehicle for this qualification was the merge of PR #9
  (`feat/access-audit-foundation` into `main`), squash-merged on 2026-11-06 as
  `57c9d8cd049dd243d13c7610c5fe75270a687af2`.
- **Recorded qualification (observed 2026-11-06).** The `push` run
  `42214887310` on `main` has `headSha`
  `57c9d8cd049dd243d13c7610c5fe75270a687af2`, event `push`, conclusion
  `success`, and all 15 jobs `success`. Its summary reports **444 unique
  tests, 0 failures + errors, 0 skipped**, and all seven mandatory JUnit
  artifacts are present and unexpired. This satisfies items 1-5 below. Item 6
  is **not** satisfied: `main` has no branch protection, so repository
  governance remains an unverified gap.
- Re-verify before citing:
  `gh run view 42214887310 --json headSha,event,conclusion,jobs` and
  `gh api repos/<owner>/<repo>/actions/runs/42214887310/artifacts`.
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
   run and are not expired at review time. `sbom` and `dast-report` are
   supporting evidence: they are uploaded with `if-no-files-found: ignore`
   and `warn` respectively (`.github/workflows/ci.yml:131-137,353-359`), so
   their absence does not fail CI. If either is missing, record it as an
   evidence gap rather than calling the run fully evidenced.
5. **No weakened gates.** The workflow and summary tooling at the merge SHA
   still contain every required job and the same mandatory report list; no
   `continue-on-error`, no `if: false`, and no new optional job that bypasses
   the summary.
6. **Branch protection, if configured.** If `main` has protection, it must
   require the CI checks, require an up-to-date branch, and forbid force
   pushes/deletions, and the merge must satisfy it. This repository currently
   has no branch protection configured (verified 2026-11-06). Record that as
   an unverified repository-governance gap, not as a pass, and do not
   describe repository governance as qualified.

The release decision is recorded by filling the evidence table in this
document and attaching it to the PR or release ticket.

## Required gates

The required set is the `ci-summary` `needs` list in
`.github/workflows/ci.yml:696-710`, plus `ci-summary` itself. `dast` is
allowed to be `skipped` by `tools/ci_summary.py` (`--optional-jobs` defaults
to `dast`, `tools/ci_summary.py:119-123`), but this qualification treats a
skipped DAST as **not qualified** unless the skip is explicitly approved and
recorded in the Notes column.

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

Sources: `.github/workflows/ci.yml:35-729`, `tools/ci_summary.py:23-31,74-101`,
`docs/security-ci.md:7-28`.

## Evidence table

Fill this in from the qualified run. Use `success` / `failure` / `skipped` /
`cancelled` exactly as GitHub reports it. Do not paraphrase a result into
"green".

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
  "Required job(s) did not succeed — this run is not qualified."
  (`tools/ci_summary.py:172-175`).
- Any of the seven mandatory JUnit reports is missing:
  `unit-junit.xml`, `contract-junit.xml`, `security-junit.xml`,
  `integration-junit.xml`, `fault-injection-junit.xml`,
  `scenarios-junit.xml`, `e2e-junit.xml` (`tools/ci_summary.py:23-31`).
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
- Branch protection is configured and the merge violates it. Absence of
  protection is recorded as a governance gap (see item 6), not as a code-gate
  pass.
- A secret appears in the diff, logs, artifacts, or audit payloads.

## How to verify

Use `<run-id>`, `<merge-sha>`, and `<owner>/<repo>` placeholders. Never
paste a real token into a ticket.

### 1. Resolve the merge commit

```sh
gh pr view 9 --json number,state,mergeCommit,headRefOid,mergeStateStatus,url
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
gh pr checks 9 --json name,state,bucket,link
```

### 4. Inventory artifacts and retention

```sh
gh api "repos/<owner>/<repo>/actions/runs/<run-id>/artifacts" \
  --jq '.artifacts[] | {name, size_in_bytes, expired, expires_at}'
```

Expected artifact names: `sbom`, `dast-report`, `unit-junit`,
`contract-junit`, `security-junit`, `integration-junit`,
`fault-injection-junit`, `e2e-junit`, `scenarios-junit`
(`.github/workflows/ci.yml`).

### 5. Download and re-check the JUnit set

```sh
mkdir -p reports/qualification
gh run download <run-id> -p '*-junit' -D reports/qualification
find reports/qualification -name '*-junit.xml' -exec cp {} reports/qualification/ \;
python3 tools/ci_summary.py --reports reports/qualification --sha <merge-sha>
```

`gh run download` extracts each artifact into its own directory; the `cp`
step flattens them for `tools/ci_summary.py`, which expects the seven filenames in
one directory (`tools/ci_summary.py:129-136`).

The local recomputation cannot see job conclusions: `NEEDS_RESULTS` is only
populated inside the workflow (`ci.yml:725-729`). Use step 3 for job results
and the run's summary page for the authoritative `ci-summary` output.

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
         enforce_admins: .enforce_admins.enabled,
         force_pushes: .allow_force_pushes.enabled,
         deletions: .allow_deletions.enabled}'
```

A `403` here means the caller lacks admin access; record that as an
unverified item, not as a pass.

## Where the summary comes from

`ci-summary` runs `tools/ci_summary.py` with `--reports reports` and
`--sha "$GITHUB_SHA"` (`.github/workflows/ci.yml:723-729`). It:

- requires all seven JUnit reports (`EXPECTED_REPORTS`);
- sums failures, errors, and skips per report;
- checks `NEEDS_RESULTS` and fails when any required job is not `success`
  (only `dast` is optional by default);
- writes a Markdown table to `GITHUB_STEP_SUMMARY`, which renders on the
  run's summary page;
- exits non-zero on a missing report, a failure/error, or a non-success
  required job (`tools/ci_summary.py:144-184`).

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
  implemented; Mockoon is the acceptance connector (`README.md`).

No statement in this document should be read as "production ready". The
qualification is evidence about one CI run on one commit under simulators.

## Known limitations of this qualification

- The evidence table is manual. Nothing prevents an operator from recording
  a result that was not observed; the run URL and `headSha` are the audit
  anchor.
- `gh pr checks` may include non-required checks; only the required job set
  counts.
- Artifact retention is GitHub-configured; an expired artifact cannot be
  re-downloaded, and a qualified run whose artifacts expired is no longer
  reviewable. Record `expires_at` at qualification time. `sbom` and
  `dast-report` can be absent without failing their jobs; absence is an
  evidence gap, not a green artifact.
- The local `tools/ci_summary.py` recomputation cannot evaluate job conclusions
  without `NEEDS_RESULTS`; it is a report-integrity check, not a substitute
  for step 3.
- Branch protection verification requires repository admin access that an
  agent or contributor may not have.
- DAST is optional in `tools/ci_summary.py` but treated as required here. If it is
  skipped, the run is not qualified unless the skip is explicitly approved
  and recorded.
