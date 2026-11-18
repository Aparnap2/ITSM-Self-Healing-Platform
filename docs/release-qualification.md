# Release qualification

This document defines what "release qualified" means for this repository,
how to prove it from CI evidence, and what a green pipeline still does not
prove. It is a companion to `docs/security-ci.md` and
`docs/production-readiness.md`; it is not a production-readiness claim.

## Status and scope

- Portfolio baseline: simulators only (Mockoon, Moto, the in-process
  infrastructure simulator). No real production data, credentials, or
  external SaaS mutations.
- **CI record for `f4b5640` (observed 2026-11-17).** The vehicle is PR #26
  (`fix/release-workflow-yaml` into `main`), squash-merged on 2026-11-17 as
  `f4b5640fba7294f18f8a4e14fd440f9809626ecb`. The `push` run `44016524854`
  on `main` has `headSha`
  `f4b5640fba7294f18f8a4e14fd440f9809626ecb`, event `push`, conclusion
  `success`, **15/15 jobs `success`, 0 failures**, created
  `2026-11-17T04:20:43Z` and completed `2026-11-17T04:25:22Z`. Re-running
  `tools/ci_summary.py` offline against that run's downloaded reports
  reproduces its verdict: **777 unique tests, 0 failures, 0 errors,
  0 skipped**, seven mandatory suites present, all fifteen required jobs
  `success`, no owner-marked optional job. Per-suite counts: unit 513,
  contract 55, security 45, integration 161, fault injection 20, scenarios
  24, e2e 12. Artifacts are unexpired and listed in the evidence table.
  **This record qualifies CI for `f4b5640` only.** It does not confer
  staging readiness or demo qualification on that commit, and it is not
  inherited by later commits. A later commit (`70e9220`) does hold both;
  see `docs/staging-demo-qualification.md`. Its CI evidence is a separate
  run (849 executions) and is not a re-use of the numbers above.
- **Superseded record (observed 2026-11-15).** The vehicle is PR #16
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
- **No inherited qualification.** Evidence is bound to one commit. `2ebd7ef`,
  `8a3cc60` and every earlier record in this document **do not** qualify
  `f4b5640`, and `f4b5640`'s record does not qualify any later commit. A
  merged change moves the baseline; the qualification must be re-run against
  the new merge commit. Reusing an older run's verdict, job list or test
  counts for a newer SHA is a disqualifier, not a shortcut.
- Re-verify before citing:
  `gh run view 44016524854 --json headSha,event,conclusion,jobs` and
  `gh api repos/<owner>/<repo>/actions/runs/44016524854/artifacts`.
  The superseded 2026-11-15 record is
  `gh run view 43672858417 --json headSha,event,conclusion,jobs`.
- A later run supersedes this record; a green `pull_request` run on the head
  branch is supporting evidence, not the qualified run.

## Qualification states

There are **two** qualification states, and they are not interchangeable.
Passing one does not imply the other, and neither is implied by a green CI
run or by merged code.

| State | Question it answers | Evidence required |
| --- | --- | --- |
| **`STAGING_READY`** | Can this commit be run as a staging deployment — one documented command, real PostgreSQL with migrations and the constrained runtime role, durable JetStream consumer, OIDC authentication with no HMAC bypass, secrets from the environment and absent from logs, and metrics/traces covering the main workflow? | A staging-equivalent stack brought up from the recorded commit, with the stack's own health output and the authentication path exercised over TLS. Component tests alone are necessary but not sufficient. |
| **`DEMO_QUALIFIED`** | Does one complete scenario run end to end with a real model and real reviewers: simulated CloudTrail ingestion → deterministic finding → grounded model investigation → evidence-reference validation → authenticated reviewer decision → independent verification by a second principal → reproducible retained report? | One retained, redacted rehearsal artifact that satisfies every disqualifier in "Rehearsal qualification" below, bound to the recorded commit SHA. |

A commit that is CI-qualified **and** `STAGING_READY` is a candidate for
`DEMO_QUALIFIED`; it is not `DEMO_QUALIFIED` until a rehearsal actually
succeeds and its artifact is retained.

### Status of `f4b5640`

Recorded 2026-11-17 against `f4b5640fba7294f18f8a4e14fd440f9809626ecb`.
Each row is judged on evidence that exists for **this** commit. "The tests
pass" is not evidence for a row that no test exercises.

**`CI_QUALIFIED` — PASS.** Run `44016524854`, 15/15 required jobs
`success`, 777 unique tests, artifacts unexpired (evidence table below).

**`STAGING_READY` — FAIL.** Not because a test failed, but because the
deployment path that would prove it does not exist in a staging-compatible
form: one criterion actively fails, and the rest have never been run as an
integrated deployment. Verdicts use only `PASS`, `FAIL`, `NOT RUN`,
`NOT APPLICABLE`.

| # | Criterion | Verdict | Evidence |
| --- | --- | --- | --- |
| 1 | One documented command starts the stack | **NOT RUN** | `make compose-up` exists (`Makefile:184`), but CI only runs `docker compose config -q` (`.github/workflows/ci.yml`, "Validate compose file"). The file is syntax-checked; the stack is never brought up and exercised. |
| 2 | Real PostgreSQL, migrations applied, constrained runtime role | **NOT RUN** | Proven at component level: `tests/integration/test_migration_safety.py` and `test_runtime_database_safety.py` pass against real PostgreSQL in CI. No deployment has been migrated and started. |
| 3 | Real JetStream with a durable consumer | **NOT RUN** | Proven at component level: the `integration` and `fault_injection` suites use a real broker and assert durable-consumer behaviour. No deployed consumer has been observed. |
| 4 | API health endpoints | **NOT RUN** | Health behaviour is exercised in `tests/integration/`; no running API has been probed. |
| 5 | Relay and audit consumer start and stop gracefully | **NOT RUN** | Proven at component level in `tests/fault_injection/test_interruption_and_timeout.py` (mid-stream interruption and drain). |
| 6 | Staging-compatible authentication (OIDC, no HMAC bypass) | **FAIL** | `compose.yaml:164` hardcodes `ITSM_ENV: local` and `compose.yaml:168` defaults `ITSM_AUTH_MODE` to `hmac`; `.env.example:44,49` ships the same. No compose service runs an OIDC provider. `src/itsm_agent/config.py:212` refuses `ITSM_AUTH_MODE=hmac` when `ITSM_ENV=staging`, so the documented stack cannot produce staging-compatible auth. |
| 7 | Secrets supplied by environment, absent from logs | **NOT RUN** | Compose requires secrets through `:?` interpolation and gitleaks + the redaction tests are green, but no deployment's logs have been inspected. |
| 8 | Worker restart neither loses nor duplicates durable processing | **NOT RUN** | Proven at component level by the fault-injection interrupt/drain tests. |
| 9 | Logs, metrics and traces cover the main workflow | **NOT RUN** | `tests/integration/test_telemetry_surface.py` asserts the served metric names, counters and timings, but nothing asserts spans reach a real OTLP collector (a stated CI gap), and no deployment's telemetry has been observed. |

Row 6 is the reason this is a **FAIL** rather than a "not yet verified"
bundle: the stack the repository documents as *the* way to start the platform
is a local HMAC stack. Wiring the identity simulator into `compose.yaml` with
`ITSM_ENV=staging`, and replacing the CI step that only validates compose
with one that brings the stack up and probes it, is the work that would move
row 6 — this is WP-I's `make demo-up` work, not a documentation change. Note
that the OIDC *implementation* is verified (the contract suite drives the
production `OIDCAuthenticator` over TLS with a pinned CA); what fails is that
no runnable stack serves it.

**`DEMO_QUALIFIED` — NOT RUN.** No rehearsal has executed against a live
stack with a real model at this commit or any commit in this milestone. What
exists is implementation plus offline tests: the runner is unit-tested, the
identity simulator's tokens are proven accepted by the production relying
party in the contract suite, and the evidence producer is integration-tested.
None of that is a rehearsal. There is no artifact in
`evals/reports/staging/` to judge, so no disqualifier check can be evaluated.

**Independent human review — NOT APPLICABLE.** The repository is
solo-maintained; `main` requires 0 approving reviews because GitHub does not
permit a PR author to approve their own PR. This is recorded, not waived.



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

The table below is the **2026-11-17 record** for
`f4b5640fba7294f18f8a4e14fd440f9809626ecb`, run `44016524854`
(`https://github.com/Aparnap2/ITSM-Self-Healing-Platform/actions/runs/44016524854`),
event `push` on `main`, attempt 1. Every row was re-inventoried from the run
on 2026-11-17; the test counts are the ones `tools/ci_summary.py` reported
when re-run offline against the downloaded reports, not counts copied from a
previous record.

| Gate | Job name | Result | Artifact / expiry | Notes |
| --- | --- | --- | --- | --- |
| Formatting and lint | Lint & Format | `success` | run `44016524854` | 04:20:46 → 04:20:57 |
| Static typing | Type Check (mypy --strict) | `success` | run `44016524854` | 04:20:46 → 04:21:03; `mypy --strict` clean on 189 source files locally |
| Secret scanning | Secret Scan (gitleaks) | `success` | `gitleaks-results.sarif`, expires 2027-02-15 | no finding |
| Workflow security | Workflow Security (zizmor) | `success` | run `44016524854` | **does not validate workflow YAML syntax** — see the defect note below |
| Supply chain, SAST, SBOM | Supply Chain (pip-audit, bandit, SBOM) | `success` | `sbom`, expires 2026-12-17 | Bandit/pip-audit/Trivy clean |
| Build and compose | Build & Compose Config | `success` | `image-digest`, expires 2026-12-17 | validates `docker compose config`; does **not** start the stack |
| DAST | DAST (OWASP ZAP baseline, isolated target) | `success` | `dast-report`, expires 2026-12-17 | no FAIL rule |
| Unit tests | Unit Tests | `success` | `unit-junit`, expires 2026-12-17 | 513 tests, 0 failed |
| Contract tests | Contract Tests (simulators, offline) | `success` | `contract-junit`, expires 2026-12-17 | 55 tests, 0 failed; includes the identity simulator's tokens being accepted by the production relying party |
| Security invariants | Security Invariant Tests | `success` | `security-junit`, expires 2026-12-17 | 45 tests, 0 failed |
| Integration | Integration Tests | `success` | `integration-junit`, expires 2026-12-17 | 161 tests, 0 failed; includes the migration harness against real PostgreSQL |
| Fault injection | Fault Injection Tests | `success` | `fault-injection-junit`, expires 2026-12-17 | 20 tests, 0 failed |
| E2E | E2E Tests | `success` | `e2e-junit`, expires 2026-12-17 | 12 tests, 0 failed |
| Scenario harness | Scenario Harness | `success` | `scenarios-junit`, expires 2026-12-17 | 24 tests, 0 failed |
| Summary | CI Verification Summary | `success` | run `44016524854` | **777 unique tests, 0 failures, 0 errors, 0 skipped**, 0 missing groups, 0 non-success required jobs, no owner-marked optional job |
| Run binding | `headSha` = `f4b5640fba7294f18f8a4e14fd440f9809626ecb` | `success` | run `44016524854` | event `push` on `main`, attempt 1 |

Local corroboration at the same commit (`make verify`, real PostgreSQL on
5544 and NATS on 4224, `ITSM_TEST_STRICT=1`): exit `0`; 830 test executions
(unit 513, contract 55, security 45, fault injection 20, integration 161,
scenarios 24, e2e 12), 0 failures — 777 unique tests once the suites that
carry multiple markers are de-duplicated, matching CI. `ruff format --check`
245 files; `ruff check` clean; `mypy --strict` clean on 189 files; Bandit
clean.

**Defect observed during this record (kept as an engineering lesson).** At
`8a3cc60`, `release.yml` did not parse — an unquoted colon in a job's
`name:` — and GitHub reported it as a jobless *failure* run named after the
file path rather than as a CI failure. No gate caught it: `zizmor` checks
security properties of workflows, not YAML validity, and no job runs
`actionlint`. It was fixed in `f4b5640` (this commit). Adding a workflow-YAML
validation step is a **future CI change** and must go through the same
explicit gate-policy process; this record does not alter the 15-gate set to
accommodate it. Until then, **a green `Workflow Security` job is not evidence
that a workflow file parses.**

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

## Rehearsal qualification (staging and demo track)

This section defines `DEMO_QUALIFIED` independently of CI. A rehearsal
artifact is judged **against this list only**, not against the author's
description of it. If a required field is absent, the artifact does not
qualify — an absent field is a failure, not a note.

### What a qualifying rehearsal artifact must contain

The artifact is the report written by `tools/e2e_staging_run.py` to
`evals/reports/staging/staging-run-<run-id>.json` (SOP-06). It must carry:

1. **`git_sha`** — the commit the rehearsal ran against, and it must equal the
   commit being qualified.
2. **`run_id`** and the report's own generation timestamp.
3. **`credential_mode`** — `oidc`, `token`, or `hmac`. A staging rehearsal is
   `oidc`; an `hmac` artifact is a local run and cannot qualify a staging
   claim.
4. **Source event identity** — source-event id and payload hash — and the
   **finding** id with its detection outcome.
5. **Model identity** — model id, model version, prompt version, the number of
   model calls made, and the latency observed.
6. **Request/proposal identifiers** and the **evidence-validation outcome**
   (grounding).
7. **Both reviewer identities** and their decisions, each a distinct
   principal.
8. **Final finding status**, which must be `VERIFIED`.
9. The **bundle retrieval result**, which must be a 200.
10. The explicit **"does not prove"** list, so the artifact cannot be read as
    a broader claim than it is.
11. **No secret.** No API key, bearer token, HMAC secret, DSN password, or
    model-debug dump. The report path is sanitised before it is written.

### Disqualifying conditions

Any one of these makes the rehearsal **not qualified**. Do not average, do
not waive, do not describe it as "passed with notes".

- The artifact's `git_sha` is not the commit under qualification, or the
  rehearsal did not run against a recorded SHA at all.
- The evidence bundle was not retrieved (non-200), or the bundle is empty.
- The proposal cited an evidence id that was **outside** the snapshot, or one
  that does not resolve to a persisted, tenant-scoped `evidence_references`
  row.
- The model made **more calls than the budget** (hard cap 3). Retries beyond
  the cap are a disqualifier, not a demonstration of resilience.
- The two reviewers were **not distinct principals**, or a principal
  transitioned the finding to `VERIFIED` on its own work. The policy refuses
  self-verification; a rehearsal that works around that refusal does not
  qualify.
- The **finding status was changed by the model**, or by anything other than
  an authenticated reviewer transition.
- **A secret appeared** in the artifact, the logs, the trace, or an audit
  payload.
- The artifact is **not reproducible**: the commands in SOP-06, run against
  the same commit on a clean stack, do not produce an artifact with the same
  required fields.
- The final status is not `VERIFIED`, or the incident was marked resolved
  without independent postcondition verification.
- The rehearsal ran against a **different model** than the one recorded, or
  the model identity is absent.
- The report was **hand-edited** after the run without a re-run; the artifact
  must be machine-produced.

### Judging an artifact from this document alone

1. Open the JSON. Check `git_sha` equals the commit being qualified. If it
   does not, stop — the artifact belongs to another commit and qualifies
   nothing.
2. Check `credential_mode`. A staging claim requires `oidc`.
3. Check `model_calls <= 3`.
4. Check the reviewer block: two entries, distinct `sub` values, decisions
   `RESOLVED` then `VERIFIED`, in that order.
5. Check `bundle_status == 200`.
6. Check the grounding block: failures empty, and every cited evidence id
   present in the snapshot.
7. Check `final_status == "VERIFIED"`.
8. Scan for `secret`, `token`, `password`, `api_key`, `authorization` values
   that are non-empty. Any hit is a disqualifier and must be treated as an
   incident, not a documentation bug.
9. If every check passes, record `DEMO_QUALIFIED` **for that SHA only**.

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

The payload can be recovered, which removes the need to trust the summary
page. The summary job echoes it, so it is recoverable from the job log:

```sh
gh run view --job <ci-summary-job-id> --log > /tmp/ci-summary.log
python3 - <<'PY'
import io, json, re
lines = io.open("/tmp/ci-summary.log", encoding="utf-8").read().splitlines()
fixed = []
for ln in lines:
    ln = re.sub(r"^CI Verification Summary\t[^\t]*\t", "", ln)
    ln = re.sub(r"^\ufeff?\d{4}-\d\d-\d\dT[\d:.]+Z ", "", ln)
    fixed.append(ln)
start = next(i for i, l in enumerate(fixed) if l.strip().startswith("NEEDS_RESULTS:"))
buf, depth = ["{"], 1
for l in fixed[start + 1:]:
    buf.append(l)
    depth += l.count("{") - l.count("}")
    if depth == 0:
        break
io.open("/tmp/needs.json", "w").write(json.dumps(json.loads("\n".join(buf))))
PY
uv run python tools/ci_summary.py --reports /tmp/qual-flat \
  --sha <merge-sha> --run-id <run-id> --run-attempt 1 --head-sha "" \
  --retention-days 30 --max-skipped 0 \
  --needs-json "$(cat /tmp/needs.json)"
```

This reproduces the full verdict — required-job table, per-suite counts and
the qualification line — from downloaded artifacts plus the run's own
payload. It is how the `f4b5640` record above was produced: an exit code of
`0` and no "not qualified" line is the check.

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
  conclusions without `NEEDS_RESULTS`. The payload is recoverable from the
  summary job's log (step 5), so a full replay is possible; it still proves
  report integrity and job conclusions, not that those jobs tested the right
  thing.
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
- **The `Workflow Security` gate does not prove a workflow parses.**
  `zizmor` checks security properties; there is no `actionlint` step. A
  syntax-invalid workflow is reported by GitHub as a jobless failure run
  named after the file path, which no gate reads. Observed at `8a3cc60` and
  fixed in `f4b5640`. Adding YAML validation is a tracked, deliberate future
  CI change — not part of this record, and not a reason to weaken the
  existing 15 gates.
- **Detection is narrowed by a declared privilege gap.** There is no
  PostgreSQL privilege rule in the detection engine, so the
  `mal-pg-alter-role-superuser` scenario is declared `"known_gap": true` in
  `evals/datasets/pilot_scenarios.json` and excluded from the rule-supported
  recall figure. Recall on that scenario is not measured and must not be
  inferred from the pilot's overall numbers.
- **No load test and no throughput gate.** Concurrency is asserted for
  *correctness* only (`tests/integration/test_concurrency_load.py`): the same
  event delivered concurrently is stored and processed exactly once. No
  latency, throughput, or capacity claim is made or gated. A green run says
  nothing about behaviour under production load.
- **No trace-export assertion against a real collector.** Spans are verified
  in-process and the API's metric endpoint is asserted
  (`tests/integration/test_telemetry_surface.py`), but no test asserts that
  spans actually reach an OTLP collector. A broken exporter configuration
  would not fail CI.
- **Single-node infrastructure only.** PostgreSQL, NATS and the application
  are each a single instance in CI. No failover, leader election, partition
  behaviour, or broker-cluster recovery is tested. `docs/nats-stream-config.md`
  states the single-node scope.
- **Nothing here is a production-readiness claim.** This record covers
  `f4b5640`. A later, separate record
  (`docs/staging-demo-qualification.md`) does bring up a local
  staging-equivalent stack from a later commit and run one rehearsal with a
  real model; it is explicitly *not* a cloud staging environment, and it
  still makes no production-readiness claim. Read that document for the
  demo verdicts; read this one for what the CI suite itself establishes.
- **No independent human review has occurred.** Every approval in this
  repository's history is the author's. GitHub forbids self-approval, so the
  "two-reviewer" workflow is exercised only by the *application's* simulated
  identities, never by two independent humans on the PR.
