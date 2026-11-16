# The CI pipeline, job by job

This document is the readable contract for `.github/workflows/ci.yml`. It
answers three questions for every job:

1. **What does this job actually prove?**
2. **How could it pass without proving anything?**
3. **Does its failure block a merge?**

The standard the pipeline is held to is *explicit, not toy-grade*: every gate
states what it proves, every step fails loudly, no step can pass vacuously,
and a reader can tell from the workflow alone what is required for a merge.

- The release path is documented in [`release-path.md`](release-path.md).
- The local `act` runner is documented in [`act-local-ci.md`](act-local-ci.md).
- The qualification record for a specific commit is
  [`../release-qualification.md`](../release-qualification.md).

---

## 1. The required set: all 15 jobs

`tools/ci_summary.py` names the required set explicitly in `REQUIRED_JOBS`:

```text
lint  typecheck  secret-scan  workflow-security  supply-chain
unit-tests  contract-tests  security-invariants  build  dast
integration-tests  fault-injection-tests  e2e-tests  scenarios
ci-summary
```

**Every one of them is required.** The summary compares that list against the
workflow's `needs` payload, so:

- a required job that is **absent** from the payload (it never ran) fails;
- a required job that did not reach `success` — `failure`, `cancelled`,
  `timed_out`, `skipped`, `stale` — fails;
- a job that appears in the payload but is **not** in `REQUIRED_JOBS` fails,
  because the required set must be changed deliberately.

### Is DAST required? Yes.

**A DAST failure blocks the merge.** There is no exemption:

- `dast` is one of the 15 required status checks on `main`;
- a DAST failure makes the `ci-summary` job fail, which is itself a required
  status check.

`tools/ci_summary.py` has a `--optional-jobs` escape hatch, but **its default
is empty**. The only way to relax a gate is for the owner to name the job
explicitly, and the summary always prints the list of owner-marked optional
jobs so a reader can see the relaxation in the evidence itself.

---

## 2. Job by job

| # | Job id | Check name | What it proves | How it could pass vacuously | Blocks a merge? |
| --- | --- | --- | --- | --- | --- |
| 1 | `lint` | Lint & Format | The tree is formatted (`ruff format --check`) and free of lint findings (`ruff check`). | Not vacuous: both commands exit non-zero on a violation, and they run over the whole repository. | Yes |
| 2 | `typecheck` | Type Check (mypy --strict) | `mypy --strict` passes over `src/` and `tests/`. | Not vacuous. **Known gap:** `tools/` is not in the mypy path, so `tools/ci_summary.py` is lint- and format-checked but not type-checked by CI. | Yes |
| 3 | `secret-scan` | Secret Scan (gitleaks) | No secret-shaped literal exists in the commit history (`fetch-depth: 0`). | Not vacuous: gitleaks fails the job on a finding. | Yes |
| 4 | `workflow-security` | Workflow Security (zizmor) | The workflows themselves have no medium/high-confidence finding (`advanced-security: "false"` makes findings blocking). | Not vacuous: `advanced-security: false` is what makes zizmor fail the job instead of only uploading SARIF. | Yes |
| 5 | `supply-chain` | Supply Chain (pip-audit, bandit, SBOM) | No known vulnerability in the locked manifest (`pip-audit`), no SAST finding in `src/` (`bandit`), no CRITICAL/HIGH fixable IaC/Dockerfile/secret finding (`Trivy fs`), and a CycloneDX SBOM exists. | Not vacuous: all three scanners are configured to exit non-zero. The SBOM upload is supporting evidence only (`if-no-files-found: warn`). | Yes |
| 6 | `unit-tests` | Unit Tests | The `unit` marker selection passes. | Guarded: the `guard-collect` preflight fails when the selection collects zero tests; the summary fails when the report is missing, empty, has zero tests, or skipped every test. | Yes |
| 7 | `contract-tests` | Contract Tests (simulators, offline) | The `contract` marker selection passes against the offline simulators (moto/respx). | Guarded exactly like `unit-tests`. | Yes |
| 8 | `security-invariants` | Security Invariant Tests | The `security` marker selection passes against a live PostgreSQL and NATS. | Guarded, and fail-closed: `ITSM_TEST_STRICT=1` plus an explicit service-readiness wait, so an unreachable service is a red job, not a skip. | Yes |
| 9 | `build` | Build & Compose Config | `docker compose config` resolves, the image builds from the `Dockerfile`, and the image has no CRITICAL/HIGH fixable vulnerability, secret, or Dockerfile misconfiguration. | Not vacuous: a missing `Dockerfile` is an explicit error, and the container scan is unconditional. | Yes |
| 10 | `dast` | DAST (OWASP ZAP baseline, isolated target) | The application, behind its real middleware, does not trip a configured FAIL rule in `ci/zap-baseline.conf`. | Not vacuous: `tools/dast.sh` exits non-zero when the target is unreachable or Docker is missing; it never skips silently. | **Yes — required.** |
| 11 | `integration-tests` | Integration Tests | The `integration` marker selection passes against real PostgreSQL, NATS, and the Mockoon simulator. | Guarded and fail-closed (strict mode + service-readiness wait). | Yes |
| 12 | `fault-injection-tests` | Fault Injection Tests | The `fault_injection` marker selection passes against real PostgreSQL and NATS. | Guarded and fail-closed. | Yes |
| 13 | `e2e-tests` | E2E Tests | The `e2e` marker selection passes against real PostgreSQL and the Mockoon simulator. | Guarded and fail-closed. The job now waits for PostgreSQL as well as the simulator, so the one hand-rolled skip in the suite (`test_db_backed_dedup_live_stack`) cannot hide behind a down database. | Yes |
| 14 | `scenarios` | Scenario Harness | The deterministic `scenarios` marker selection passes. | Guarded exactly like `unit-tests`. | Yes |
| 15 | `ci-summary` | CI Verification Summary | The evidence set is complete, non-vacuous, bound to this run, and every required job succeeded. | Not vacuous: it runs `if: always()` and fails on a missing job, a missing/empty/zero-test report, a failure/error, a silent skip, a stale provenance stamp, or an undeclared retention window. | Yes |

---

## 3. No vacuous passes

Three independent mechanisms stop a job from being green without having
proved anything.

**a. The collect preflight (`make guard-collect`).** Every test target runs
the marker selection through `pytest --collect-only` first. pytest exits 5
when a selection matches nothing; the guard turns that into an explicit
failure and records the collected count in `reports/<suite>.collect.txt`:

```make
test-unit:
	$(MAKE) --no-print-directory guard-collect PYTEST_MARKER=unit PYTEST_SUITE=unit-junit
	uv run pytest -m unit $(PYTEST_OPTS)
```

**b. The report checks in the summary.** For each of the seven mandatory
reports the summary fails when the report is missing, is 0 bytes, is not
parseable XML, has `tests == 0`, has `executed == 0` (every test skipped), or
skips more tests than `--max-skipped` allows (default: 0).

**c. The collect/report cross-check.** The summary compares the collected
count in `<suite>.collect.txt` with the test count in the JUnit report. A
report that contains more tests than were collected fails.

### Service-backed suites fail closed

Every job that needs PostgreSQL or NATS sets `ITSM_TEST_STRICT=1`, which
turns "service unreachable" from a skip into a failure
(`tests/conftest.py`). All seven pytest jobs set it, so a future
service-backed unit test fails loudly instead of disappearing into a skip.

In addition, the jobs that start services **assert the service is reachable
before the suite runs** (bounded 30 s wait, `exit 1` on timeout). That closes
the one gap strict mode cannot close on its own: a hand-written
`pytest.skip("service unreachable")` inside a test body.

---

## 3a. Coverage: which category runs where

`tools/ci_coverage.py` is the mechanical check of this table, and it runs as
a step in the CI Verification Summary job — so a suite that exists but is not
executed by any job fails the pipeline.

| Suite | CI job | What it proves |
|---|---|---|
| `unit` | `unit-tests` | pure domain, policy and contract logic; no network, no services |
| `contract` | `contract-tests` | adapters against the simulators (Moto/Mockoon) and offline stubs |
| `security` | `security-invariants` | tenant isolation, RLS and privilege invariants against real PostgreSQL |
| `fault_injection` | `fault-injection-tests` | deterministic failure paths: redelivery, DLQ, interruption, timeout |
| `integration` | `integration-tests` | full stack against real PostgreSQL and NATS JetStream |
| `scenarios` | `scenarios` | the 24-scenario audit harness (offline, deterministic) |
| `e2e` | `e2e-tests` | end-to-end verification against the live stack |

Coverage that lives inside those suites rather than in a job of its own:

- **PostgreSQL-backed behaviour** — the integration, security and
  fault-injection suites, plus the telemetry and concurrency tests in the
  integration suite.
- **Authentication and authorization** — the auth/RBAC, OIDC and tenant
  isolation tests live in the unit and integration suites.
- **Infrastructure mocks** — the contract suite runs against the simulators;
  the e2e suite runs against the live stack (real PostgreSQL, NATS and the
  Mockoon simulator container).
- **Telemetry** — the metrics/tracing surface is asserted in the integration
  suite (`tests/integration/test_telemetry_surface.py`): the API serves the
  documented metric names, counts requests, times them, and counts failures.

### Categories that are NOT gated (stated, not implied)

- **No throughput or latency benchmark.** The concurrency test
  (`tests/integration/test_concurrency_load.py`) asserts exactly-once
  behaviour under concurrent delivery — correctness, never speed. A latency
  assertion on a shared runner is a flake, not a gate.
- **No trace-export assertion against a real OTLP collector.** Spans are
  verified in-process; the collector path is exercised only by the stack.
- **No load test against the public API surface.** The webhook is exercised
  at the ingestion boundary.
- **No multi-node NATS or PostgreSQL failover.** The services are single-node.

Run the check locally:

```sh
uv run python tools/ci_coverage.py
```

## 4. Artifacts, retention and provenance

### The seven mandatory reports

| Artifact | Produced by | Contents | Retention |
| --- | --- | --- | --- |
| `unit-junit` | `unit-tests` | `unit-junit.xml`, `unit-junit.collect.txt`, `unit-junit.meta` | 30 days |
| `contract-junit` | `contract-tests` | `contract-junit.xml`, `contract-junit.collect.txt`, `contract-junit.meta` | 30 days |
| `security-junit` | `security-invariants` | `security-junit.xml`, `security-junit.collect.txt`, `security-junit.meta` | 30 days |
| `integration-junit` | `integration-tests` | `integration-junit.xml`, `integration-junit.collect.txt`, `integration-junit.meta` | 30 days |
| `fault-injection-junit` | `fault-injection-tests` | `fault-injection-junit.xml`, `fault-injection-junit.collect.txt`, `fault-injection-junit.meta` | 30 days |
| `scenarios-junit` | `scenarios` | `scenarios-junit.xml`, `scenarios-junit.collect.txt`, `scenarios-junit.meta` | 30 days |
| `e2e-junit` | `e2e-tests` | `e2e-junit.xml`, `e2e-junit.collect.txt`, `e2e-junit.meta` | 30 days |

Supporting artifacts (not mandatory, absence is an evidence gap, not a red
job): `sbom`, `dast-report`, `image-digest`.

The retention window is declared once, at the top of the workflow:

```yaml
env:
  ARTIFACT_RETENTION_DAYS: 30
```

The summary prints the expiry it derives from that value and **fails when the
window was not declared**, so the window cannot be inherited silently from a
repository default that later changes.

### Provenance: a stale artifact cannot be presented as this run's evidence

Each test job stamps the report with the identity of the run that produced it
(`make ci-stamp`):

```text
sha=<commit>
run_id=<workflow run id>
run_attempt=<workflow run attempt>
job=<workflow job id>
```

The summary verifies that stamp against the commit, run and attempt it was
invoked with. A report from an earlier run, a re-run attempt, or a different
commit fails the summary with *"the report does not belong to this run"*.

This is the answer to "can the workflow pass with a stale or wrong
`headSha`?": **no.** The summary binds the evidence to one commit, one run
and one attempt, and prints all three plus the PR head SHA.

---

## 5. Reproducing a gate locally

Every gate in CI is a `make` target, and the CI workflow calls those same
targets. The commands below are the exact ones CI runs.

### Fast, offline, no services

```sh
make verify-fast
```

which is:

```sh
make format-check   # ruff format --check .
make lint           # ruff check .
make typecheck      # mypy --strict over src/ and tests/
make test-unit      # pytest -m unit   (with the collect preflight)
make test-contract  # pytest -m contract
make sast           # bandit over src/
```

No Docker, no PostgreSQL, no NATS, no network.

### Full, needs the local stack

```sh
make compose-up     # docker compose up -d --wait
make verify         # format, lint, typecheck, all seven suites, sast
make compose-down
```

`make verify` runs every pytest suite, so it needs PostgreSQL and NATS. It
does not run `audit-deps` (network) and it does not run the Trivy scans
(container-level). Those live in CI only.

### Strict, CI-equivalent

```sh
make verify-ci
```

which is `verify` plus `test-fault-injection`, with `ITSM_TEST_STRICT=1`
forced on every suite so an unreachable service fails instead of skipping.

### One gate at a time

```sh
make format-check
make lint
make typecheck
make sast
make audit-deps        # needs network
make test-unit PYTEST_OPTS='--junitxml=reports/unit-junit.xml'
make test-security PYTEST_OPTS='--junitxml=reports/security-junit.xml'
```

### The summary, by hand

```sh
python3 tools/ci_summary.py --help
python3 tools/ci_summary.py \
  --reports reports \
  --sha "$(git rev-parse HEAD)" \
  --run-id local \
  --run-attempt 1 \
  --retention-days 30 \
  --no-require-needs
```

`--no-require-needs` is only for a local re-computation: job conclusions are
only available inside the workflow (`NEEDS_RESULTS`). A local run still
checks report presence, non-emptiness, non-vacuity, the collect cross-check
and the retention declaration.

### The pre-push gate

```sh
make hooks-install   # once per clone: git config core.hooksPath .githooks
make verify-pre-push
```

The hook runs the fast, service-free gates only. See
[`act-local-ci.md`](act-local-ci.md) for the bounded local Actions runner.

---

## 6. Supply-chain hygiene

- Every third-party action is pinned to a **commit SHA**, never a tag.
- Every job declares its own least-privilege `permissions:` block:
  `contents: read` everywhere, plus `pull-requests: read` for `secret-scan`
  (gitleaks lists PR commits) and `actions: read` for `ci-summary` (it
  downloads this run's artifacts).
- Every job has a `timeout-minutes`.
- Concurrency is grouped per workflow and ref. PR runs cancel superseded PR
  runs; **main-branch runs are never cancelled**, so the verification for a
  tagged commit always completes.
- No `continue-on-error`, no `|| true` on a gate, no `if: false` gate. The
  `|| true` occurrences in the workflow are limited to diagnostic commands in
  cleanup steps (`docker rm -f`, `docker logs`) whose failure cannot mask a
  result.

---

## 7. What a green pipeline does not prove

A green run proves that these checks ran and reported success. It does not
prove that the change is correct, that the coverage is meaningful, or that a
deployed system behaves like the test double. See
[`../release-qualification.md`](../release-qualification.md) for the
disqualifying conditions and [`../security-ci.md`](../security-ci.md) for the
DAST and container-hardening scope.
