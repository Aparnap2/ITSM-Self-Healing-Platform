# Staging & Full E2E Demo Qualification — implementation plan (DRAFT for review)

_Status: draft plan, not approved work. Nothing here has been executed.
Baseline: `main` at `f38f6eb` (PRs #15/#16/#17 merged; `main` push CI 15/15 on
`f38f6eb`). This plan was written from a read-only audit of the repository, not
from memory; every "exists today" claim below carries a file reference._

---

## 0. Why this milestone exists, and what it is not

The platform has a qualified CI baseline but **no demonstration evidence**: the
agentic path has never run against a real model with real evidence and an
authenticated human reviewer. This plan closes that gap without adding new
product surface.

Two gates, deliberately not conflated:

| Gate | Meaning |
| --- | --- |
| **Staging-ready** | The environment starts from a clean state, uses the intended authentication mechanism, and can run a real-model investigation. |
| **Demo-qualified** | One complete business scenario runs end to end — ingestion → detection → grounded investigation → evidence validation → authenticated review → independent verification → reproducible report — with retained evidence. |

A successful model API call is **not** a successful workflow. A green pipeline
is **not** a demonstration. This plan produces the second, and records the
first.

**Explicitly out of scope** (per the milestone definition): public cloud
hosting, Kubernetes, real customer integrations, production AWS accounts, SIEM
functionality, automatic access revocation, 100% detection recall, and a
production IdP deployment. The PostgreSQL privilege-detection gap stays
documented and visible; it must not be hidden or presented as solved.

---

## 1. Audit summary — what already exists

Verified by audit (file references are load-bearing):

| Work package | State | Evidence |
| --- | --- | --- |
| Finding lifecycle + append-only ledger + independence rule | **DONE** | `domain/finding_lifecycle.py:54-194`, `migrations/015_findings_lifecycle.sql`, `api/rbac.py:83-93` |
| Bundle endpoint + API composition | **DONE** | `api/routes/findings.py:429-454`, `api/__main__.py:104-105` (wired in PR #16) |
| Evidence-grounded investigation (source-event snapshot, request-scoped resolver, redaction) | **DONE** | `application/audit_consumer.py:38-78,105-107`, `investigations/service.py:60,207-229` |
| Out-of-snapshot reference rejection | **DONE** | `investigations/orchestrator.py:50-54` → ledger `FAILED` (`service.py:161-172`) |
| Groq adapter (proposes only, key scrubbed, schema re-validated) | **DONE** | `investigations/groq_model.py:44-77,170-186,221-225` |
| Packaged audit consumer + staging runner + budget (3 calls, no retry) | **DONE** | `workers/audit_consumer.py`, `tools/e2e_staging_run.py:193-238,451` |
| Failure/recovery coverage | **7 of 9 scenarios COVERED** | see §5 |
| Qualification mechanics for CI | **DONE** | `docs/release-qualification.md:55-196`, 15 job names in `.github/workflows/ci.yml` |

### The four blockers that decide the shape of this plan

1. **No identity provisioning path.** `reviewer_authorizations` has a reader
   (`api/oidc.py:112-134`) and **no writer in application code**; the runtime
   role is explicitly forbidden from writing it
   (`migrations/010_runtime_role.sql:65-69`, `privileges.py:88,250-255`).
   The only path today is manual admin SQL in `docs/runbooks/SOP-05:110-126`.
2. **No staging credential can be obtained.** The runner mints an HMAC token
   (`tools/e2e_staging_run.py:498-503`) and *requires* `ITSM_AUTH_HMAC_SECRET`
   in preflight (`:105`), while `config.py:199-201` refuses HMAC in staging
   and the OIDC relying party never accepts an HMAC token
   (`api/oidc.py:352-393`). There is no token endpoint, client-credentials
   helper, or IdP/JWKS stub anywhere in the repository.
3. **No producer for `evidence_references`.** The table has a reader only
   (`repositories.py:1238-1241`); the sole INSERT in the repo is a test
   (`tests/integration/test_findings_api.py:81`). A real proposal can
   therefore cite **only the source-event id**, and the evidence bundle
   returned to a reviewer would be empty.
4. **Observability is declared but inert.** `observe_*` is defined in
   `observability/metrics.py:91-128` and called nowhere; `get_tracer()` is
   called nowhere; the Prometheus scrape jobs for `api`/`worker` are commented
   out (`observability/prometheus/prometheus.yml:28-35`); the documented metric
   names (`docs/observability.md:10-13`) have **zero overlap** with the eight
   declared (`metrics.py:40-87`); and compose sets `OTEL_EXPORTER_OTLP_ENDPOINT`
   (`compose.yaml:173`) while the config reads `ITSM_OTEL_EXPORTER_ENDPOINT`
   (`config.py:187`).

Two further gaps from the milestone review:

5. **No rehearsal qualification vocabulary.** `docs/release-qualification.md`
   qualifies a CI run on `main` only; there is no definition or disqualifier
   set for a rehearsal artifact. The recorded qualification names `2ebd7ef`,
   so current `main` (`f38f6eb`) is not covered by a recorded run.
6. **The pilot artifact mixes stable metrics with machine-dependent latency**
   (`evals/reports/pilot-metrics.json`), and `docs/pilot.md:33` calls that
   path "committed" while `.gitignore:23` ignores every `reports/` directory.

---

## 2. Work packages, in dependency order

Each package: scope → files → acceptance evidence. One package per branch and
PR; the 15 CI gates are unchanged; nothing is merged without exact-SHA green.

### WP-A — Reviewer authorization provisioning (unblocks WP-B, WP-E)

*Why first:* without a way to create two independently authenticated reviewer
identities, the authenticated-review gate cannot be demonstrated at all.

- **Scope:** an **administration-plane** provisioning path for
  `reviewer_authorizations` — deliberately outside the runtime role (which
  stays forbidden from writing it, keeping `privileges.py:250-255` green).
  A small CLI (`tools/provision_reviewer.py`) that connects with an admin DSN,
  upserts `(issuer, subject, roles, tenant_ids, authorization_version)`,
  and prints the row it wrote. It must refuse a runtime-role DSN and refuse
  to write an empty role set.
- **Files:** `tools/provision_reviewer.py` (new), `docs/runbooks/SOP-05` (add
  the CLI path beside the existing SQL path), `tests/unit/test_provision_reviewer.py` (new).
- **Acceptance:** provisioning two subjects for one issuer/tenant; the runtime
  role still cannot write the table; the CLI is idempotent; a unit test proves
  the refusal paths (runtime DSN, empty roles).

### WP-B — A genuine local identity provider for the staging rehearsal (unblocks WP-E, WP-I)

*Why:* the rehearsal needs a real credential that the OIDC relying party
accepts. **Staging authentication is not weakened** — the API keeps verifying
signature, `iss`, `aud`, `exp`, `nbf`, `iat`, algorithm allowlist
(`api/oidc.py:72`), clock leeway, max token age, and server-side role
resolution. What is added is a *signing authority* for the isolated staging
environment, in the same spirit as the existing Mockoon simulators for the
ITSM/identity/infra APIs.

- **Scope:** `simulators/identity/` — a small RS256 issuer that publishes
  `/jwks` and mints tokens for two distinct subjects (`reviewer-a`,
  `reviewer-b`), served over **https with a pinned CA** (the OIDC provider
  requires an absolute https JWKS URL, `api/oidc.py:155-175`). Support for a
  pinned CA in `Settings` (`ITSM_OIDC_JWKS_CA_FILE`) is a legitimate
  production feature (private CAs are common), not a test backdoor.
- **Files:** `simulators/identity/` (new package + README), `src/itsm_agent/config.py`
  (new setting), `src/itsm_agent/api/oidc.py` (pass the CA to the JWKS client),
  `src/itsm_agent/api/__main__.py` (CA plumbed into the httpx client),
  `tests/contract/test_identity_simulator.py` (new), `tests/unit/test_oidc_http_jwks.py`
  (extend: pinned-CA client).
- **Acceptance:** a token minted by the simulator is accepted by the real OIDC
  authenticator; a token signed by a different key is rejected; the algorithm
  allowlist is unchanged; the simulator is labelled a simulator everywhere it
  is referenced.
- **Decision needed:** signing library. `cryptography` is not a direct
  dependency today; RS256 sign/verify + JWKS assembly is ~60 lines on top of
  it. Recommendation: add `cryptography` as an explicit dependency (dev +
  runtime for the simulator), justified in the PR body.

### WP-C — Produce `evidence_references` from detection (unblocks WP-E, WP-I)

*Why:* Gate 2 requires the model to receive *actual evidence*, and Gate 3
requires a reviewer to *receive* evidence. Today the bundle would be empty.

- **Scope:** when the detection consumer persists a finding, it also persists
  the evidence reference(s) that justify it — at minimum one row per finding
  linking the canonical source event (content hash = the event's payload hash,
  trust level reflecting the source's trust, excerpt = a **redacted** summary
  through `privacy/redaction.redact_secrets`). This makes the bundle
  non-empty and lets a model proposal cite a real evidence id that the
  orchestrator can validate against the snapshot.
- **Files:** `src/itsm_agent/adapters/persistence/repositories.py` (add
  `PsycopgEvidenceReferenceRepository.insert`), `src/itsm_agent/application/audit_consumer.py`
  (write evidence in the same tenant transaction as the finding),
  `tests/integration/test_audit_pipeline_durable.py` (evidence row + bundle
  content), `docs/event-contract.md` (what evidence a finding carries).
- **Acceptance:** after a detection pass the finding has ≥1 evidence row; the
  bundle endpoint returns it; the excerpt is redacted; evidence rows are
  tenant-isolated and append-only in the same transaction as the finding.

### WP-D — Make observability real (Gate 1; unblocks WP-I)

*Why:* Gate 1 requires "logs, metrics and distributed traces capture the main
workflow". Today nothing is emitted, and the documented metric names do not
exist in code — a truthfulness problem as much as a capability one.

- **Scope:** (a) emit the declared metrics at the ingestion, detection,
  investigation, outbox and dead-letter points (the `observe_*` helpers
  already exist and are unused); (b) create spans for the same path with
  `observability/tracing.setup_tracing`/`get_tracer`; (c) reconcile
  `docs/observability.md` with the code — either rename the code to the
  documented names or amend the doc, and state which; (d) fix the compose ↔
  config OTel variable mismatch (`OTEL_EXPORTER_OTLP_ENDPOINT` vs
  `ITSM_OTEL_EXPORTER_ENDPOINT`); (e) enable the Prometheus scrape jobs for
  `api` and `worker`.
- **Files:** `src/itsm_agent/observability/` (instrumentation), the API/consumer
  paths, `docs/observability.md`, `compose.yaml`, `observability/prometheus/prometheus.yml`.
- **Acceptance:** `/metrics` returns a non-empty registry after a pipeline
  run and the names match the documentation exactly; a trace appears in the
  collector for one processed event; the doc contains no metric name that the
  code does not declare (checked by a test).

### WP-E — Upgrade the staging runner into a qualification rehearsal (unblocks WP-H, WP-I)

- **Scope:** (a) **credential**: obtain an OIDC token from the configured
  issuer (token endpoint / client-credentials / an explicitly supplied token
  via env) instead of minting HMAC; drop the mandatory
  `ITSM_AUTH_HMAC_SECRET` from preflight and add the OIDC variables;
  (b) **two reviewers**: run the lifecycle — reviewer-a transitions
  `ACKNOWLEDGED → RESOLVED` with a reason, reviewer-b independently
  transitions `RESOLVED → VERIFIED` (the independence rule must hold and the
  runner must fail loudly if it does not); (c) **bundle**: treat a 503 from
  the bundle endpoint as a **failed rehearsal**, not a note; (d) **evidence
  grounding**: assert that the proposal's supporting/contradicting evidence
  ids are inside the snapshot and that they resolve to real evidence rows;
  (e) **report**: include run id, commit SHA, model id, source-event id and
  payload hash, finding id and detection outcome, request/proposal ids, model
  call count and latency, evidence-validation outcome, reviewer identities and
  decisions, final finding status, and the explicit "does not prove" list —
  with no key, token or credential in the artifact; (f) write the report to a
  **committed** path (`evals/reports/staging/`, with the ignore rule narrowed
  so the directory is not blanket-ignored).
- **Files:** `tools/e2e_staging_run.py`, `tests/unit/test_e2e_staging_runner.py`,
  `docs/runbooks/SOP-06-staging-e2e-run.md`, `.gitignore`.
- **Acceptance:** a rehearsal against the local stack with the identity
  simulator completes all steps, produces a 200 bundle, records exactly one
  RESOLVED and one VERIFIED transition by two distinct principals, and writes
  a redacted report.

### WP-F — Close the two uncovered failure scenarios (Gate 4)

- **Scope:** (a) **NATS interruption mid-stream**: stop the broker while the
  pipeline is running; assert the outbox backlog accumulates and drains after
  the broker returns, with no duplicate finding and no lost event;
  (b) **LLM timeout**: simulate `httpx.TimeoutException` on the model path;
  assert the investigation is recorded `FAILED` with a bounded reason, the
  deterministic finding survives unchanged, and no proposal row is written.
- **Files:** `tests/fault_injection/test_nats_interruption.py` (new),
  `tests/fault_injection/test_llm_timeout.py` (new).
- **Acceptance:** both scenarios pass deterministically with real PostgreSQL
  and NATS; they run in the `fault_injection` marker so they join `verify-ci`.

### WP-G — Split the pilot artifact; fix the reporting-truth gaps (P1/P2 from the milestone review)

- **Scope:** (a) split `evals/reports/pilot-metrics.json` into a stable
  `pilot-metrics.json` (scenario results, precision, recall, false-positive
  rate, evidence preservation — byte-stable and asserted unchanged) and
  `pilot-performance.json` (latency distribution, environment, timestamp —
  explicitly non-deterministic); (b) narrow `.gitignore` so the intended
  report paths are committable while transient output stays ignored;
  (c) reconcile `docs/pilot.md` with the artifact paths so the doc's
  "committed" claim is true.
- **Files:** `tests/e2e/test_pilot_metrics.py`, `evals/reports/*`,
  `docs/pilot.md`, `.gitignore`.
- **Acceptance:** re-running the harness changes only the performance file;
  the metrics file is byte-identical; the docs match the paths.

### WP-H — Define and record the rehearsal qualification (Gate 2)

- **Scope:** extend `docs/release-qualification.md` with a second
  qualification track for a **staging rehearsal**: what a qualifying rehearsal
  artifact must contain (all of WP-E's report fields), and the disqualifiers
  (bundle not retrieved, proposal cited an out-of-snapshot evidence id, model
  made more calls than the budget, the two reviewers were not distinct, the
  finding status was changed by the model, a secret appeared in the artifact,
  the rehearsal did not run against the recorded commit SHA). Record the
  exact-SHA qualification run for the current `main` as well.
- **Files:** `docs/release-qualification.md`, `IMPLEMENTATION_PLAN.md`.
- **Acceptance:** the doc defines rehearsal qualification and disqualifiers
  in the same evidence-first style as the existing CI track; a rehearsal
  artifact can be judged pass/fail from the document alone.

### WP-I — Demo storyboard and a runnable demo path (Gate 2; the Loom deliverable)

- **Scope:** a **narrated** demo that shows, in order: successful recovery
  (ingest → detect → grounded investigation → reviewer decision →
  independent verification → report), failed recovery (the investigation
  fails closed and the deterministic finding survives), and a security
  boundary (an unauthorized reviewer or a cross-tenant attempt is rejected).
  Deliverables: a storyboard/beat sheet with timings (5–7 minutes) in
  `docs/demo-storyboard.md`; a `make demo-*` target that runs the workflow and
  prints the artefacts (bundle, transition ledger, report) an operator can
  screen-share; and the retained staging report as the backing evidence.
- **Files:** `docs/demo-storyboard.md` (new), `Makefile` (targets), and the
  runner/report output from WP-E.
- **Acceptance:** a stranger can follow the storyboard against a clean stack
  without hand-holding; every claim in the storyboard is backed by a line in
  the retained report.

### WP-J — Independent review requirement (blocked externally)

Raise the branch-protection approving-review count from 0 to 1 **when another
qualified reviewer with write access exists**. GitHub does not allow a PR
author to approve their own PR, so this cannot be enabled while the repository
is solo-maintained. Recorded as a one-command follow-up in
`docs/release-qualification.md`; no code change in this milestone.

---

## 3. Chronological order and dependency graph

```
WP-A  provision reviewer identities      (no deps)
WP-B  local OIDC identity simulator       (needs WP-A for two directory rows)
WP-C  evidence_references producer        (no deps)
WP-D  observability wiring                (no deps)
WP-F  NATS-interruption + LLM-timeout tests(no deps)
WP-G  pilot artifact split                (independent)
        │
        ├─ WP-E  rehearsal runner upgrade  (needs WP-A, WP-B, WP-C)
        │        │
        │        ├─ WP-H  rehearsal qualification record (needs a real run)
        │        └─ WP-I  demo storyboard + demo path (needs WP-E, WP-D)
        │
        └─ WP-J  raise approving reviews   (blocked on an independent reviewer)
```

Sequencing rationale:

1. **WP-A → WP-B** is the critical path. Everything about authenticated review
   depends on being able to create two identities and then obtain their
   tokens; nothing else in the plan can substitute for it.
2. **WP-C** is independent and small, but it must land before WP-E: the
   rehearsal asserts that a proposal cites real, resolvable evidence.
3. **WP-D** can run in parallel with WP-A/B/C (disjoint files) and is required
   before the demo, because a demo that shows no metrics or traces cannot
   satisfy Gate 1's observability line.
4. **WP-E** is the integration point and is where the milestone is actually
   decided; it needs WP-A, WP-B and WP-C complete.
5. **WP-H** needs a real rehearsal run, so it follows WP-E.
6. **WP-I** is last: a storyboard written before the workflow works would be
   fiction.
7. **WP-J** is externally blocked and is recorded, not attempted.

Parallelisation (agents may work concurrently on disjoint files):
WP-C ∥ WP-D ∥ WP-F ∥ WP-G can all proceed while WP-A → WP-B runs.

---

## 4. Gate definitions this plan will satisfy

**Gate 1 — Staging environment readiness.** One documented command starts the
stack; real PostgreSQL with migrations and the constrained `itsm_app` role;
real JetStream with a durable consumer; API health endpoints; relay + audit
consumer starting and stopping gracefully; **actual staging-compatible
authentication** (OIDC — no HMAC bypass); secrets supplied by environment and
absent from logs; worker restart neither loses nor duplicates durable
processing; logs, metrics and traces covering the main workflow.

*Where each line is satisfied:* WP-B (authentication), WP-C (evidence), WP-D
(observability), WP-F (restart/interruption), plus the existing
`compose.yaml` + `Makefile` (`compose-up`, `compose-reset`, `demo-reset`).

**Gate 2 — Demo-qualified.** One complete scenario — simulated CloudTrail
administrative role assumption → deterministic finding → real Groq
investigation over actual evidence → evidence-reference validation →
authenticated reviewer decision → independent verification by a second
principal → reproducible report — with the retained artifact satisfying the
WP-H disqualifier set.

**Not claimed:** production readiness, certification, real production data,
100% detection recall, or an independent human review (WP-J).

---

## 5. Failure/recovery coverage: already covered vs. to add

| Scenario | State | Where / what to add |
| --- | --- | --- |
| Duplicate event | COVERED | `test_inbox_dedup.py`, `test_nats_consumer.py:170` |
| NATS interruption (startup) | COVERED | `test_worker_process.py:134` |
| **NATS interruption (mid-stream)** | **TO ADD (WP-F)** | backlog accumulates, drains after recovery, no duplicate |
| Worker restart | COVERED | `test_worker_process.py:63,155`, `test_atomic_terminal_state.py:337` |
| **LLM timeout** | **TO ADD (WP-F)** | `httpx.TimeoutException` → ledger `FAILED`, finding survives |
| Invalid model response | COVERED | `test_groq_investigation_model.py:305,313,331,382,392` |
| Unsupported evidence reference | COVERED | `test_investigation.py:66`, `test_investigation_service.py:243` |
| Unauthorized reviewer | COVERED | `test_findings_api.py:179,189,305`, `test_findings_transition_api.py:327,395,414` |
| Cross-tenant access | COVERED | `test_rls_tenant_isolation.py:154`, `test_tenant_propagation.py:180,213,239` |
| Replayed event | COVERED | `test_nats_replay.py:37,93,119`, `test_webhook_security.py:130` |

---

## 6. Decisions needed before execution

1. **Identity source for the rehearsal** — recommend the **local RS256
   simulator** in `simulators/identity/` (offline, repeatable, no external
   credentials, no CI billing) over an external IdP. It is a signing
   authority, not an authentication bypass: the API's verification is
   unchanged. Requires adding `cryptography` as an explicit dependency.
   *Alternative: an external IdP, which needs real credentials and cannot run
   in CI.*
2. **Where the rehearsal report lives** — recommend committing it under
   `evals/reports/staging/` with `.gitignore` narrowed to that path, so the
   demonstration has retained evidence in Git. *Alternative: keep reports
   ignored and publish a summary — weaker evidence.*
3. **Scope of WP-D (observability)** — recommend doing the metric-name
   reconciliation, the instrumentation, the compose variable fix and the
   scrape-job enablement in one package. It is the difference between Gate 1
   being satisfied and being asserted.
4. **Whether WP-I (storyboard/demo path) is in scope for me** or is the
   owner's recording session with my storyboard as the input.
5. **The `make verify` vs `make verify-ci` divergence** the audit found
   (`Makefile:63`: `verify` omits fault-injection). Recommend aligning them
   so the local gate matches CI — a one-line change, but it changes what a
   local green means, so it is your call.

---

## 7. What this plan does not change

- The 15 CI gates, their thresholds, and the branch-protection policy
  (required checks, strict merges, admins enforced, force-push and deletion
  blocked).
- The detection semantics or the finding lifecycle semantics (measured:
  false-positive rate 0.0, precision 1.0, recall 1.0 over rule-supported
  scenarios).
- The runtime role's privileges: `reviewer_authorizations` stays
  read-only for it; provisioning stays an administration-plane operation.
- The rule that the model proposes and never authorizes: the finding status
  changes only through a human-authenticated transition.
- The honesty conventions: every artifact states what it does not prove, and
  no document will claim production readiness or certification.
