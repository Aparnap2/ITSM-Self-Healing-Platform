# Local staging demo — qualification record

Bound to one code-bearing commit: **`b9644e41e3b102a996a9a42b3bdf6f9da5f36a1b`**
(short: `b9644e4`). Working tree clean at capture time.

All three gates — CI, `STAGING_READY`, `DEMO_QUALIFIED` — were executed at
that same commit, `b9644e4`. Nothing here is inherited from a neighbouring
SHA, and nothing needs to be: the pipeline run, the readiness probe and the
rehearsal all name it. This document itself is a later, documentation-and-
evidence-only commit that inherits the record under the rule at the end.

This record states what was **executed**, what was **observed**, and what is
**not proven**. It deliberately separates three different things that are easy
to blur together: tests passing, a stack starting, and a security workflow
completing.

## What "staging" means here

The stack runs with `ITSM_ENV=staging` and `ITSM_AUTH_MODE=oidc`, which means
the application refuses the development HMAC bearer outright
(`src/itsm_agent/config.py`). Authentication is RS256 against a **local
identity simulator**: a signing authority with no role or tenant claims. Both
reviewers are authorized by rows in `reviewer_authorizations`, read from
PostgreSQL on every request.

This is **not** a cloud staging environment. There is no managed PostgreSQL,
no hosted identity provider, no multi-node broker. It is the same application
code on the same protocols, with every external dependency simulated. Calling
it "staging" means "staging-compatible configuration", nothing more.

## Verdicts

| Gate | Verdict | Bound to |
| --- | --- | --- |
| CI qualification (15 required checks) | **PASS** — 15/15 jobs, 856 executions, 0 failures, 0 skipped | `b9644e4` |
| `STAGING_READY` | **PASS** | `b9644e4` |
| `DEMO_QUALIFIED` | **PASS** | `b9644e4` |

One SHA, three independently executed gates. No verdict is transferred from
a commit that was not executed.

## CI qualification: PASS at `b9644e4`

Run [`44464855386`](https://github.com/Aparnap2/ITSM-Self-Healing-Platform/actions/runs/44464855386),
event `push`, branch `feat/demo-staging-stack`, head SHA
`b9644e41e3b102a996a9a42b3bdf6f9da5f36a1b`. **15/15 jobs `success`,
0 failures.**

| Job | Result |
| --- | --- |
| Workflow Security (zizmor) | success |
| Secret Scan (gitleaks) | success |
| Type Check (mypy --strict) | success |
| Lint & Format | success |
| Unit Tests | success |
| Supply Chain (pip-audit, bandit, SBOM) | success |
| Contract Tests (simulators, offline) | success |
| Security Invariant Tests | success |
| Build & Compose Config | success |
| Integration Tests | success |
| Fault Injection Tests | success |
| DAST (OWASP ZAP baseline, isolated target) | success |
| E2E Tests | success |
| Scenario Harness | success |
| CI Verification Summary | success |

Counts parsed from that run's own JUnit artifacts (`gh run download`), not
from this document:

| Suite | Executions | Failures | Errors | Skipped |
| --- | --- | --- | --- | --- |
| unit | 537 | 0 | 0 | 0 |
| contract | 57 | 0 | 0 | 0 |
| security | 45 | 0 | 0 | 0 |
| fault_injection | 20 | 0 | 0 | 0 |
| integration | 161 | 0 | 0 | 0 |
| scenarios | 24 | 0 | 0 | 0 |
| e2e | 12 | 0 | 0 | 0 |
| **total** | **856** | **0** | **0** | **0** |

The summary job runs with `--max-skipped 0`, so a skipped test would have
failed the pipeline rather than counting as a pass.

**Why these numbers moved from 850 to 856.** This commit adds six unit tests
covering the readiness gate's failure-evidence routing and its diagnostic
probe, and changes the CI workflows (the JetStream assertion and an optional,
dispatch-only spike that adds no required check). Because the workflows are
executable configuration, the documentation-only inheritance rule does not
apply, and all three gates were re-executed here rather than borrowed from
the previous SHA.

## Execution A — `STAGING_READY`: PASS

Command: `make demo-verify` (full mode).
Artifact: `evals/reports/staging/readiness-20261119T052345Z.json`
(started `2026-11-19T05:23:45Z`, finished `05:25:25Z`, mode `full`).

| # | Criterion | Verdict | Observed |
| --- | --- | --- | --- |
| 1 | All required services running | PASS | postgres, nats, identity, mockoon, otel-collector, prometheus, api, worker, relay, retention |
| 2 | Every service with a healthcheck is healthy | PASS | postgres, nats, identity, mockoon, prometheus, api all `healthy`; `starting` is treated as not-ready. otel-collector, worker, relay, retention declare no healthcheck, so only `running` is asserted for them |
| 3 | PostgreSQL migrations complete | PASS | 16/16 applied |
| 4 | Reviewer directory populated | PASS | 2 active authorizations |
| 5 | NATS JetStream available | PASS | `streams=2 consumers=1` |
| 6 | OIDC discovery responds | PASS | advertised issuer matches the configured issuer |
| 7 | JWKS responds with the expected algorithm | PASS | 1 key, `alg=RS256` |
| 8 | API health endpoint responds | PASS | `GET /healthz` → 200 |
| 9 | RS256-issued token is accepted | PASS | `GET /v1/findings` as `reviewer-a` → 200 |
| 10 | Malformed token is rejected | PASS | `Bearer not-a-jwt` → 401 |
| 11 | Missing token is rejected | PASS | no header → 401 |
| 12 | Unauthorized principal is rejected | PASS | valid signature for `reviewer-intruder`, no directory row → 401 |
| 13 | Expired token is rejected | PASS | same token 200 before expiry, 401 after 100 s (60 s TTL + 30 s leeway + margin) |
| 14 | API metrics endpoint serves platform metrics | PASS | `HTTP 200, 121 lines` in this run — the total varies with which processes are running, so the check asserts the declared `itsm_*` families (`itsm_ingestion_events_total`, `itsm_consumer_messages_total`, `itsm_outbox_backlog`), not a line count |
| 15 | Prometheus scrape targets up | PASS | `api`, `otel-collector`, `otel-exported-app-metrics`, `prometheus` all `up` |
| 16 | Outbox backlog | PASS | 0 tenant-scoped rows pending; 7 system rows (`tenant_id IS NULL`) flagged as a known limitation (below) |

The gate emits **14** checks; rows 1–2 and 3–4 above are two aspects each of
one emitted check. The artifact, not this table, is the authoritative count.

Criterion 12 is the security boundary in one line: the simulator will happily
sign a token for `reviewer-intruder`, and the API still refuses it. A
signature proves who spoke, never what they may do.

### Execution A captures

Directory: `evals/reports/staging/evidence/readiness-20261119T052549Z/`

| File | Kind | Content |
| --- | --- | --- |
| `01-prometheus-targets.png` | screenshot (headless Chrome, live page) | Prometheus `/targets`, all jobs UP |
| `02-prometheus-query-ingestion.png` | screenshot (live endpoint) | Prometheus query result for `itsm_ingestion_events_total` |
| `03-api-metrics.png` | screenshot (live endpoint) | API `/metrics` |
| `04-oidc-discovery.png` | screenshot (live endpoint over TLS) | OIDC discovery document |
| `compose-ps.json` | raw capture | `docker compose ps` output |
| `prometheus-targets.json` | raw capture | `/api/v1/targets` |
| `oidc-discovery.json`, `oidc-jwks.json` | raw capture | OIDC surface, fetched with the pinned CA |
| `auth-matrix.json` | raw capture | the 401/200 matrix, statuses and bodies, no bearer values |
| `api-metrics.txt` | raw capture | `/metrics` body |
| `database-state.json` | raw capture | migrations, reviewer rows, event/finding counts |
| `index.json` | manifest | commit, timestamp, file sizes, and the certificate-verification note below |

The screenshots that hit the simulator use `--ignore-certificate-errors`
**in the browser process only**, because the simulator's CA is throwaway. The
platform itself never disables verification: it pins
`ITSM_OIDC_JWKS_CA_FILE` and the readiness probe uses the same pinned CA.
This is recorded in `index.json` so a reader is not misled.

Grafana is **not configured** in this stack. A dashboard screenshot is
`NOT APPLICABLE`; it is not missing evidence.

### About screenshots and CLI evidence

Only the four files above are browser captures. Everything else — container
health, migrations, auth matrix, outbox — is raw machine-readable output,
because a picture of a terminal is a rendering, not a capture. The raw files
are what a reviewer can diff and hash.

## Execution B — `DEMO_QUALIFIED`: PASS

Command: `make demo-run`.
Artifact: `evals/reports/staging/staging-run-72a99034-604c-4328-aff7-313f798ed136-20261119T052541Z.json`.

Tenant `72a99034-604c-4328-aff7-313f798ed136` is fresh per run, so the
rehearsal is repeatable and cannot be satisfied by rows left over from an
earlier attempt. Reviewers are provisioned immediately before the run for that
tenant *and* for the readiness tenant — a list that is added to deliberately,
because provisioning replaces it (defect 8 below).

| # | Stage | Verdict | Observed |
| --- | --- | --- | --- |
| 1 | Synthetic event ingested | PASS | `source_event_ingest = ACCEPTED`, external id `cloudtrail:staging-6411ff3b58a9…` |
| 2 | Signed webhook accepted by the API | PASS | HTTP 202 with an idempotency key |
| 3 | Durable persistence before publishing | PASS | source event + outbox row committed, then `outbox_relay` published 1 message |
| 4 | NATS consumer processed the message | PASS | `detection = processed` (in-process consumer) |
| 5 | Deterministic finding created | PASS | `MISSING_APPROVAL`, severity P2, outcome `SUSPICIOUS`, risk 60, finding `6e5e1b0a…` |
| 6 | Real model investigation, bounded | PASS | status `COMPLETED`, **1** real Groq call against a budget of 3 |
| 7 | Proposal is advisory only | PASS | `finding_status_unchanged_by_investigation=true`; the status is sampled straight after the model stage (`OPEN → OPEN`) and again after review (`→ VERIFIED`), so the model's non-effect and the reviewers' effect are separate observations |
| 8 | Evidence reference persisted and resolvable | PASS | cited id `301428b5…`, `in_snapshot=True`, `resolves_to_persisted_evidence=True` |
| 9 | Evidence bundle served over HTTP | PASS | bundle hash `a0205813…` |
| 10 | Reviewer A authenticates via OIDC | PASS | credential mode `oidc`, token accepted |
| 11 | Reviewer A acknowledges and resolves | PASS | `ACKNOWLEDGED: 200`, `RESOLVED: 200` |
| 12 | Reviewer B independently verifies | PASS | `VERIFIED: 200` — a different principal from the resolver |
| 13 | Final lifecycle state | PASS | `OPEN → OPEN (after investigation) → VERIFIED (after review)` |
| 14 | Audit trail retrievable | PASS | bundle contains finding, evidence, review decisions, limitations, hash |

The report also carries `what_this_run_does_not_prove`, generated from what
actually happened in this run (transition count, persisted evidence count)
rather than fixed boilerplate.

### What the two grounding fields each mean

The report carries two independent booleans, and they answer different
questions:

- `resolves_to_persisted_evidence` — does the cited id belong to a row that
  actually exists for this tenant? This catches invented identifiers.
- `in_snapshot` — was that id among the ids the model was *shown*? The
  production consumer passes `evidence_snapshot_ids=(source_event.event_id,)`
  (`src/itsm_agent/application/audit_consumer.py`), so the prompt's only
  evidence key is the source event id. The evidence-reference row written for
  the finding has its own, different id.

An evidence-reference id therefore satisfies the first check and fails the
second: it is real, and the model was never given it. Trusting either field
alone would pass an unsupported claim, so the runner checks both and the unit
suite pins the distinction
(`tests/unit/test_e2e_staging_runner.py::test_grounding_rejects_a_real_id_that_was_never_in_the_prompt`).

This is not hypothetical. An earlier attempt at this rehearsal produced
`in_snapshot=False` while `resolves_to_persisted_evidence=True`: the model
cited a persisted reference id it had not been shown. The gate refused it.
The attempt was re-run on a clean tenant rather than published, and — worth
saying plainly — **its report was deleted along with the other stale-tenant
artifacts, so it cannot be inspected here.** That is a process mistake, not
a strength: failure evidence should have been archived outside the tracked
tree instead of removed. What survives is the live observation in the run
log and the regression test added afterwards.

The honest reading of the PASS above is therefore narrow: **the gate accepts
a grounded citation and refuses an ungrounded one; this run produced a
grounded one.** It is not evidence that the model grounds reliably.

### Execution B captures

Directory: `evals/reports/staging/evidence/rehearsal-20261119T052552Z/`

| File | Kind | Content |
| --- | --- | --- |
| `10-prometheus-ingestion-after-run.png` | screenshot (live endpoint) | ingestion counter after processing |
| `11-api-metrics-after-run.png` | screenshot (live endpoint) | API `/metrics` after the run |
| `compose-ps.json` | raw capture | service state (worker restored after the rehearsal) |
| `prometheus-targets.json`, `oidc-*.json`, `auth-matrix.json`, `api-metrics.txt` | raw capture | live surfaces |
| `database-state.json` | raw capture | migrations, reviewers, event/finding counts, outbox by status |

The lifecycle itself is evidenced by the rehearsal report and the bundle, not
by a screenshot: the report is the diffable artifact.

## Disqualifier self-check

| Disqualifier | Status |
| --- | --- |
| Evidence inherited from another SHA | No — every passing artifact records `b9644e4`. The one artifact that records a different SHA (`21ebf24`) is the kept failure under `failures/`, labelled as a failure, and it backs no verdict |
| Gate marked PASS from unit/contract tests | No — every criterion is a live probe or a live run |
| Screenshot of a mockup or fixture | No — four live pages, two live metric endpoints; originals retained |
| Success manufactured after a failure | No — no result was edited or re-labelled. One attempt was refused by the grounding gate; it is described above, and the fact that its report was deleted is disclosed rather than hidden |
| A failure quietly re-run until it passed | Only in one place, stated above: the refused grounding attempt was re-run on a fresh tenant. The gate's refusal was not suppressed — the missing regression test was added afterwards so the behaviour is pinned without a live model |
| Credentials in evidence | No — checked with a JWT-shaped-string scan; bearer values never written |
| Unbounded model retries | No — 1 call used of 3; the runner has `max_retries=0` |
| Resolution without independent verification | No — `VERIFIED` by a second principal |
| Terminal outcome without audit records | No — bundle carries the decision and transition trail |
| Tests skipped to make the gate green | No — the full suite ran; CI runs with `--max-skipped 0` |
| CI borrowed from a neighbouring SHA | No longer applicable — CI, readiness and the rehearsal all ran at `b9644e4` itself |
| A gate left blank or marked N/A to avoid a failure | No — all three gates were run; the only `NOT APPLICABLE` is Grafana, which is not deployed |

## Local test evidence at `b9644e4`

`make verify` (local, `ITSM_TEST_STRICT=1`), exit 0:

| Suite | Passed |
| --- | --- |
| unit | 537 |
| contract | 57 |
| security | 45 |
| fault-injection | 20 |
| integration | 161 |
| scenarios | 24 |
| e2e | 12 |
| **total executions** | **856** |

Plus `ruff format --check` (253 files), `ruff check`, `mypy` (191 files),
and `bandit` over `src/`.

Local and CI agree exactly at this commit: 537 unit, 856 total executions.
The local run is what the pre-push gate enforces; CI is the independent
re-execution of the same tree.

Coverage gaps that are intentional and unchanged: no throughput/latency gate,
no load test against the public API, no assertion on real OTLP trace content,
single-node PostgreSQL and NATS.

## Defects found and fixed by doing this work

These are recorded because the point of the exercise is the gap between "tests
are green" and "the thing runs".

1. **The application image could not start.** `prometheus_client` and
   `opentelemetry.sdk` are imported at module level in production code but
   were declared only in the `dev` extra. The image is built `--no-dev`, so
   api/worker/relay/retention crashed on import. No gate caught it because
   every test runs with the dev extra installed.
2. **The compose stack had no identity provider and no migration gate.**
   `ITSM_ENV=staging` necessarily refused the HMAC bearer, so the documented
   stack could not run at all in staging mode.
3. **The rehearsal runner could never emit an OIDC report.** `sanitize_report`
   evaluated `options.reviewer_token` unconditionally and raised *after* the
   work was done. Fixed, with a regression test.
4. **The report described a runner that no longer existed.** It claimed the
   rehearsal "stops at the proposal", which stopped being true when the
   two-reviewer lifecycle was added. Statements are now derived per run.
5. **The collector's self-metrics target was always down.** The declared
   Prometheus job scraped a port the collector never exposed.
6. **`--wait` did not mean "serving".** The API had no healthcheck, so
   `docker compose up --wait` returned before it answered.
7. **Re-running in a fixed tenant produced false failures.** Detection
   dedupes by `(tenant, type, title)`, so a second run met a terminal finding
   and its transitions were refused with 409. `demo-run` now provisions a
   fresh tenant per run.
8. **Re-provisioning silently de-authorized the readiness tenant.** Fixing
   defect 7 introduced a worse one: provisioning *replaces* a subject's tenant
   list, so every rehearsal removed the reviewers from `1111…` and the next
   readiness probe failed closed with 403. The gate was correct and the
   automation was wrong. The failing report is kept in
   `evals/reports/staging/failures/`.
9. **The report blamed the model for the reviewers' change.** The finding
   status was read once at the end of the run, so
   `finding_status_unchanged_by_model` compared the pre-investigation status
   with the post-review one and reported `false` for a run in which the model
   had changed nothing. It now samples immediately after the investigation
   stage and keeps the final value separately. The original test could not
   have caught this: it asserted the boolean with before equal to after.
10. **The documented test setup produced a NATS server without JetStream.**
    Following the README started `nats:2`, which reads a relative
    `nats-server.conf` that shadows the mounted one, so JetStream was off.
    The server reported healthy and four fault-injection tests failed with
    `ServiceUnavailableError` from `update_stream` — a message that points at
    the test rather than at the server. The README now pins the tag CI uses
    and passes the config path explicitly, and every CI readiness loop probes
    `/jsz` instead of `/healthz`, so the same mistake fails at startup with an
    obvious cause.

## Known limitations

- **PostgreSQL privilege gap.** The runtime role `itsm_app` is
  `NOSUPERUSER`/`NOBYPASSRLS`, but this record does not prove it holds
  *exactly* the intended grants. No test asserts the full privilege set.
- **No load test, no throughput or latency gate.** Correctness under
  concurrency is tested elsewhere; performance is not characterised here.
- **No real trace-export assertion.** Metrics are asserted end to end (API →
  OTLP collector → Prometheus). Trace *content* reaching a real backend is not.
- **Single-node PostgreSQL and NATS.** No failover, no quorum behaviour.
- **System outbox rows are not drained.** The relay runs one scoped pass per
  registered tenant, so `outbox` rows with `tenant_id IS NULL` (the legacy
  `IncidentCreated` workflow) stay pending once a tenant exists. Pre-existing;
  the demo's own tenant-scoped rows do drain. Not fixed here because changing
  relay selection semantics is outside this slice and none of the 15 CI gates
  covers it.
- **Simulated externals.** Identity, ITSM (Mockoon), and infrastructure are
  simulated. No real IdP, Jira, ServiceNow, or cloud account was contacted.
- **One transient gate failure is unexplained.** After defect 8 was fixed, a
  single `make demo-up` smoke run failed `oidc token accepted` (403) and every
  subsequent run passed, including a deliberate replay of the exact
  re-provision-then-probe sequence. The cause was not identified; it is
  recorded in `failures/README.md` rather than smoothed away. A gate that can
  fail once for unknown reasons is a known weakness of this record.
  The first attempt to investigate it failed for a bad reason: the fast path
  printed a FAIL and wrote no artifact, so there was nothing to inspect. That
  is now fixed — any non-PASS gate writes a report, routed to
  `evals/reports/staging/failures/` so it is never filed beside a passing
  one, and a membership refusal now carries the reviewer-authorization row
  that explains it (`tenant_ids`, whether the requested tenant is in that
  list, the authorization version, and the age of `updated_at`). The
  instrumentation was checked by injecting the failure deliberately:
  provisioning `reviewer-a` for an unrelated tenant and running the gate
  produced the 403 and an artifact stating
  `requested_tenant_is_member: false`, `age_seconds: 0.5`,
  `authorization_version: 12`. That injection also showed the two causes are
  now distinguishable — a stored row that genuinely lacks the tenant reads
  differently from a row that has it and was read stale. It does not explain
  the transient; it makes the next occurrence explainable instead of
  merely observable.
- **The rehearsal drives the consumer in-process, not in its container.** The
  durable consumer `itsm-workflow` can only have one binding, so `demo-run`
  stops the `worker` container and runs the same `AuditConsumer` code inside
  the rehearsal process. That proves the consumer logic and the full event
  path; it does not prove the container's own supervisor loop, which the
  separate worker service exercises outside the run.
- **This document postdates the commit it qualifies.** The record is
  committed after `b9644e4` and changes only documentation and captured
  evidence, so it inherits that commit's verdicts under the rule below. The
  inheritance is a convenience, not a re-run: the three gates were executed
  at `b9644e4`, and this text did not exist when they ran.

## Inheritance rule

Documentation-only commits may inherit this record only if they change no
`.github/`, `src/`, `tests/`, or `Makefile` files, do not alter criteria or
claims, and name the inherited code-bearing commit (`b9644e4`). Any change
that affects executable behaviour invalidates the record and requires a fresh
run.

## Reproduction

```sh
make demo-up        # start stack, provision reviewers, smoke gate
make demo-verify    # full STAGING_READY gate, writes readiness JSON
make demo-evidence  # Execution A captures and screenshots
make demo-run       # Execution B: fresh tenant, real bounded model call
make demo-evidence-run
make demo-down
```

`make demo-up` runs `make demo-env` first: it writes a gitignored `.env` with
generated local secrets and inherits `GROQ_API_KEY` as `ITSM_GROQ_API_KEY`.
Without a Groq key the stack still starts, but the rehearsal's model stage
fails closed at startup rather than quietly skipping the model, so the run
would fail rather than produce a hollow pass. Expect about 100 s for
`demo-verify` (the token-expiry probe) and one billed model call per
`demo-run`.

`make demo-run` stops the generic `worker` first: the rehearsal drives the
durable consumer in-process, and two processes cannot bind the same consumer.
`make demo-worker-restart` puts it back.
