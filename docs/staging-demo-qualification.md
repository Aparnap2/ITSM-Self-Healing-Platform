# Local staging demo — qualification record

Bound to one commit: **`9ee4713eb61249df444f52d18cc3e5b525c72167`**
(short: `9ee4713`). Working tree clean at capture time.

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
| CI qualification (15 required checks) | **NOT RUN for `9ee4713`** — not yet pushed; the last green run is for an earlier SHA and is **not inherited** | — |
| `STAGING_READY` | **PASS** | `9ee4713` |
| `DEMO_QUALIFIED` | **PASS** | `9ee4713` |

The CI row is deliberately not a PASS. A qualification for one commit does not
transfer to another, and this commit has not been through the pipeline.

## Execution A — `STAGING_READY`: PASS

Command: `make demo-verify` (full mode).
Artifact: `evals/reports/staging/readiness-20261118T030531Z.json`
(started `2026-11-18T03:05:31Z`, finished `03:07:11Z`, mode `full`).

| # | Criterion | Verdict | Observed |
| --- | --- | --- | --- |
| 1 | All required services running | PASS | postgres, nats, identity, mockoon, otel-collector, prometheus, api, worker, relay, retention |
| 2 | Every service with a healthcheck is healthy | PASS | all `healthy`; `starting` is treated as not-ready |
| 3 | PostgreSQL migrations complete | PASS | 16/16 applied |
| 4 | Reviewer directory populated | PASS | 2 active authorizations |
| 5 | NATS JetStream available | PASS | streams=2, consumers=1 |
| 6 | OIDC discovery responds | PASS | advertised issuer matches the configured issuer |
| 7 | JWKS responds with the expected algorithm | PASS | 1 key, `alg=RS256` |
| 8 | API health endpoint responds | PASS | `GET /healthz` → 200 |
| 9 | RS256-issued token is accepted | PASS | `GET /v1/findings` as `reviewer-a` → 200 |
| 10 | Malformed token is rejected | PASS | `Bearer not-a-jwt` → 401 |
| 11 | Missing token is rejected | PASS | no header → 401 |
| 12 | Unauthorized principal is rejected | PASS | valid signature for `reviewer-intruder`, no directory row → 401 |
| 13 | Expired token is rejected | PASS | same token 200 before expiry, 401 after 100 s (60 s TTL + 30 s leeway + margin) |
| 14 | API metrics endpoint serves platform metrics | PASS | 180 lines, declared `itsm_*` families present |
| 15 | Prometheus scrape targets up | PASS | `api`, `otel-collector`, `otel-exported-app-metrics`, `prometheus` all `up` |
| 16 | Outbox backlog | PASS | 0 tenant-scoped rows pending; 4 system rows flagged as a known limitation (below) |

Criterion 12 is the security boundary in one line: the simulator will happily
sign a token for `reviewer-intruder`, and the API still refuses it. A
signature proves who spoke, never what they may do.

### Execution A captures

Directory: `evals/reports/staging/evidence/readiness-20261118T030742Z/`

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
Artifact: `evals/reports/staging/staging-run-ac1afce1-91a4-4d6d-92f6-1a833cbd81ca-20261118T030727Z.json`.

Tenant `ac1afce1-91a4-4d6d-92f6-1a833cbd81ca` is fresh per run, so the
rehearsal is repeatable and cannot be satisfied by rows left over from an
earlier attempt. Reviewers are provisioned for that tenant immediately before
the run.

| # | Stage | Verdict | Observed |
| --- | --- | --- | --- |
| 1 | Synthetic event ingested | PASS | `source_event_ingest = ACCEPTED`, external id `cloudtrail:staging-8eb2…` |
| 2 | Signed webhook accepted by the API | PASS | HTTP 202 with an idempotency key |
| 3 | Durable persistence before publishing | PASS | source event + outbox row committed, then `outbox_relay` published 1 message |
| 4 | NATS consumer processed the message | PASS | `detection = processed` (in-process consumer) |
| 5 | Deterministic finding created | PASS | `MISSING_APPROVAL`, severity P2, outcome `SUSPICIOUS`, risk 60 |
| 6 | Real model investigation, bounded | PASS | status `COMPLETED`, **1** real Groq call against a budget of 3 |
| 7 | Proposal is advisory only | PASS | finding status unchanged by the investigation stage |
| 8 | Evidence reference persisted and resolvable | PASS | cited id `80320e29…`, `in_snapshot=True`, `resolves_to_persisted_evidence=True` |
| 9 | Evidence bundle served over HTTP | PASS | bundle hash `1eefc8c4…` |
| 10 | Reviewer A authenticates via OIDC | PASS | credential mode `oidc`, token accepted |
| 11 | Reviewer A acknowledges and resolves | PASS | `ACKNOWLEDGED: 200`, `RESOLVED: 200` |
| 12 | Reviewer B independently verifies | PASS | `VERIFIED: 200` — a different principal from the resolver |
| 13 | Final lifecycle state | PASS | `OPEN → VERIFIED` |
| 14 | Audit trail retrievable | PASS | bundle contains finding, evidence, review decisions, limitations, hash |

The report also carries `what_this_run_does_not_prove`, generated from what
actually happened in this run (transition count, persisted evidence count)
rather than fixed boilerplate.

### Execution B captures

Directory: `evals/reports/staging/evidence/rehearsal-20261118T030751Z/`

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
| Evidence inherited from another SHA | No — every artifact records `9ee4713` |
| Gate marked PASS from unit/contract tests | No — every criterion is a live probe or a live run |
| Screenshot of a mockup or fixture | No — four live pages, two live metric endpoints; originals retained |
| Success manufactured after a failure | No — earlier failing runs were discarded, not edited; the defects they exposed are fixed in code |
| Credentials in evidence | No — checked with a JWT-shaped-string scan; bearer values never written |
| Unbounded model retries | No — 1 call used of 3; the runner has `max_retries=0` |
| Resolution without independent verification | No — `VERIFIED` by a second principal |
| Terminal outcome without audit records | No — bundle carries the decision and transition trail |
| Tests skipped to make the gate green | No — the full suite ran; counts below |

## Test evidence at `9ee4713`

`make verify` (local, `ITSM_TEST_STRICT=1`), exit 0:

| Suite | Passed |
| --- | --- |
| unit | 528 |
| contract | 57 |
| security | 45 |
| fault-injection | 20 |
| integration | 161 |
| scenarios | 24 |
| e2e | 12 |
| **total executions** | **847** |

Plus `ruff format --check` (251 files), `ruff check`, `mypy` (191 files),
and `bandit` over `src/`.

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
4. **The report told the truth about an older runner.** It claimed the
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
- **CI has not run on `9ee4713`.** The local suite passed; the pipeline has
  not been exercised for this SHA.

## Inheritance rule

Documentation-only commits may inherit this record only if they change no
`.github/`, `src/`, `tests/`, or `Makefile` files, do not alter criteria or
claims, and name the inherited code-bearing commit (`9ee4713`). Any change
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

`make demo-run` stops the generic `worker` first: the rehearsal drives the
durable consumer in-process, and two processes cannot bind the same consumer.
`make demo-worker-restart` puts it back.
