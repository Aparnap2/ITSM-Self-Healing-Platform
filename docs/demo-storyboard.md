# Demo storyboard — local staging, end-to-end evidence-backed audit workflow

Scope: the **local staging-equivalent stack** (`ITSM_ENV=staging`, OIDC only,
PostgreSQL + NATS JetStream + a local RS256 identity simulator) and the
two-execution demonstration it supports.

This document describes what is shown, in what order, and what evidence each
step leaves behind. It is not a marketing script: every step maps to a
machine-readable artifact produced by a command that actually ran.

> **Simulator notice.** Every identity, ITSM system and piece of
> infrastructure in this demo is simulated. The identity simulator is a
> signing authority with no application authorization; reviewer roles and
> tenant membership come only from the `reviewer_authorizations` table in
> PostgreSQL. No production credential or production mutation is involved.

## Two executions, two verdicts

| Execution | Question | Verdict |
| --- | --- | --- |
| **A — Staging readiness** | Can this stack actually run, with staging-compatible authentication, and is every component reachable? | `STAGING_READY` |
| **B — Full E2E** | Does one synthetic security event travel the whole pipeline and end in an independently verified, audited resolution? | `DEMO_QUALIFIED` |

Execution B is only attempted after Execution A passes. A failed A stops the
demo: a screenshot of running containers is not proof of a security
investigation, and we refuse to manufacture one.

## Preconditions

- Docker daemon reachable; ports `5532`, `4223`, `8223`, `3002`, `8001`,
  `8444`, `9091` free.
- `ITSM_GROQ_API_KEY` available (execution B only). The demo fails closed
  without it rather than silently disabling the investigation stage.
- `make demo-env` completed. Secrets are generated locally into `.env`
  (gitignored) and never printed.

## Execution A — staging readiness

`make demo-up` performs, in order:

1. **`demo-env`** — complete `.env` with generated local secrets.
2. **`docker compose up -d --build --wait`** — build images, start the stack,
   block until every healthcheck passes. The API healthcheck is a real HTTP
   request to `/healthz`, not a process liveness probe.
3. **Provision two reviewers** — `tools/provision_reviewer.py` inserts
   `reviewer-a` and `reviewer-b` into the reviewer directory for the demo
   tenant, with `reviewer` role and an audit-recorded reason.
4. **Readiness gate** — `tools/demo_readiness.py` probes the running stack.

`make demo-verify` re-runs the gate in full mode (adds a real token-expiry
wait) and writes `evals/reports/staging/readiness-*.json`.

The fast mode run by `demo-up` calls itself `STAGING_SMOKE`, not
`STAGING_READY`: it skips the time-boxed expiry probe, and a check that did
not run is not evidence. Only `--full` can pronounce `STAGING_READY`, and in
that mode a `NOT RUN` check fails the gate.

### What the readiness gate actually asserts

| Check | Live evidence |
| --- | --- |
| compose services | every required service `running`; every service that *has* a healthcheck is `healthy` |
| postgres migrations | `schema_migrations` count equals the number of migration files; reviewer rows exist |
| nats jetstream | `/jsz` over the monitor port: streams and consumers present |
| oidc discovery | the simulator's advertised `issuer` matches what the API is configured to trust |
| oidc jwks | one key, `alg=RS256` |
| api health | `GET /healthz` → 200 |
| oidc token accepted | a simulator-minted token → `GET /v1/findings` → 200 |
| malformed token rejected | `Bearer not-a-jwt` → 401 |
| missing token rejected | no `Authorization` header → 401 |
| unauthorized principal rejected | token for `reviewer-intruder` (valid signature, **no directory row**) → 401 |
| expired token rejected | same token 200 before expiry, 401 after a real TTL elapses |
| api metrics endpoint | `/metrics` serves the declared `itsm_*` metric families |
| prometheus targets | all four declared scrape targets `up` |
| outbox backlog | tenant-scoped rows either drained or still inside the 60 s grace window; `NOT APPLICABLE` on a fresh stack (no rows = no evidence) |

The `reviewer-intruder` case is the security-boundary demonstration: a
correctly signed token is still refused, because authentication is not
authorization.

### Screenshots (Execution A)

| File | What it is |
| --- | --- |
| `01-prometheus-targets.png` | browser capture of the live Prometheus `/targets` page, all jobs `UP` |
| `02-prometheus-itsm-metrics.png` | browser capture of a Prometheus query over the platform's own metric families |
| `03-api-metrics.png` | browser capture of the live API `/metrics` endpoint |

Grafana is **not configured** in this stack, so a dashboard screenshot is
`NOT APPLICABLE` — not "missing evidence".

Everything else in Execution A is CLI-only. Those steps are evidenced by raw
captured output (`compose-ps.json`, `readiness.json`, `prometheus-targets.json`,
`auth-matrix.json`), because a picture of a terminal would be a rendering, not
a capture, and we will not present a rendering as proof.

## Execution B — full E2E

`make demo-run` executes `tools/e2e_staging_run.py` against the running stack
with a fixed tenant (`11111111-1111-1111-1111-111111111111`) so the
provisioned reviewers and the rehearsal agree.

The rehearsal drives the JetStream consumer **in-process**, so `demo-run`
stops the generic `worker` container first: two processes cannot bind the same
durable consumer (`itsm-workflow`), and racing them would make the result
ambiguous. `make demo-worker-restart` puts the worker back. Execution A
already proved the worker starts and runs; Execution B proves the pipeline
processes a real event.

| Stage | What is shown | Evidence |
| --- | --- | --- |
| 1. Ingest | one synthetic CloudTrail-shaped security event enters through the signed webhook | webhook HTTP transcript |
| 2. Persist | the source event and its outbox row commit in one transaction | `source_events` row + `outbox` row |
| 3. Relay | the outbox row is published to NATS and marked published | outbox `status=published` |
| 4. Consume | the JetStream consumer processes the message | consumer processing record |
| 5. Detect | the deterministic detector creates the expected finding | `findings` row keyed by `(tenant, type, title)` |
| 6. Investigate | the model proposes; policy authorizes; the adapter executes only allowlisted actions, within the 3-call budget | investigation ledger with call count |
| 7. Evidence | a redacted excerpt (≤500 chars) is written in the same tenant transaction as the finding | evidence reference + hash |
| 8. Review | reviewer-a authenticates via OIDC and records a decision | decision row with proposal hash |
| 9. Verify | reviewer-b independently confirms and transitions the finding | transition row with distinct principal |
| 10. Audit | the bundle endpoint returns the full trail | `GET /v1/findings/{id}/bundle` |

The run writes a sanitized report to
`evals/reports/staging/staging-run-*.json`. It records the model-call count,
states the proposal's advisory nature, and lists what the run does **not**
prove.

### Screenshots (Execution B)

| File | What it is |
| --- | --- |
| `10-prometheus-ingestion.png` | live ingestion/consumer counters after the event was processed |
| `11-api-metrics-after-run.png` | live API metrics after the run |

The lifecycle, persistence and audit evidence is captured as raw JSON from
the database and the bundle endpoint. A screenshot of a JSON body in a
browser adds nothing over the body itself, and the body is what a reviewer
can diff.

## What this demo does not prove

- Production readiness of any kind.
- Throughput or latency under load (no load test is run; no latency gate
  exists).
- Multi-node failover (PostgreSQL and NATS are single-node).
- That spans reach a *real* OTLP backend (metrics are asserted; trace
  *content* is not).
- That the PostgreSQL runtime role has exactly the intended privilege set
  (the known privilege gap remains open).
- That the outbox relay drains **system** rows. The relay runs one scoped pass
  per registered tenant, so `outbox` rows with `tenant_id IS NULL` (the legacy
  `IncidentCreated` workflow) stay pending once any tenant exists. This is
  pre-existing behaviour, not introduced here; the demo's own
  `SourceEventIngested` rows are tenant-scoped and do drain.

## Repeatability

```sh
make demo-up       # Execution A: start + provision + readiness
make demo-verify   # Execution A in full mode, writes readiness JSON
make demo-run      # Execution B, writes the rehearsal report
make demo-down     # stop, keep volumes
make demo-reset    # wipe volumes and start clean
```

Every command is idempotent with respect to configuration: `demo-env` never
overwrites an existing value, and re-running `demo-up` against a healthy stack
changes nothing except re-confirming the same assertions.
