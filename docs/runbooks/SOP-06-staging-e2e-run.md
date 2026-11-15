# SOP-06 — Staging end-to-end rehearsal (selective investigation stage)

Scope: the manual staging rehearsal that exercises the **selective, bounded
agentic investigation stage** end to end: durable source-event ingest, the
signed HTTP webhook, the deterministic detection engine, the advisory model
proposal, and the evidence bundle.
Audience: operator with staging credentials for PostgreSQL, NATS and the
Groq API. **This rehearsal makes real, billed model calls.**

## Purpose

Produce one honest, reproducible artifact that shows what the agentic
investigation stage actually does in a staging deployment — and, just as
importantly, what it does **not** do.

The rehearsal is deliberately manual:

* it is **not** part of `make verify-ci` and never runs in CI;
* it makes **real, billed** Groq calls, bounded by a hard budget;
* it writes a JSON report that states the advisory nature of the model's
  proposal, the number of model calls used, and an explicit list of things
  the run does not prove.

Everything the automated suites assert about this stage is asserted offline:
`tests/unit/test_groq_investigation_model.py`,
`tests/unit/test_audit_consumer_entrypoint.py`,
`tests/unit/test_e2e_staging_runner.py` and
`tests/integration/test_audit_consumer_process.py` never make a model call.

## Scope

In scope:

- `tools/e2e_staging_run.py` — the manual runner.
- `python -m itsm_agent.workers.audit_consumer` — the packaged consumer
  (`src/itsm_agent/workers/audit_consumer.py`).
- `src/itsm_agent/investigations/groq_model.py` — the model adapter.
- `src/itsm_agent/investigations/service.py` — the advisory investigation
  service and its append-only ledger.
- The evidence bundle endpoint `GET /v1/findings/{id}/bundle`.

Out of scope: the 24-scenario evaluation harness (`evals/`), the CI gates,
production credentials, and any real cloud or ITSM SaaS mutation.

## Preconditions

- The stack is up and migrations are applied (SOP-01). Verify:

  ```sh
  docker compose ps
  uv run python -m migrations.apply --dsn "$ADMIN_DATABASE_URL"
  ```

- The runtime role exists and is constrained: `itsm_app` is `NOSUPERUSER`,
  `NOBYPASSRLS` (`migrations/010_runtime_role.sql`). Both the API and the
  audit consumer refuse to start against a role that can bypass RLS, so the
  DSN used below **must not** be a superuser connection.
- `ITSM_GROQ_API_KEY` is present in the operator's shell. It is never written
  to the report, never logged and never sent anywhere except the Groq
  chat-completions endpoint.
- The rehearsal is a rehearsal: it writes one tenant, one source event and
  one finding into the target database. Use a **staging** database, never a
  production one.

## The exact environment variables

| Variable | Required | Meaning |
| --- | --- | --- |
| `ITSM_POSTGRES_DSN` (or `DATABASE_URL`) | yes | Runtime DSN for the staging database. Must be the constrained role, not a superuser. |
| `ITSM_NATS_URL` (or `NATS_URL`) | yes | Staging NATS JetStream URL. |
| `ITSM_WEBHOOK_SECRET` | yes | Shared secret for the ingestion HMAC signature. |
| `ITSM_AUTH_HMAC_SECRET` | yes | Reviewer token secret (≥ 16 characters). The runner mints a reviewer bearer token with it. |
| `ITSM_GROQ_API_KEY` | yes | Model API key. Presence is what makes this a *billed* run. |
| `ITSM_GROQ_BASE_URL` | no | Defaults to `https://api.groq.com/openai/v1`. |
| `ITSM_GROQ_MODEL` | no | Defaults to `openai/gpt-oss-120b`. |
| `ITSM_GROQ_MAX_TOKENS` | no | Defaults to `2000`. |
| `ITSM_API_BASE_URL` | no | Base URL of the running API. Defaults to `http://127.0.0.1:8000`. |
| `ITSM_INVESTIGATION_LLM_BUDGET_CALLS` | no | **Hard cap on real model calls for the whole run.** Defaults to `3`. |

> **Reviewer authentication.** The runner mints an HMAC reviewer token
> (`itsm_agent.api.auth.mint_token`) with `ITSM_AUTH_HMAC_SECRET`. The
> application refuses HMAC authentication when `ITSM_ENV=staging`
> (`src/itsm_agent/config.py`), because HMAC is a development/test
> placeholder, not an identity provider. A real staging deployment
> therefore runs with OIDC, and the minted token is **not** accepted by it.
> In that case the rehearsal only proves the parts that do not need a
> reviewer credential, and the bundle fetch is reported as failed. Never
> weaken `ITSM_AUTH_MODE` in a production-like deployment to make this
> rehearsal pass.

The consumer process additionally reads:

| Variable | Default | Meaning |
| --- | --- | --- |
| `ITSM_INVESTIGATION_ENABLED` | `false` | Turns the advisory stage on. **When on, `ITSM_GROQ_API_KEY` must be present** or the process exits `2`. |
| `ITSM_INVESTIGATION_MAX_MODEL_CALLS` | `2` | Per-request model-call bound (1..5). |
| `ITSM_INVESTIGATION_MAX_TOOL_CALLS` | `5` | Per-request tool-call bound (1..20). |
| `ITSM_AUDIT_COVERED_SOURCES` | `cloudtrail,github,postgresql,pgaudit` | Sources whose approval coverage is considered complete. |
| `ITSM_AUDIT_FETCH_TIMEOUT_SECONDS` | `1.0` | JetStream fetch timeout. |
| `ITSM_AUDIT_POLL_SECONDS` | `0.05` | Idle poll interval. |
| `ITSM_AUDIT_SHUTDOWN_SECONDS` | `30` | Bounded graceful-shutdown timeout. |

## Procedure

### 1. Decide how the consumer runs

**Chosen approach: `--in-process` (the default).** The runner drives
`consume_source_event` itself, so the rehearsal does **not** require the
packaged consumer to be running locally. This is the simplest, most
reproducible staging rehearsal.

If you want to rehearse the *packaged process* instead, start it in another
shell and pass `--external-consumer`:

```sh
python -m itsm_agent.workers.audit_consumer
```

With `--external-consumer` the runner only seeds the event and waits (up to
60 s) for the finding to appear; if nothing appears it says so and tells you
to start the packaged consumer.

### 2. Run the rehearsal

```sh
make e2e-staging
```

or, equivalently:

```sh
uv run python tools/e2e_staging_run.py \
  --api-base-url "$ITSM_API_BASE_URL" \
  --report-path evals/reports/staging-run.json
```

The `make` target prints the required variables before running. If any
required variable is missing the runner prints exactly what is missing and
exits `2` **without touching the network**.

### 3. Read the artifact

The report is written to `evals/reports/staging-run.json` (override with
`--report-path`). It contains:

- `run` — timestamps, mode, tenant, API base URL, model, budget.
- `steps` — the ordered record of what happened (each step with an outcome).
- `source_event` — the seeded CloudTrail event and its ingest outcome.
- `webhook_ingest` — the HTTP status of the signed webhook delivery.
- `detection` — the finding, its severity/outcome, and its status **before
  and after** the investigation stage.
- `investigation` — the stage status, the number of model calls used, the
  advisory proposal, and the debug dump path when a model call failed.
- `evidence_bundle` — the bundle fetched from the API with a reviewer token.
- `statements` — the explicit statements, including `what_this_run_does_not_prove`.

The terminal output is a short human summary of the same information.

## The LLM budget rule

- One run may make **at most `ITSM_INVESTIGATION_LLM_BUDGET_CALLS` real model
  calls** (default **3**). Every call consumes one unit, successful or not.
- The runner builds the adapter with **no retries** (`max_retries=0`). A
  transport failure ends the call; there is no retry loop.
- When the budget is exhausted the runner stops and reports the exhaustion.
- On a model failure the **raw model response** is written to
  `/tmp/llm_debug_<UTC timestamp>.json` and the run stops. The file contains
  the error, the model id and the raw response — it never contains the API
  key. Attach it to the change ticket when reporting a model-side failure.
- The budget is a **cost** control, not a quality control. Three calls say
  nothing about the model's accuracy.

## Failure handling

| Symptom | Meaning | Action |
| --- | --- | --- |
| Exit `2`, "preflight FAILED" | a required variable is missing | set the named variable; no network was touched |
| Exit `2`, `ITSM_GROQ_API_KEY is missing` | the consumer was started with the stage enabled but no key | set the key, or set `ITSM_INVESTIGATION_ENABLED=false` |
| Exit `2`, "unsafe runtime database role" | the DSN can bypass RLS | use the constrained runtime role, not the owner connection |
| Exit `1`, "no finding appeared within 60s" | no consumer processed the event | start `python -m itsm_agent.workers.audit_consumer`, or use `--in-process` |
| Exit `1`, model failure | the model call failed | read `/tmp/llm_debug_<timestamp>.json`; do **not** retry in a loop |
| `evidence_bundle_error: HTTP 503` | the API process has no evidence-reference store wired | the rehearsal records it and continues; wire `evidence_references_repo` into the API to fetch bundles |
| `investigation.status = "FAILED"` | the proposal did not validate, or referenced evidence outside the snapshot | read the ledger rows in `investigation_requests` |

## What this does **not** prove

This section is the point of the rehearsal. The report repeats it verbatim in
`statements.what_this_run_does_not_prove`.

- **The source event is simulated.** The CloudTrail record is a literal
  fixture. No AWS account, no API call, no real identity was involved.
- **The model proposes; it never authorizes.** The proposal is stored
  verbatim in the append-only investigation ledger. It cannot change
  `findings.status`, approve an action, or run a command. The finding's
  status is recorded before and after the stage in the report so the claim
  can be checked rather than believed.
- **No independent verification of a real finding happened.** The rehearsal
  stops at the proposal and the evidence bundle. Recovery, verification and
  resolution are owned by the deterministic workflow and the reviewer
  transition path, and they are not exercised here.
- **No production credentials were used.** Every secret came from the
  operator's environment and none of them appears in the report.
- **The finding carries no evidence references yet**, so the model was given
  the question only and no evidence ids to reference. A proposal with empty
  `supporting_evidence` is the expected shape today, not a defect of the
  model.
- **The LLM budget is not an accuracy measure.** A run that completes within
  three calls proves nothing about how often the model is right.
- **The report is not a certification.** It is evidence of one rehearsal on
  one dataset.
- **The evidence bundle may be missing.** The bundle endpoint answers `503`
  when the API process has no evidence-reference store wired
  (`src/itsm_agent/api/app.py`), and the rehearsal records that as
  `evidence_bundle_error` instead of failing. The bundle is an observation,
  not the rehearsal's subject.

## Cleanup

The rehearsal leaves one tenant, one source event, one finding and (when the
stage ran) two investigation ledger rows in the target database. Remove them
with the administration connection when the database must be returned to a
clean state:

```sql
DELETE FROM investigation_proposals WHERE tenant_id = '<tenant-uuid>'::uuid;
DELETE FROM investigation_requests  WHERE tenant_id = '<tenant-uuid>'::uuid;
DELETE FROM findings              WHERE tenant_id = '<tenant-uuid>'::uuid;
DELETE FROM source_events         WHERE tenant_id = '<tenant-uuid>'::uuid;
DELETE FROM outbox                WHERE tenant_id = '<tenant-uuid>'::uuid;
DELETE FROM event_inbox           WHERE tenant_id = '<tenant-uuid>'::uuid;
DELETE FROM tenants               WHERE id        = '<tenant-uuid>'::uuid;
```

The tenant id is recorded in `run.tenant_id` in the report.

`/tmp/llm_debug_*.json` files contain raw model output; delete them once the
failure has been triaged.
