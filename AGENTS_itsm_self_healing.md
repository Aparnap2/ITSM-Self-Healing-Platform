# Coding Agent Instructions --- Headless ITSM Self-Healing Platform

## Role

Implement a portfolio-grade, headless ITSM self-healing platform.
Inspect the existing repository before changing anything. Build small,
testable vertical slices and report evidence, not assumptions.

## Mandatory rules

1.  Inspect repository instructions, README, manifests, source tree,
    tests, CI, migrations, and Git status before editing.
2.  Preserve existing user changes. Never reset, clean, or overwrite
    unexplained work.
3.  Do not rewrite the repository wholesale. Reuse and extend suitable
    code; record consequential architecture decisions in ADRs.
4.  Add a failing regression test before fixing a bug.
5.  Do not claim tests, merges, deployments, or external changes
    occurred without direct evidence.
6.  Use simulated identities, ITSM, and infrastructure only. Never
    request real production credentials.
7.  Never execute model-generated shell commands, code, SQL, or
    unrestricted tool arguments.
8.  LLMs may propose and explain. Deterministic policy code authorizes;
    allowlisted adapters execute; an independent verifier establishes
    success.
9.  Fail closed on unknown action/resource/principal, invalid model
    output, unavailable policy state, or missing durable audit capacity.
10. Persist action intent and idempotency key before a side effect.
11. If a side-effecting call times out or its result is uncertain,
    reconcile actual target state before retrying.
12. Never mark an incident resolved without independent postcondition
    verification.
13. Bound model attempts, tool calls, retries, output size, and workflow
    duration.
14. Validate all external events, LLM outputs, approvals, and tool
    inputs at trust boundaries using typed schemas.
15. Keep secrets out of Git, logs, traces, test output, and audit
    payloads. Run a secret scan and inspect the diff.
16. Deterministic tests must not require a remote LLM, external SaaS, or
    internet access.
17. Add dependencies only when justified; avoid speculative abstractions
    and scope expansion.
18. Report simulator licensing and SaaS-plan limitations accurately.
19. Distinguish planned, implemented, tested, and independently verified
    behavior.
20. Never call the system "production ready" without specifying exactly
    which test suites and failure conditions passed and what remains
    untested.

## Required workflow for every task

1.  Read repository instructions and `git status`.
2.  State scope and acceptance criteria.
3.  Identify relevant modules and tests.
4.  Add/update tests first where appropriate.
5.  Implement the smallest complete slice.
6.  Run targeted tests and relevant security/invariant tests.
7.  Run formatting, lint, typing, and the full relevant test suite.
8.  Inspect `git diff --check`, changed files, and secret-scan output.
9.  Update documentation and contracts if behavior changed.
10. Report exact commands, exit codes, test counts, limitations, and
    remaining work.

## Architecture constraints

-   Headless; no Streamlit or dashboard requirement.
-   Python, Pydantic v2, LangGraph.
-   PostgreSQL is the durable business-state source of truth.
-   NATS JetStream is the asynchronous event backbone.
-   Use inbox/outbox or an equivalent durable publishing protocol;
    assume at-least-once delivery and deduplicate.
-   Mockoon CLI simulates external HTTP APIs.
-   Moto is the default AWS API simulator. LocalStack is optional only
    after verifying current license/plan terms for the intended use.
-   Ollama is optional for local model inference; core tests must run
    without it.
-   OpenTelemetry/Prometheus provide observability.
-   Jira Service Management is the first optional real SaaS adapter;
    ServiceNow is later. Mockoon remains the deterministic acceptance
    environment.
-   Domain/application code must not import vendor-specific SDKs
    directly.
-   Real production mutations are out of scope and disabled in the
    portfolio baseline.

## Safety invariants

-   Unknown actions, targets, and principals are denied.
-   A model proposal is not authorization.
-   Approval must be authenticated, exact-action-bound, unexpired,
    single-use, and checked against current policy and preconditions.
-   No side effect before durable action intent and policy decision.
-   Uncertain outcomes trigger state reconciliation before retry.
-   A tool success response is not proof of recovery.
-   No resolution without independent verification.
-   Terminal outcomes must have the required audit records.
-   Retry exhaustion escalates; it never silently resolves.

## Phase order

### Phase 0 --- Audit only

Inspect the repository and report layout, Git status, instructions,
baseline tests, reusable components, gaps, and licensing/configuration
blockers. Do not make broad code changes.

### Phase 1 --- Domain and policy

Implement typed contracts, canonical hashes, state transitions, policy
matrix, reason codes, and unit tests. No LLM, network, database, or
vendor dependencies in the pure domain policy.

### Phase 2 --- Simulators and ports

Implement Mockoon fixtures, typed adapter ports, deterministic
infrastructure state, fault injection, and an independent verifier. Use
Moto for AWS API behavior only when needed.

### Phase 3 --- Persistence and events

Implement PostgreSQL schema/migrations, repositories, inbox/outbox, NATS
JetStream, deduplication, bounded redelivery, and dead-letter/escalation
handling.

### Phase 4 --- LangGraph workflow

Implement explicit nodes, conditional routes, durable checkpointing,
bounded execution, interrupt/resume, and crash-recovery tests.

### Phase 5 --- Approval and audit

Implement proposal-hash-bound approvals, expiry, authenticated approver
identity, one-time nonce, revalidation, append-only audit events, and
redaction.

### Phase 6 --- ITSM and observability

Implement Jira adapter only if access is available; otherwise Mockoon
remains the acceptance connector. Add outbound update
retry/reconciliation, OpenTelemetry traces, and Prometheus metrics.

### Phase 7 --- Evaluation and CI

Implement the 24-scenario harness, deterministic fault injection,
JSON/JUnit reports, security release gates, and optional separate model
evaluation.

### Phase 8 --- Portfolio and Loom

Document reproducible setup, generate actual evaluation evidence, and
prepare a 5--7 minute demo showing successful recovery, failed recovery,
and a security boundary.

## Required final report

Use this format for every completed task:

``` text
Task:
Scope completed:
Files changed:
Behavioral changes:
Tests run:
  - command:
  - exit code:
  - passed/failed/skipped:
Security invariants checked:
Manual verification:
Known limitations:
Remaining risks:
Git status:
Recommended next slice:
```

Do not proceed to the next phase until the current phase's acceptance
criteria are satisfied or the blocker is explicitly documented.
