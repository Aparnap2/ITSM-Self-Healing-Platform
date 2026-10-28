# Headless ITSM Self-Healing Platform

## Final PRD, Architecture, Contracts, SOP, Test Plan, Release Checklist, and Coding-Agent Instructions

**Status:** Baseline specification\
**Purpose:** FDE portfolio project demonstrating production-oriented
agentic AI, event-driven systems, safe tool execution, domain reasoning,
failure recovery, and evidence-driven engineering.\
**Deployment target:** Local Docker Compose first; no real enterprise
environment required.\
**Primary demonstration:** Detect a simulated service outage, diagnose
from evidence, execute an allowlisted remediation, independently verify
recovery, and update the incident with an audit reference.

------------------------------------------------------------------------

## 0. Executive decision

Build a **headless, event-driven IT operations agent**. It consumes
incident and alert events, gathers diagnostic evidence, proposes a
bounded action, passes it through deterministic policy enforcement,
executes only approved tools, verifies the actual resulting state, and
records an auditable outcome.

The portfolio must demonstrate that the system is safe and
recoverable---not merely that an LLM can call tools.

### Locked decisions

-   No Streamlit, no UI requirement, and no user-facing dashboard.
-   Python application with typed domain contracts and Pydantic
    validation.
-   LangGraph for explicit stateful workflow orchestration, conditional
    routing, and interrupt/resume where appropriate.
-   PostgreSQL as the durable source of truth for incidents, workflow
    state, approvals, action attempts, and audit events.
-   NATS JetStream for durable asynchronous event delivery.
-   Mockoon CLI for deterministic HTTP APIs representing ITSM, identity,
    and service-management systems.
-   Moto as the default AWS API simulator for tests. LocalStack is
    optional only after verifying that its current license and plan
    permit the intended portfolio use.
-   Ollama for local development-time LLM inference. CI and
    security-critical tests must not depend on an LLM or network.
-   OpenTelemetry for traces and metrics; Prometheus for operational
    metrics.
-   Docker Compose for local orchestration.
-   Jira Service Management is the first optional external SaaS
    connector. ServiceNow is a later adapter and is not required for
    acceptance.
-   No real production credentials, corporate data, or live production
    infrastructure are needed.
-   Every integration must be behind an adapter/port; domain logic must
    not import vendor SDKs directly.

### First acceptance scenario

1.  A simulated ITSM system creates an incident for a known unhealthy
    service.
2.  The event is validated, deduplicated, persisted, and queued.
3.  The agent gathers health and log evidence through read-only tools.
4.  It chooses a remediation from a finite allowlist.
5.  The policy engine validates resource, action, environment, risk,
    approval requirement, and current state.
6.  The action adapter performs a simulated restart or equivalent safe
    repair.
7.  An independent verifier reads service state after the action.
8.  The incident is resolved only if the verification contract passes.
9.  The ITSM adapter records the result and audit reference.
10. If any required condition fails, the incident remains unresolved and
    is escalated.

------------------------------------------------------------------------

## 1. Product requirements document (PRD)

### 1.1 Problem statement

IT support teams receive noisy and ambiguous incidents, spend time
collecting evidence across tools, and perform repetitive diagnostics and
low-risk remediation. Uncontrolled LLM agents introduce a separate risk:
they may misinterpret requests, invent evidence, exceed authorization,
repeat side effects, or claim success without verifying the system.

This project demonstrates a controlled alternative: **agentic reasoning
inside deterministic operational boundaries**.

### 1.2 Target audience

-   Forward Deployed Engineer (FDE) hiring teams.
-   Technical interviewers evaluating agentic AI, systems integration,
    security, and operational maturity.
-   Engineers evaluating event-driven architecture, durable workflows,
    and testability.

### 1.3 Product goals

1.  Demonstrate one complete, reproducible incident-to-resolution
    workflow.
2.  Keep model reasoning separate from policy decisions and side
    effects.
3.  Demonstrate recovery from duplicate delivery, transient failure,
    process interruption, and uncertain action outcomes.
4.  Make every outcome explainable through persisted evidence.
5.  Provide a repeatable evaluation harness and CI release gates.
6.  Run locally with free/open-source components, subject to any
    external SaaS and simulator plan/license restrictions.
7.  Make the system easy to explain and demonstrate in a 5--7 minute
    Loom recording.

### 1.4 Non-goals

-   Production deployment into a real enterprise.
-   Real corporate Active Directory or identity-provider changes.
-   Unrestricted AWS access or arbitrary shell execution.
-   Fully autonomous remediation of arbitrary incidents.
-   Multi-tenant commercial SaaS.
-   A graphical operator dashboard.
-   Replacing Jira/ServiceNow.
-   Claiming enterprise-grade uptime based only on local tests.
-   Adding Kafka, Kubernetes, Temporal, a vector database, or a second
    ITSM connector without a concrete demonstrated need.

### 1.5 Users and actors

  -----------------------------------------------------------------------
  Actor                               Responsibility
  ----------------------------------- -----------------------------------
  Incident source                     Emits an incident or alert event.

  Agent workflow                      Coordinates evidence collection,
                                      reasoning, policy checks, action,
                                      and verification.

  Policy engine                       Deterministically allows, denies,
                                      or requires approval.

  Tool adapter                        Performs a narrowly defined
                                      operation against a simulator or
                                      external integration.

  Approver                            Authenticates and approves/rejects
                                      an exact proposed action when
                                      required.

  Independent verifier                Reads actual simulator state and
                                      determines whether the desired
                                      state was reached.

  Evaluator                           Seeds scenarios and compares
                                      observed results with explicit
                                      expectations.

  Coding agent                        Implements scoped work, runs tests,
                                      and reports evidence without
                                      claiming unverified success.
  -----------------------------------------------------------------------

### 1.6 Functional requirements

**FR-01 --- Event ingestion** - Accept events from a test harness and
HTTP webhook adapter. - Validate payloads and reject invalid events. -
Authenticate webhook requests using a configured secret or signature
scheme. - Apply request-size and rate limits at the API boundary. -
Assign a correlation ID and idempotency key. - Persist accepted events
before acknowledging durable acceptance. - Return a clear status for
accepted, duplicate, invalid, or temporarily unavailable events.

**FR-02 --- Canonical incident model** - Normalize source-specific
fields into a provider-neutral incident contract. - Preserve source
system, source incident ID, external event ID, timestamps, severity,
service, summary, and sanitized evidence references. - Keep
source-specific payloads out of core business logic.

**FR-03 --- Triage** - Extract incident category, affected service,
suspected failure class, urgency, and missing information. - Use
schema-constrained output where supported; validate again with
Pydantic. - Treat ticket text, logs, and external content as untrusted
data, never as instructions to override policy. - If required fields are
missing or confidence is insufficient, request clarification through the
adapter or escalate without mutation. - Limit retries and record
model/version/configuration metadata.

**FR-04 --- Diagnostics** - Gather health status, selected log excerpts,
service metadata, and recent simulated events through read-only
allowlisted tools. - Record each observation with source, timestamp, and
correlation ID. - Distinguish observed facts from model hypotheses. - Do
not allow the model to fabricate tool results.

**FR-05 --- Policy enforcement** - Deny by default. - Validate action,
target resource, environment, principal, risk, approval requirement, and
current incident state. - Unknown resource/action combinations are
denied. - LLM output is never a source of authorization. - Policy
decision is recorded before any side effect.

**FR-06 --- Human approval** - Persist the exact action proposal and its
canonical hash. - Bind the approval to incident ID, action ID, target,
parameters, policy version, expiry, and approver identity. - Reject
expired, replayed, mismatched, or unauthorized approvals. - Do not
execute while pending. - A UI is not required; approval can be submitted
through an authenticated internal API or a seeded test fixture. -
Approval must be independently authenticated; a request body claiming
`"approved": true` is not sufficient.

**FR-07 --- Action execution** - Invoke only registered, allowlisted
tools with validated typed arguments. - No arbitrary shell, Python, SQL,
or model-generated code execution. - Use idempotency keys for
side-effecting actions. - Record intent before execution and outcome
after execution. - Represent uncertain outcomes explicitly; reconcile
actual state before retrying. - Apply bounded retries, timeouts, and a
maximum action budget.

**FR-08 --- Independent verification** - Verify the actual target state
using a read-only path distinct from the action response. - Resolve an
incident only when the verification predicate passes. - A successful
HTTP response or LLM statement is not verification. - If verification
fails or is unavailable, retain a non-resolved status and escalate.

**FR-09 --- ITSM updates** - Update the source incident with status,
concise summary, action result, verification result, and audit
reference. - Treat ITSM write failure as a retryable delivery task, not
proof that the underlying action failed. - Use an outbox/reconciliation
mechanism so the action outcome and external update can recover
independently.

**FR-10 --- Audit** - Record event receipt, normalized input, evidence
references, model proposal, policy decision, approval, tool intent, tool
result, verification, status transitions, and outbound update. - Audit
records are append-only at the application layer. - Do not log secrets
or unnecessary sensitive data. - Every record includes timestamp,
correlation ID, actor/component, event type, and relevant entity IDs.

**FR-11 --- Observability** - Propagate trace/correlation IDs through
API, event, graph, tools, and outbound adapter. - Emit structured logs
and metrics for queue depth, event age, retries, workflow duration, tool
errors, approval wait time, and unresolved incidents. - Keep
observability optional for core unit tests but available in Compose
integration tests.

**FR-12 --- Evaluation** - Provide seeded deterministic scenarios and a
machine-readable report. - Verify final state independently of agent
narration. - Record scenario ID, seed, model metadata (when used),
observed tool calls, final state, invariant violations, timing, and
result. - Separate deterministic tests from model-dependent evaluations.

### 1.7 Non-functional requirements

-   **Safety:** zero unauthorized side effects in the defined
    adversarial suite.
-   **Determinism:** policy and state-transition logic must be
    deterministic.
-   **Recoverability:** process restarts must not silently lose accepted
    incidents or pending approvals.
-   **Idempotency:** duplicate delivery must not cause duplicate logical
    incidents or uncontrolled duplicate side effects.
-   **Boundedness:** retries, tool calls, workflow duration, and model
    attempts have explicit limits.
-   **Auditability:** all terminal outcomes have complete required audit
    events.
-   **Portability:** domain logic has no direct vendor SDK dependency.
-   **Resource awareness:** services must be runnable on a modest 16 GB
    RAM development machine with a small local model or with model calls
    disabled.
-   **Security:** secrets are externalized; services bind privately by
    default; test fixtures contain no real credentials.
-   **Reproducibility:** one documented command starts the stack and one
    documented command runs the deterministic acceptance suite.

### 1.8 Definition of done

A feature is done only when: 1. Requirements and invariants are
documented. 2. A failing regression test was added first for a bug fix,
or acceptance tests exist for a feature. 3. Implementation is complete
within scope. 4. Unit, integration, and relevant security tests pass. 5.
Formatting, lint, typing, and static checks pass as configured. 6. The
full relevant test command exits successfully. 7. Git diff and secret
scan are reviewed. 8. Documentation and example configuration are
updated. 9. Evidence is reported: exact commands, exit codes, counts,
and limitations. 10. No claim is made about a test, merge, deployment,
or external state that was not observed.

------------------------------------------------------------------------

## 2. Architecture and system boundaries

### 2.1 Logical architecture

``` text
ITSM / Alert Sources
        |
        v
Webhook/API Ingestion
  - authentication
  - schema validation
  - deduplication
  - durable acceptance
        |
        v
PostgreSQL Inbox + Outbox
        |
        v
NATS JetStream
        |
        v
Workflow Worker (LangGraph)
  1. load/normalize incident
  2. gather read-only evidence
  3. triage / propose diagnosis
  4. evaluate deterministic policy
  5. approval gate if required
  6. execute allowlisted action
  7. independently verify state
  8. update incident / escalate
        |
        +------> PostgreSQL state, checkpoints, audit
        +------> Mockoon ITSM / identity / service APIs
        +------> Moto or licensed LocalStack AWS adapter
        +------> OpenTelemetry / Prometheus
```

### 2.2 Component responsibilities

**API/inbox** - Accepts events, validates source authentication, applies
limits, stores a durable inbox record. - Does not run long model calls
or remediation synchronously in the webhook request. - Acknowledges only
after durable acceptance or returns a retryable error.

**Outbox publisher** - Publishes persisted events to NATS. - Marks
publication state only after broker acknowledgement. - Can safely retry
publication; consumers must deduplicate.

**NATS consumer** - Uses explicit acknowledgements, durable consumer
configuration, bounded redelivery, and a dead-letter/escalation path. -
Does not assume exactly-once delivery. Design for at-least-once delivery
plus idempotent handlers.

**Workflow worker** - Runs the explicit LangGraph state machine. -
Persists checkpoint/state to PostgreSQL. - Enforces node budgets and
timeouts. - Does not hold an open HTTP request for the entire workflow.

**Policy engine** - Pure deterministic domain service. - No LLM call,
network access, or mutable global policy state. - Returns a typed
decision with reason codes and policy version.

**Tool registry** - Maps a known action type to a typed adapter. -
Rejects unknown action types and unrecognized parameters. - Separates
read-only diagnostic tools from side-effecting tools.

**Verifier** - Reads actual target state independently. - Does not reuse
the action's success message as evidence. - Emits a typed verification
result.

**Audit repository** - Persists append-only audit events. - Uses
redaction and data minimization. - Links records by incident, workflow,
action, and correlation IDs.

**Scenario runner** - Seeds initial state and faults, submits events,
waits for bounded completion, checks invariants, and emits JSON/JUnit
reports. - Does not use LLM prose as the expected result.

### 2.3 Event-driven reliability rules

-   Use a transactional outbox or an equivalent protocol for
    database-to-broker publication.
-   Use an inbox/deduplication table for external event IDs.
-   Assume messages can be delivered more than once.
-   Acknowledge a message only after the required durable transition has
    committed.
-   Do not retry a side-effecting action blindly after an ambiguous
    timeout.
-   Use explicit retry classes: transient, permanent, policy denial, and
    uncertain outcome.
-   After retry exhaustion, dead-letter or escalate with evidence.
-   Use a reconciliation worker for stuck outbox rows, unprocessed inbox
    events, and pending ITSM updates.
-   Persist state transitions and audit events transactionally where
    possible.

### 2.4 Failure domains

  -----------------------------------------------------------------------
  Failure                             Expected behavior
  ----------------------------------- -----------------------------------
  LLM unavailable                     Deterministic workflows that do not
                                      need the LLM continue;
                                      model-dependent triage escalates or
                                      retries within a limit.

  Invalid model output                Validate, perform a bounded retry
                                      if safe, then escalate; no action
                                      occurs from invalid output.

  NATS unavailable                    Persist accepted events; outbox
                                      retries publication; no false
                                      acceptance if persistence fails.

  PostgreSQL unavailable              Fail closed; do not execute new
                                      side effects without durable
                                      state/audit capacity.

  Tool timeout before action          Retry only if classified safe and
                                      within budget.

  Tool timeout with uncertain side    Reconcile target state before
  effect                              retry.

  Verification fails                  Do not resolve incident; escalate
                                      and preserve evidence.

  ITSM update fails after successful  Preserve verified action result and
  repair                              retry outbound update separately.

  Worker crashes                      Resume from durable state;
                                      reconcile in-flight actions.

  Approval expires                    Reject and escalate/re-request;
                                      never execute expired approval.
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## 3. Workflow specification

### 3.1 Canonical workflow

``` text
RECEIVED
  -> VALIDATED
  -> NORMALIZED
  -> TRIAGING
  -> DIAGNOSTICS
  -> POLICY_EVALUATION
      -> DENIED -> ESCALATED
      -> APPROVAL_REQUIRED -> WAITING_APPROVAL
          -> REJECTED/EXPIRED -> ESCALATED
          -> APPROVED -> READY_TO_EXECUTE
      -> ALLOWED -> READY_TO_EXECUTE
  -> ACTION_INTENT_RECORDED
  -> EXECUTING
  -> VERIFYING
      -> VERIFIED -> UPDATE_ITSM -> RESOLVED
      -> NOT_VERIFIED -> ESCALATED
  -> terminal status
```

All transitions must be explicit. A node must not write arbitrary status
strings. Invalid transitions fail closed and are audited.

### 3.2 LangGraph nodes

1.  `validate_event`
2.  `normalize_incident`
3.  `load_or_create_workflow`
4.  `triage_incident`
5.  `collect_diagnostics`
6.  `select_remediation_candidate`
7.  `evaluate_policy`
8.  `request_approval` (interrupt/persist)
9.  `validate_approval`
10. `record_action_intent`
11. `execute_action`
12. `reconcile_uncertain_action`
13. `verify_postcondition`
14. `update_itsm`
15. `escalate`
16. `finalize_audit`

Conditional routing uses typed statuses and explicit route functions. No
route decision should depend on substring matching in natural-language
output.

### 3.3 State model

Workflow state is a short-lived orchestration snapshot, not the
canonical database. Store only what is needed to resume safely: -
workflow and incident IDs - current status/node - normalized request -
evidence references and hashes - candidate action - policy decision
reference - approval request reference - action attempt reference -
verification reference - retry counters and deadline - correlation/trace
IDs

Large raw logs should live in the simulator/evidence store; the graph
state stores references and sanitized summaries.

### 3.4 Bounded execution rules

Suggested initial defaults, configurable: - maximum model attempts per
node: 2 - maximum diagnostic tool calls per workflow: 8 - maximum action
attempts: 1 for non-idempotent actions; at most 2 only where
reconciliation proves safe - maximum transient retry attempts per
integration: 3 with exponential backoff and jitter - maximum workflow
wall-clock budget: 120 seconds for the deterministic demo, excluding
human approval wait - maximum evidence size per item: configured cap;
truncate with explicit metadata, never silently - maximum approval
lifetime: 15 minutes in test scenarios - all limits are enforced in code
and covered by tests

Human approval wait is not counted as an active worker execution loop.
Persist and resume rather than holding a worker or database transaction
open.

### 3.5 Primary workflow sequence

1.  Receive incident event.
2.  Authenticate and validate the source.
3.  Deduplicate on source + external event ID.
4.  Persist inbox record and publish through outbox.
5.  Normalize incident.
6.  Gather health status and bounded diagnostic evidence.
7.  Ask the LLM to classify and propose an action candidate, if
    required.
8.  Validate structured output.
9.  Evaluate candidate against deterministic policy.
10. If approval is required, persist exact proposal hash and wait.
11. Revalidate policy and target state after approval; approval does not
    override changed policy or stale preconditions.
12. Persist action intent and idempotency key.
13. Execute through registered adapter.
14. If outcome is uncertain, inspect target state before any retry.
15. Independently verify postcondition.
16. Update ITSM and attach audit reference.
17. Persist terminal status and emit metrics.
18. If any critical step fails, escalate and retain a non-resolved
    status.

------------------------------------------------------------------------

## 4. Standard operating procedures (SOPs)

### SOP-01: Start the local environment

1.  Confirm Docker Engine and Compose are installed.
2.  Copy `.env.example` to `.env`; never commit `.env`.
3.  Use only local test credentials generated for the simulator.
4.  Run configuration validation.
5.  Start dependencies with the documented Compose command.
6.  Wait for health checks, not fixed sleeps.
7.  Run database migrations.
8.  Seed simulator fixtures.
9.  Run a smoke test.
10. Inspect service health and logs before running scenarios.

**Pass condition:** PostgreSQL, NATS, API, worker, and required
simulators are healthy; migrations succeed; no real external credentials
are required.

### SOP-02: Run the successful self-healing scenario

1.  Reset the test environment to a known seed.
2.  Seed `payments-api` as unhealthy with a known recoverable failure.
3.  Submit a test incident through the simulated ITSM API.
4.  Wait for the workflow with a bounded timeout.
5.  Inspect the event timeline and trace.
6.  Confirm diagnostics cite simulator evidence.
7.  Confirm policy permitted the action.
8.  Confirm one action intent and one logical action were recorded.
9.  Independently inspect target state.
10. Confirm ITSM status is resolved only after verification.
11. Export the scenario report.

### SOP-03: Run an authorization denial scenario

1.  Seed a principal without permission for the requested
    action/resource.
2.  Submit an access request.
3.  Confirm the model cannot modify the principal or policy.
4.  Confirm the policy engine returns a denial reason code.
5.  Confirm no side-effecting tool was called.
6.  Confirm the incident is escalated/denied, not resolved.
7.  Confirm audit records contain the decision but no secrets.

### SOP-04: Run an approval scenario

1.  Seed a valid action that requires approval.
2.  Submit the incident and wait for `WAITING_APPROVAL`.
3.  Confirm no execution attempt exists.
4.  Submit a valid authenticated approval for the exact proposal.
5.  Confirm policy is reevaluated and preconditions are rechecked.
6.  Confirm execution occurs once.
7.  Repeat with expired, mismatched, replayed, and unauthorized approval
    tokens; all must be rejected.

### SOP-05: Recover from a worker interruption

1.  Seed a recoverable incident.
2.  Configure the simulator to perform the action but make the response
    time out.
3.  Stop the worker at the intended fault-injection point.
4.  Restart the worker.
5.  Confirm the workflow resumes from durable state.
6.  Confirm the adapter reconciles actual state before retrying.
7.  Confirm no duplicate side effect occurs.
8.  Confirm final verification and audit history are complete.

### SOP-06: Respond to an unresolved incident

1.  Seed a service that cannot recover using the allowed remediation.
2.  Run the workflow.
3.  Confirm retry and action budgets are respected.
4.  Confirm the verifier rejects recovery.
5.  Confirm incident status remains unresolved/escalated.
6.  Confirm the notification does not claim success.
7.  Confirm evidence and failure reason are persisted.

### SOP-07: Reset and reproduce a scenario

1.  Stop scenario workers.
2.  Reset only disposable test data using an explicit test-only command.
3.  Never run destructive reset commands against an unrecognized
    database URL.
4.  Re-seed the fixed scenario version and seed.
5.  Re-run the test.
6.  Compare result, tool-call sequence, invariants, and final state.
7.  Record expected nondeterminism for model-dependent tests.

### SOP-08: Release candidate verification

1.  Ensure the working tree is understood; do not discard user changes.
2.  Run formatting, lint, type checks, and unit tests.
3.  Run policy/security tests.
4.  Run integration tests with local dependencies.
5.  Run scenario acceptance tests.
6.  Run secret scan and inspect the diff.
7.  Verify migrations and clean startup from an empty test database.
8.  Confirm deterministic tests work without network or LLM.
9.  Generate evaluation reports.
10. Document any failures and blockers; do not waive a security
    invariant to obtain a green build.

------------------------------------------------------------------------

## 5. Domain data model

Use UUIDs for internal IDs and UTC timestamps. Use database constraints
for uniqueness and valid relationships. Do not treat LangGraph
checkpoint state as the only record of business state.

### 5.1 Core entities

**Incident** - `id: UUID` - `source_system: str` -
`source_incident_id: str` - `external_event_id: str | None` -
`title: str` - `description: str` (sanitized and size-limited) -
`service_name: str` - `severity: Severity` - `status: IncidentStatus` -
`created_at`, `updated_at` - `correlation_id: UUID` -
`current_workflow_id: UUID | None` - `resolution_summary: str | None` -
`audit_reference: str | None`

Unique constraint: `(source_system, source_incident_id)`. External event
deduplication: `(source_system, external_event_id)` when the external
event ID is present.

**WorkflowRun** - `id: UUID` - `incident_id: UUID` -
`workflow_version: str` - `status: WorkflowStatus` -
`current_node: str` - `checkpoint_ref: str | None` -
`attempt_count: int` - `started_at`, `updated_at`,
`finished_at: datetime | None` - `correlation_id: UUID` -
`last_error_code: str | None`

**Evidence** - `id: UUID` - `incident_id: UUID` - `workflow_id: UUID` -
`kind: EvidenceKind` - `source: str` - `observed_at: datetime` -
`content_hash: str` - `sanitized_summary: str` -
`external_ref: str | None` - `trust_level: EvidenceTrust`

**PolicyDecision** - `id: UUID` - `incident_id: UUID` -
`workflow_id: UUID` - `principal_id: str` - `resource_id: str` -
`action_type: ActionType` - `decision: PolicyOutcome` -
`reason_codes: list[str]` - `policy_version: str` -
`evaluated_at: datetime` - `proposal_hash: str`

**ApprovalRequest** - `id: UUID` - `incident_id: UUID` -
`workflow_id: UUID` - `proposal_hash: str` - `action_type: ActionType` -
`resource_id: str` - `parameters_hash: str` - `status: ApprovalStatus` -
`requested_at`, `expires_at` - `decided_at: datetime | None` -
`approver_id: str | None` - `decision_reason: str | None` -
`replay_nonce_hash: str`

**ActionAttempt** - `id: UUID` - `incident_id: UUID` -
`workflow_id: UUID` - `action_type: ActionType` - `resource_id: str` -
`idempotency_key: str` - `proposal_hash: str` - `status: ActionStatus` -
`attempt_number: int` - `intent_recorded_at: datetime` - `started_at`,
`finished_at: datetime | None` - `adapter_name: str` -
`result_code: str | None` - `result_summary: str | None` -
`result_evidence_id: UUID | None`

Unique constraint: `idempotency_key`; enforce the intended uniqueness of
action identity in the repository/database.

**Verification** - `id: UUID` - `incident_id: UUID` -
`action_attempt_id: UUID` - `predicate: str` - `passed: bool` -
`observed_state: dict` - `evidence_id: UUID` - `verified_at: datetime` -
`verifier_version: str`

**AuditEvent** - `id: UUID` - `occurred_at: datetime` -
`correlation_id: UUID` - `incident_id: UUID | None` -
`workflow_id: UUID | None` - `actor_type: str` - `actor_id: str` -
`event_type: str` - `entity_type: str | None` -
`entity_id: UUID | None` - `payload_redacted: dict` -
`previous_hash: str | None` (optional chain for tamper-evidence
demonstration) - `event_hash: str | None`

Append-only application semantics. A hash chain can provide tamper
evidence, not absolute immutability; do not describe it as a substitute
for external immutable storage.

**InboxEvent** - `id: UUID` - `source_system: str` -
`external_event_id: str` - `payload_hash: str` -
`received_at: datetime` - `status: InboxStatus` - `attempt_count: int` -
`last_error: str | None`

Unique constraint: `(source_system, external_event_id)`.

**OutboxEvent** - `id: UUID` - `event_type: str` -
`aggregate_id: UUID` - `payload: dict` - `created_at: datetime` -
`published_at: datetime | None` - `publish_attempts: int` -
`last_error: str | None`

### 5.2 Enums

``` python
from enum import StrEnum

class Severity(StrEnum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"

class IncidentStatus(StrEnum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    IN_PROGRESS = "IN_PROGRESS"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    RESOLVED = "RESOLVED"
    ESCALATED = "ESCALATED"
    REJECTED = "REJECTED"

class WorkflowStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    ESCALATED = "ESCALATED"
    CANCELLED = "CANCELLED"

class ActionType(StrEnum):
    RESTART_SERVICE = "RESTART_SERVICE"
    CLEAR_SIMULATED_CACHE = "CLEAR_SIMULATED_CACHE"
    GRANT_TEST_RESOURCE_ACCESS = "GRANT_TEST_RESOURCE_ACCESS"

class PolicyOutcome(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"

class ApprovalStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    INVALIDATED = "INVALIDATED"

class ActionStatus(StrEnum):
    INTENT_RECORDED = "INTENT_RECORDED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"
    RECONCILED = "RECONCILED"
    CANCELLED = "CANCELLED"

class EvidenceKind(StrEnum):
    HEALTH_CHECK = "HEALTH_CHECK"
    LOG_EXCERPT = "LOG_EXCERPT"
    SERVICE_METADATA = "SERVICE_METADATA"
    ACTION_RESULT = "ACTION_RESULT"
    POSTCONDITION_CHECK = "POSTCONDITION_CHECK"

class EvidenceTrust(StrEnum):
    UNTRUSTED_EXTERNAL = "UNTRUSTED_EXTERNAL"
    SIMULATOR_OBSERVATION = "SIMULATOR_OBSERVATION"
    POLICY_ENGINE = "POLICY_ENGINE"
    INDEPENDENT_VERIFIER = "INDEPENDENT_VERIFIER"

class InboxStatus(StrEnum):
    RECEIVED = "RECEIVED"
    PROCESSING = "PROCESSING"
    PROCESSED = "PROCESSED"
    REJECTED = "REJECTED"
    DEAD_LETTERED = "DEAD_LETTERED"
```

------------------------------------------------------------------------

## 6. Pydantic contracts

Use Pydantic v2. Treat these as starting contracts; the coding agent
must put them in the appropriate domain modules, add tests, and avoid a
single giant schema file. Use `extra="forbid"` for model/tool input
contracts and validate at trust boundaries.

### 6.1 Shared base and incident event

``` python
from datetime import datetime, timezone
from typing import Annotated, Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

ShortText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=240)]
SafeIdentifier = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]

class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

class IncidentCreated(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    event_id: UUID
    source_system: SafeIdentifier
    source_incident_id: SafeIdentifier
    external_event_id: SafeIdentifier
    occurred_at: datetime
    received_at: datetime | None = None
    correlation_id: UUID
    title: ShortText
    description: Annotated[str, StringConstraints(max_length=8000)]
    service_name: SafeIdentifier
    severity: Literal["P1", "P2", "P3", "P4"]
    environment: Literal["local", "test", "staging"]
```

Rules: - Normalize timestamps to timezone-aware UTC at the boundary. -
Do not accept `production` as an executable target in this portfolio
baseline. - Never assume a claimed user email in a ticket is the
authenticated requester. - Sanitize/control log content before rendering
or passing it to the model. - Source-specific payload is stored
separately and redacted.

### 6.2 Triage output

``` python
class TriageResult(StrictModel):
    category: Literal[
        "SERVICE_UNHEALTHY",
        "ACCESS_REQUEST",
        "NETWORK_ISSUE",
        "UNKNOWN",
    ]
    affected_service: SafeIdentifier | None
    suspected_failure_class: Literal[
        "PROCESS_DOWN",
        "DEPENDENCY_FAILURE",
        "CONFIGURATION",
        "PERMISSION",
        "UNKNOWN",
    ]
    urgency: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    missing_information: list[ShortText] = Field(default_factory=list, max_length=10)
    evidence_ids: list[UUID] = Field(default_factory=list, max_length=20)
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: Annotated[str, StringConstraints(max_length=1500)]
```

The model may recommend an action candidate, but the output must not
contain an `authorized` boolean that is trusted by the executor.
Confidence is an evaluation signal, not an authorization signal.

### 6.3 Diagnostic evidence

``` python
class DiagnosticObservation(StrictModel):
    evidence_id: UUID
    source: SafeIdentifier
    kind: Literal["HEALTH_CHECK", "LOG_EXCERPT", "SERVICE_METADATA"]
    observed_at: datetime
    content_hash: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
    sanitized_summary: Annotated[str, StringConstraints(max_length=2000)]
    structured_facts: dict[str, str | int | float | bool | None] = Field(
        default_factory=dict, max_length=30
    )
    trust_level: Literal["UNTRUSTED_EXTERNAL", "SIMULATOR_OBSERVATION"]
```

Raw untrusted log content must not be treated as a trusted instruction.
Store only bounded evidence and preserve its origin.

### 6.4 Action proposal

``` python
class RestartServiceParameters(StrictModel):
    action_type: Literal["RESTART_SERVICE"]
    service_name: SafeIdentifier
    environment: Literal["local", "test", "staging"]
    reason: Annotated[str, StringConstraints(max_length=500)]
    evidence_ids: list[UUID] = Field(min_length=1, max_length=10)

class ClearCacheParameters(StrictModel):
    action_type: Literal["CLEAR_SIMULATED_CACHE"]
    service_name: SafeIdentifier
    environment: Literal["local", "test", "staging"]
    reason: Annotated[str, StringConstraints(max_length=500)]
    evidence_ids: list[UUID] = Field(min_length=1, max_length=10)

class GrantTestAccessParameters(StrictModel):
    action_type: Literal["GRANT_TEST_RESOURCE_ACCESS"]
    principal_id: SafeIdentifier
    resource_id: SafeIdentifier
    environment: Literal["local", "test"]
    ticket_reference: SafeIdentifier

ActionProposal = RestartServiceParameters | ClearCacheParameters | GrantTestAccessParameters
```

Use a discriminated union in the actual implementation. The adapter
registry must reject unknown action types. A proposal is data, not
permission.

### 6.5 Policy decision

``` python
class PolicyDecisionResult(StrictModel):
    decision_id: UUID
    outcome: Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]
    action_type: SafeIdentifier
    resource_id: SafeIdentifier
    principal_id: SafeIdentifier
    policy_version: SafeIdentifier
    reason_codes: list[SafeIdentifier] = Field(min_length=1, max_length=20)
    proposal_hash: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
    evaluated_at: datetime
```

Policy implementation requirements: - Pure deterministic function for a
given input and policy snapshot. - Unknown principal, resource,
environment, or action =\> deny. - A model's confidence cannot turn a
denial into an allow. - A human approval does not override a currently
denied policy. - Reevaluate policy and preconditions after approval and
immediately before execution.

### 6.6 Approval

``` python
class ApprovalRequest(StrictModel):
    approval_id: UUID
    incident_id: UUID
    workflow_id: UUID
    proposal_hash: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
    action_type: SafeIdentifier
    resource_id: SafeIdentifier
    parameters_hash: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
    requested_at: datetime
    expires_at: datetime
    status: Literal["PENDING", "APPROVED", "REJECTED", "EXPIRED", "INVALIDATED"]

class ApprovalDecision(StrictModel):
    approval_id: UUID
    decision: Literal["APPROVE", "REJECT"]
    approver_id: SafeIdentifier
    decided_at: datetime
    nonce: Annotated[str, StringConstraints(min_length=16, max_length=256)]
    reason: Annotated[str, StringConstraints(max_length=1000)]
```

The API must authenticate the approver independently. Never accept
`approver_id` as proof of identity. Persist a nonce hash, enforce
one-time use, verify expiry, and compare the proposal hash against the
exact pending request.

### 6.7 Tool result and verification

``` python
class ToolResult(StrictModel):
    action_attempt_id: UUID
    idempotency_key: SafeIdentifier
    status: Literal["SUCCEEDED", "FAILED", "OUTCOME_UNKNOWN"]
    result_code: SafeIdentifier
    summary: Annotated[str, StringConstraints(max_length=1500)]
    observed_at: datetime
    evidence_ids: list[UUID] = Field(default_factory=list, max_length=20)

class VerificationResult(StrictModel):
    verification_id: UUID
    incident_id: UUID
    action_attempt_id: UUID
    predicate: SafeIdentifier
    passed: bool
    observed_state: dict[str, str | int | float | bool | None] = Field(max_length=50)
    evidence_id: UUID
    verified_at: datetime
    verifier_version: SafeIdentifier
```

The verifier must query simulator state through a read-only interface.
`ToolResult.status == "SUCCEEDED"` does not imply
`VerificationResult.passed == True`.

### 6.8 Audit event

``` python
class AuditEvent(StrictModel):
    event_id: UUID
    occurred_at: datetime
    correlation_id: UUID
    incident_id: UUID | None = None
    workflow_id: UUID | None = None
    actor_type: Literal["SYSTEM", "WORKER", "POLICY", "APPROVER", "ADAPTER", "VERIFIER"]
    actor_id: SafeIdentifier
    event_type: SafeIdentifier
    entity_type: SafeIdentifier | None = None
    entity_id: UUID | None = None
    payload_redacted: dict[str, str | int | float | bool | None] = Field(
        default_factory=dict, max_length=50
    )
```

Audit payloads must be deliberately constructed and redacted. Do not
serialize arbitrary request objects or secrets into the audit table.

### 6.9 Canonical event envelope

``` python
class EventEnvelope(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    event_id: UUID
    event_type: SafeIdentifier
    occurred_at: datetime
    producer: SafeIdentifier
    correlation_id: UUID
    causation_id: UUID | None = None
    payload: dict[str, object]
```

In production code, prefer a discriminated union of known event payload
models instead of an unrestricted payload dictionary. Unknown event
types must be rejected or quarantined, never dynamically executed.

------------------------------------------------------------------------

## 7. Event contracts

Initial event types:

  -----------------------------------------------------------------------------------
  Event                    Producer          Consumer               Meaning
  ------------------------ ----------------- ---------------------- -----------------
  `IncidentCreated`        ITSM adapter      Ingestion/normalizer   New incident
                                                                    accepted

  `DiagnosticsCollected`   Diagnostic worker Workflow               Read-only
                                                                    observations
                                                                    available

  `RemediationProposed`    Triage/planner    Policy engine          Candidate action;
                                                                    not authorized

  `PolicyEvaluated`        Policy engine     Workflow               Allow, deny, or
                                                                    approval required

  `ApprovalRequested`      Workflow          Approval store/adapter Exact action
                                                                    awaits approval

  `ApprovalDecided`        Approval adapter  Workflow               Authenticated
                                                                    decision received

  `RemediationStarted`     Executor          Audit/metrics          Action intent and
                                                                    execution begun

  `RemediationExecuted`    Executor          Verifier               Tool returned a
                                                                    result

  `RemediationVerified`    Verifier          Workflow               Independent
                                                                    postcondition
                                                                    result

  `IncidentResolved`       Workflow          ITSM adapter           Resolution only
                                                                    after
                                                                    verification

  `IncidentEscalated`      Workflow          ITSM adapter           Workflow stopped
                                                                    safely

  `OutboundUpdateFailed`   ITSM adapter      Retry/reconciliation   External incident
                                                                    update failed
  -----------------------------------------------------------------------------------

Events are immutable facts. Do not use an event to silently mutate old
history. Corrections are new events. Include schema versions and define
compatibility rules.

------------------------------------------------------------------------

## 8. Policy model

### 8.1 Example initial rules

  ------------------------------------------------------------------------------------
  Action            Target               Default decision  Conditions
  ----------------- -------------------- ----------------- ---------------------------
  Read health       Registered simulated Allow             Read-only adapter, bounded
                    service                                output

  Read logs         Registered simulated Allow             Sanitization, size cap, no
                    service                                secrets

  Restart service   Local/test simulator Allow             Service is registered;
                                                           evidence indicates
                                                           unhealthy; retry budget
                                                           available

  Restart service   Staging simulator    Require approval  Valid authenticated
                                                           approver and current
                                                           preconditions

  Clear simulated   Local/test simulator Allow             Registered target and valid
  cache                                                    evidence

  Grant test access Known test           Require approval  Policy explicitly allows
                    principal/resource                     the exact
                                                           principal/resource/action

  Any action        Unknown target or    Deny              No implicit fallback
                    action                                 

  Any action        Production target    Deny in this      No real production
                                         portfolio         mutations
                                         baseline          

  Any action        Model-generated      Deny              Arbitrary code execution is
                    shell/code                             not a tool
  ------------------------------------------------------------------------------------

### 8.2 Policy invariants

1.  Only the policy engine can return an execution authorization.
2.  An action is never executed before its intent and policy decision
    are durable.
3.  The target, parameters, and policy version are hashed into the
    proposal identity.
4.  Approval binds to one exact proposal and expires.
5.  A policy or precondition change invalidates stale approval.
6.  Unknown action, target, or principal fails closed.
7.  Tool adapters validate inputs independently of the LLM.
8.  A successful action cannot resolve an incident without independent
    verification.
9.  An uncertain side effect triggers reconciliation before retry.
10. No LLM output is allowed to alter policy, approval identity, or
    audit history.

------------------------------------------------------------------------

## 9. Testing strategy

### 9.1 Test layers

**A. Unit tests** - Pydantic validation and forbidden extra fields. -
Canonical normalization. - Policy matrix and reason codes. - State
transition graph. - Proposal canonicalization/hash stability. - Approval
expiry, replay, and mismatch. - Idempotency-key construction. - Retry
classification. - Evidence redaction and size limits. - Verification
predicates.

**B. Adapter contract tests** - ITSM adapter: create/fetch/update
incident, pagination/errors, idempotent update. - Identity adapter:
unknown user, missing role, disabled user, conflicting data. -
Infrastructure adapter: health/log reads, action execution,
timeout/unknown result, independent state read. - Message adapter:
acknowledgement, redelivery, dead-letter path. - Repository: uniqueness,
transaction boundaries, concurrent deduplication.

**C. Integration tests** - API + PostgreSQL + NATS + worker + Mockoon. -
Outbox publication and consumer deduplication. - Durable workflow
resume. - Approval pause/resume. - ITSM update retry independent of
remediation. - Migrations from an empty database. - Compose health
checks and clean shutdown.

**D. Fault-injection tests** - Worker termination before action. -
Worker termination after action but before recording result. - Tool
applies action then times out. - Duplicate webhook delivered multiple
times. - NATS unavailable. - PostgreSQL unavailable. - ITSM update
unavailable after successful remediation. - Verification endpoint
unavailable. - Stale approval after policy changes. - Dead-letter and
replay behavior.

**E. LLM evaluation** - Ambiguous incident description. - Missing
service identifier. - Conflicting service names. - Malformed
JSON/structured output. - Prompt injection in ticket body. - Prompt
injection in logs. - False evidence claim. - Unsupported remediation
proposal. - Low confidence requiring escalation. - Different model
responses across repeated runs.

**F. Security tests** - Forged requester identity. - Forged approver
identity. - Approval replay. - Expired approval. - Approval for a
different action or target. - Privilege escalation. - Unknown
action/tool invocation. - Arbitrary shell/code proposal. - Sensitive
data in logs/audit. - Oversized payload and malformed event. - Untrusted
diagnostic text attempting to override system policy. - Unauthorized
cross-incident reference.

**G. End-to-end scenario tests** - Healthy service: no unnecessary
remediation. - Recoverable outage: repair and verify. - Unrecoverable
outage: escalate. - Access request denied by policy. - Approval-required
action. - Duplicate event. - Uncertain action outcome. - Process restart
and resume. - ITSM write-back outage. - False resolution claim rejected
by verifier.

### 9.2 Scenario inventory (initial 24)

1.  `ITSM-001`: known recoverable service outage -\> verified recovery.
2.  `ITSM-002`: already healthy service -\> no mutation.
3.  `ITSM-003`: unknown service -\> no mutation, escalation.
4.  `ITSM-004`: ambiguous ticket -\> clarification/escalation.
5.  `ITSM-005`: unauthorized access request -\> deny.
6.  `ITSM-006`: approval required -\> wait with no action.
7.  `ITSM-007`: valid approval -\> execute once after rechecking policy.
8.  `ITSM-008`: forged approval identity -\> reject.
9.  `ITSM-009`: expired approval -\> reject.
10. `ITSM-010`: approval proposal hash mismatch -\> reject.
11. `ITSM-011`: duplicate event -\> one logical incident.
12. `ITSM-012`: action succeeds but response times out -\> reconcile.
13. `ITSM-013`: worker crashes before action -\> resume safely.
14. `ITSM-014`: worker crashes after action -\> no duplicate side
    effect.
15. `ITSM-015`: remediation fails -\> bounded retry/escalation.
16. `ITSM-016`: remediation response says success but target remains
    unhealthy -\> do not resolve.
17. `ITSM-017`: ITSM write-back fails -\> retry write-back, do not
    repeat repair.
18. `ITSM-018`: PostgreSQL unavailable -\> fail closed.
19. `ITSM-019`: NATS unavailable -\> outbox retains event.
20. `ITSM-020`: malicious instructions in ticket -\> no policy bypass.
21. `ITSM-021`: malicious instructions in logs -\> no policy bypass.
22. `ITSM-022`: unknown action type -\> reject before tool invocation.
23. `ITSM-023`: excessive diagnostic output -\> bounded and sanitized.
24. `ITSM-024`: audit required event missing -\> scenario fails.

### 9.3 Metrics and release gates

Report: - Scenario pass rate. - Policy enforcement rate. - Unauthorized
side-effect count. - Unsupported resolution count. - Duplicate
side-effect count. - Recovery success rate under injected faults. -
Audit completeness. - Triage field-level accuracy. - Correct escalation
rate. - P50/P95 workflow latency for a defined local test load. - LLM
calls and token/latency data when available.

Required release gates: - All deterministic unit, policy, and contract
tests pass. - Zero unauthorized mutations in the security suite. - Zero
false resolutions in acceptance scenarios. - All critical
retry/idempotency/recovery scenarios pass. - All terminal runs have
complete required audit events. - LLM evaluation thresholds are
predeclared and met; report failures, don't hide them. - CI
deterministic tests pass without network access and without Ollama. -
Integration tests can run using local Compose dependencies. - Secret
scan and configuration validation pass.

Do not treat a high total test count as proof of reliability. Tests must
assert externally observable state and invariants.

------------------------------------------------------------------------

## 10. CI/CD and repository quality gates

Suggested CI stages:

1.  Validate project configuration and formatting.
2.  Lint and type-check.
3.  Unit tests.
4.  Policy and security invariant tests.
5.  Secret scanning and dependency audit.
6.  Build container images.
7.  Start PostgreSQL, NATS, and Mockoon in integration CI.
8.  Apply migrations.
9.  Run adapter contract and integration tests.
10. Run deterministic scenario suite.
11. Emit JUnit XML and scenario JSON report.
12. Tear down services and publish artifacts.
13. Optional separate LLM evaluation job; it must not gate deterministic
    correctness if external inference is unavailable, but
    model-evaluation failures must remain visible.

CI must use fixed seeds and bounded timeouts. Avoid sleeps; wait on
readiness probes. Do not launch a long-running server without a managed
lifecycle. Ensure cleanup runs even when tests fail.

### Example command contract

The coding agent should establish and document the actual commands, with
a stable interface such as:

``` bash
make format-check
make lint
make typecheck
make test-unit
make test-security
make test-integration
make test-scenarios
make test
make compose-up
make compose-down
make demo-reset
make demo-run
```

These are desired targets, not claims that they already exist. The
coding agent must implement them or document the existing equivalent
after inspecting the repository.

------------------------------------------------------------------------

## 11. Docker Compose and local deployment requirements

Initial services: - `api`: event ingestion and internal control
endpoints. - `worker`: LangGraph workflow consumer. - `postgres`:
durable state. - `nats`: JetStream enabled with persistent local
volume. - `mockoon`: deterministic mock API server or CLI process. -
`prometheus`: metrics collection. - `otel-collector`: traces/metrics
pipeline if used. - Optional local Ollama endpoint outside Compose or a
separately configured model service. - Optional LocalStack only after
license verification; otherwise Moto-based simulator tests.

Requirements: - Pin image versions; avoid `latest` in reproducible
demos. - Health checks must reflect actual readiness. - Use non-root
containers where feasible. - Keep database and broker ports bound to
localhost by default. - Store credentials in local environment/secrets,
not in Compose literals or Git. - Use named volumes for state that must
survive a worker restart. - Have explicit test-only reset commands and
guard them against non-test database URLs. - Keep resource use
manageable for 16 GB RAM; do not run a large local model during
deterministic integration tests. - Provide `.env.example` with
placeholders only. - Document which containers are required for the core
workflow and which are optional observability tools.

------------------------------------------------------------------------

## 12. Repository structure

Adapt to an existing repository instead of blindly creating this layout.
If starting from an empty repository, use a structure similar to:

``` text
.
├── pyproject.toml
├── Makefile
├── README.md
├── PRD.md
├── AGENTS.md
├── .env.example
├── compose.yaml
├── migrations/
├── src/itsm_agent/
│   ├── api/
│   │   ├── app.py
│   │   ├── routes/
│   │   └── security.py
│   ├── domain/
│   │   ├── models.py
│   │   ├── events.py
│   │   ├── policies.py
│   │   ├── transitions.py
│   │   └── errors.py
│   ├── application/
│   │   ├── workflow.py
│   │   ├── nodes.py
│   │   ├── commands.py
│   │   └── services.py
│   ├── ports/
│   │   ├── itsm.py
│   │   ├── identity.py
│   │   ├── infrastructure.py
│   │   ├── event_bus.py
│   │   ├── repositories.py
│   │   └── model.py
│   ├── adapters/
│   │   ├── itsm/
│   │   ├── identity/
│   │   ├── infrastructure/
│   │   ├── messaging/
│   │   ├── persistence/
│   │   └── llm/
│   ├── observability/
│   └── config.py
├── simulators/
│   ├── mockoon/
│   ├── infrastructure/
│   └── fixtures/
├── tests/
│   ├── unit/
│   ├── contract/
│   ├── integration/
│   ├── security/
│   ├── fault_injection/
│   └── scenarios/
├── evals/
│   ├── datasets/
│   ├── runner.py
│   └── reports/
└── docs/
    ├── architecture.md
    ├── data-model.md
    ├── runbooks.md
    ├── threat-model.md
    ├── test-plan.md
    ├── adr/
    └── loom-script.md
```

Use ports/adapters (hexagonal architecture): domain/application modules
must not import Mockoon, Jira, ServiceNow, Moto, LocalStack, or
provider-specific SDKs.

------------------------------------------------------------------------

## 13. Coding-agent instructions (AGENTS.md)

### Role

You are the implementation agent for a portfolio-grade headless ITSM
self-healing platform. Your job is to inspect the existing repository,
implement the smallest coherent slice, prove behavior with tests, and
report evidence. Do not assume the repository is empty.

### Mandatory operating rules

1.  **Inspect before editing.** Read README, project instructions,
    package/dependency manifests, source tree, tests, CI workflows,
    migrations, and Git status. Identify existing conventions and reuse
    suitable code.
2.  **Do not overwrite or discard user changes.** If the working tree
    has changes, inspect and preserve them.
3.  **Do not implement the entire PRD in one giant change.** Work in
    small vertical slices with acceptance criteria and tests.
4.  **Test-first for bugs.** Reproduce the bug with a failing regression
    test before fixing it.
5.  **No unsupported claims.** Never say a test passed, deployment
    succeeded, issue was filed, or PR was merged unless the command/tool
    output proves it.
6.  **No real production access.** Use simulated identities, services,
    and AWS behavior only. Do not request real production credentials.
7.  **No arbitrary execution.** Never execute LLM-generated shell
    commands, code, SQL, or unrestricted tool arguments.
8.  **Policy is deterministic.** LLMs propose and explain; policy code
    authorizes; adapters execute; independent verification determines
    success.
9.  **Fail closed.** Unknown action, resource, principal, malformed
    proposal, unavailable policy state, or missing durable audit
    capacity must not permit a side effect.
10. **Durable before side effect.** Persist action intent and
    idempotency key before executing.
11. **Reconcile uncertainty.** If a side-effecting call times out,
    inspect actual target state before retrying.
12. **No false resolution.** Only the independent verifier can establish
    the required postcondition.
13. **Bound every loop.** Configure maximum model attempts, tool calls,
    retries, output sizes, and workflow deadline.
14. **Use structured contracts.** Validate every external event, LLM
    response, approval decision, and tool input at its boundary.
15. **Keep secrets out of logs and Git.** Run secret scans and inspect
    diff before reporting completion.
16. **Keep CI deterministic.** Core tests must not require a remote
    model or external SaaS.
17. **No unnecessary dependencies.** Add a dependency only when its role
    is justified and documented.
18. **No premature abstractions.** Add interfaces where they enforce a
    real boundary or support a planned adapter; avoid generic frameworks
    for hypothetical future integrations.
19. **Document trade-offs.** Use ADRs for consequential choices,
    especially event delivery, checkpoint persistence, simulator
    licensing, and approval semantics.
20. **Report blockers honestly.** If an integration/license/plan is
    unavailable, record the limitation and use the agreed local
    simulator alternative.

### Required workflow for every task

1.  Read current repository instructions and Git status.
2.  State the exact task scope and acceptance criteria.
3.  Identify relevant modules and tests.
4.  Write or update tests first where appropriate.
5.  Implement the smallest complete vertical slice.
6.  Run targeted tests.
7.  Run relevant security/invariant tests.
8.  Run formatting, lint, typing, and the full relevant suite.
9.  Inspect `git diff --check`, changed files, and secret-scan output.
10. Update docs/contracts if behavior changed.
11. Report exact commands, exit codes, test counts, changed paths,
    limitations, and remaining work.

### Required final report format

``` text
Task:
Scope completed:
Files changed:
Behavioral changes:
Tests run:
  - command:
  - exit code:
  - tests passed/failed/skipped:
Security invariants checked:
Manual verification:
Known limitations:
Remaining risks:
Git status:
Recommended next slice:
```

Do not report "production ready" as an absolute property. Report the
exact acceptance suite and fault conditions that passed, plus the
conditions not tested.

------------------------------------------------------------------------

## 14. Implementation roadmap

### Phase 0 --- Repository and architecture audit

-   Inspect current code, Git status, instructions, dependencies, CI,
    and deployment setup.
-   Identify reuse opportunities and conflicts.
-   Create an ADR for the final architecture and simulator choices.
-   Establish baseline test and lint results.
-   Deliver: audit report, proposed file-level plan, no broad refactor.

**Gate:** architecture plan matches the actual repository and no user
changes are lost.

### Phase 1 --- Domain contracts and deterministic policy

-   Implement enums, Pydantic contracts, canonical IDs, hashing, and
    state transitions.
-   Implement policy matrix and reason codes.
-   Add unit tests for every allow/deny/approval branch.
-   Deliver: pure domain layer with no LLM, DB, network, or vendor
    dependency.

**Gate:** policy invariants pass and unknown values fail closed.

### Phase 2 --- Simulator and adapter contracts

-   Implement Mockoon fixtures for ITSM, identity, and service
    health/actions.
-   Implement typed ports and deterministic infrastructure state.
-   Add action fault injection and independent read-only verifier.
-   Use Moto for any AWS API tests that are genuinely needed.
-   Deliver: simulator can seed, inspect, mutate, and reset test state.

**Gate:** successful repair and false-success rejection are
reproducible.

### Phase 3 --- Persistence and event delivery

-   Add PostgreSQL schema/migrations and repositories.
-   Implement inbox/outbox, deduplication, NATS JetStream
    publishing/consuming, bounded redelivery, and dead-letter handling.
-   Add integration tests for duplicates, outage, and restart.
-   Deliver: durable accepted events and idempotent consumers.

**Gate:** duplicate delivery and publisher/consumer failures do not lose
or duplicate logical work.

### Phase 4 --- LangGraph workflow

-   Implement explicit graph nodes, conditional routing, checkpointing,
    retries, interrupt/resume, and workflow deadlines.
-   Keep policy and execution independent from the LLM.
-   Add recovery tests at critical transition boundaries.
-   Deliver: full simulated incident workflow.

**Gate:** graph cannot bypass policy or resolve without verification.

### Phase 5 --- Approval and audit

-   Implement persisted approval requests bound to action hashes,
    expiry, identity, nonce, and one-time decision.
-   Implement append-only audit event writing and redaction.
-   Test replay, mismatch, expired approval, policy changes, and audit
    completeness.
-   Deliver: enforced approval and traceable decision history.

**Gate:** no action executes while pending or after invalid approval.

### Phase 6 --- ITSM connector and observability

-   Implement Jira Service Management adapter only if credentials/free
    plan are available; otherwise Mockoon remains the acceptance
    connector.
-   Add outbound retry/reconciliation and incident audit reference.
-   Add OpenTelemetry traces and Prometheus metrics.
-   Deliver: incident-to-resolution trace with persisted evidence.

**Gate:** external update failure does not cause the remediation to
repeat.

### Phase 7 --- Evaluation and CI release gates

-   Implement 24-scenario runner, fixed seeds, fault injection,
    JSON/JUnit reports, and security gates.
-   Ensure deterministic tests run offline without Ollama.
-   Add separate optional model-evaluation job.
-   Deliver: reproducible report and CI artifacts.

**Gate:** required safety, recovery, and audit gates pass.

### Phase 8 --- Loom and portfolio packaging

-   Write setup instructions and one-command demo workflow.
-   Capture architecture, success, recovery failure, adversarial test,
    and CI evidence.
-   Publish a concise report with measured results and limitations.
-   Deliver: reproducible demo and 5--7 minute Loom script.

**Gate:** another engineer can reproduce the key scenarios from the
README.

------------------------------------------------------------------------

## 15. Loom demo plan (5--7 minutes)

**0:00--0:30 --- Problem** - Explain repetitive incident diagnosis and
the risk of an agent that can claim success without proof.

**0:30--1:15 --- Architecture** - Show event ingestion, NATS,
PostgreSQL, LangGraph, policy engine, simulator, verifier, and audit
trail. - State explicitly that the external environment is simulated.

**1:15--2:45 --- Successful recovery** - Submit a seeded outage
incident. - Show health/log evidence, candidate action, policy decision,
action result, independent verification, and ITSM update.

**2:45--3:45 --- Failure/recovery** - Run an action that fails or times
out. - Show bounded retry/reconciliation and escalation; no false
resolution.

**3:45--4:45 --- Security boundary** - Inject malicious text into a
ticket/log or submit an unauthorized access request. - Show the
deterministic policy decision and confirm no unauthorized side effect.

**4:45--6:00 --- Evidence** - Show CI release gates, scenario report,
trace, and audit records. - Explain measured results and limitations.

**6:00--7:00 --- Engineering choices** - Explain why reasoning is
probabilistic but policy, execution contracts, and verification are
deterministic. - Explain what would need to change before real
enterprise deployment.

Do not stage fake test output. Capture output from actual reproducible
commands. Avoid showing secrets, personal data, or real customer
information.

------------------------------------------------------------------------

## 16. Final engineering checklist

### Scope and architecture

-   [ ] No Streamlit or dashboard dependency.
-   [ ] One complete incident-to-verified-resolution workflow.
-   [ ] Domain logic independent of vendors.
-   [ ] Event schema versions and compatibility rules documented.
-   [ ] ADRs record major decisions and trade-offs.

### Security and policy

-   [ ] Deny-by-default policy.
-   [ ] Unknown actions/resources rejected.
-   [ ] LLM cannot authorize or call arbitrary tools.
-   [ ] Approval is authenticated, exact-action-bound, expiring, and
    single-use.
-   [ ] Policy is reevaluated immediately before execution.
-   [ ] Production target mutations are disabled in portfolio baseline.
-   [ ] Secrets are not committed or logged.

### Reliability

-   [ ] Durable inbox/outbox.
-   [ ] Consumer deduplication.
-   [ ] Persistent workflow checkpointing.
-   [ ] Bounded retries and deadlines.
-   [ ] Uncertain action outcome reconciliation.
-   [ ] Dead-letter/escalation path.
-   [ ] Outbound ITSM update retry is independent from remediation.
-   [ ] Database/broker outage behavior tested.

### Verification and audit

-   [ ] Independent post-action state read.
-   [ ] False success rejected.
-   [ ] Every action has a durable intent and idempotency key.
-   [ ] Required audit events present for terminal outcomes.
-   [ ] Sensitive fields redacted.
-   [ ] Audit integrity claims are accurate.

### Testing and CI

-   [ ] Unit, contract, integration, security, fault-injection, and
    scenario suites.
-   [ ] 24 initial scenarios represented as versioned fixtures.
-   [ ] Deterministic tests run without LLM/network.
-   [ ] Fixed seeds and bounded timeouts.
-   [ ] Reports include failed scenarios, not only pass counts.
-   [ ] Secret scan, lint, typing, and migrations verified.
-   [ ] Release gates block on safety invariant failures.

### Demo and documentation

-   [ ] Fresh clone setup works.
-   [ ] One-command local startup and test instructions.
-   [ ] Reset command is test-database guarded.
-   [ ] Architecture diagram and data model documented.
-   [ ] Sample report generated from a real test run.
-   [ ] Loom shows success, failure, and security boundary.
-   [ ] Simulated vs real integrations are clearly disclosed.
-   [ ] Limitations and untested conditions are explicit.

------------------------------------------------------------------------

## 17. Immediate instructions to the coding agent

Start with **Phase 0 only**. Inspect the repository and report: 1.
Current repository layout and Git status. 2. Existing instructions and
architectural boundaries. 3. Existing tests and exact baseline results.
4. Existing reusable modules and adapters. 5. Gaps against Phases 1--3.
6. Licensing/configuration blockers for any optional simulator or SaaS.
7. A minimal implementation sequence with files and acceptance criteria.

Do not start a broad rewrite. Do not install every dependency at once.
Do not claim any phase is complete without passing evidence. After the
audit, implement Phase 1 as the first vertical slice: domain contracts,
explicit policy matrix, state transitions, and tests.

**Project success criterion:** the Loom demonstrates a repeatable
incident workflow whose outcome is established by actual simulated
system state and recorded evidence---not by the LLM's narrative.
