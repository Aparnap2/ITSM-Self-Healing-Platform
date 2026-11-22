# Change Control v1.0

**Status:** H0 inventory.
**Starting SHA:** `3e3a2a014bd4aabee2d03a35e3e03f101ff382f5`

---

## 1. Purpose

This document defines how changes to the frozen Production-Parity v1.0 baseline are authorized, tracked, and classified. No change to the frozen architecture, acceptance criteria, or scope may be made without following this process.

## 2. Classification of findings

Every finding discovered during implementation or audit must be classified as one of:

| Classification | Definition | Action |
|---------------|-----------|--------|
| `BLOCKER` | Violates an existing approved requirement | Automatically actionable; must be fixed before the relevant gate can pass |
| `DEFECT` | Implementation does not meet an approved acceptance criterion | Automatically actionable within the frozen baseline |
| `DOCUMENTATION_DEFECT` | Documentation contradicts verified behavior | Actionable; does not require architecture change |
| `DEFERRED` | Useful improvement outside the frozen baseline | Not automatically actionable; requires approval to include |
| `RISK` | Known limitation with explicit owner and disposition | Recorded; not automatically actionable |

Only `BLOCKER` and `DEFECT` findings within the frozen baseline are automatically actionable. `DEFERRED` and `RISK` findings require explicit approval to become work items.

## 3. What requires approval

The following changes require explicit approval before implementation:

1. **New features** — any new product capability not in the frozen baseline.
2. **Architectural changes** — any change to the modular monolith, database, messaging, or observability topology.
3. **New dependencies** — any new Python package, Docker image, or external service.
4. **New infrastructure** — any new service, container, or cloud resource.
5. **New tables or endpoints** — any new database table or API endpoint.
6. **Changes to acceptance criteria** — any modification to `ACCEPTANCE_MATRIX_V1.yaml`.
7. **Changes to frozen NATS semantics** — delivery, ACK, retry, DLQ settings.
8. **Changes to frozen observability contract** — metrics, logs, traces, dashboards, alerts.
9. **Changes to qualification gates** — adding, removing, or modifying gates.

## 4. Change request process

1. Identify the finding or proposed change.
2. Classify it (BLOCKER, DEFECT, DOCUMENTATION_DEFECT, DEFERRED, RISK).
3. If BLOCKER or DEFECT within baseline: create a work item referencing the acceptance criterion ID.
4. If DEFERRED, RISK, or outside baseline: document in this file with owner and disposition; do not implement without approval.
5. If the change requires architecture/acceptance criteria modification: submit a change request for review and approval.
6. Record the decision (approved/rejected/deferred) with rationale.

## 5. Approved exceptions

None currently. All exceptions must be recorded here with:
- Date
- Requester
- Description
- Rationale
- Approver
- Expiry (if temporary)

## 6. Scope creep prevention

The agent must NOT:
- Add new dependencies without approval.
- Create new services without approval.
- Add new database tables without approval.
- Add new API endpoints without approval.
- Modify acceptance criteria without approval.
- Invent new requirements while implementing existing ones.
- Turn DEFERRED findings into implementation tasks without approval.

The agent MUST:
- Reference an acceptance criterion ID for every task.
- Classify every finding before acting on it.
- Stop and ask for approval when encountering a potential scope expansion.
- Record all decisions in this document.

## 7. Versioning

This document is versioned with the baseline. Changes to the baseline (including this document) require a new version number and explicit approval.

- **v1.0** — Initial frozen baseline (2026-11-22).
- Future versions: increment minor for clarifications, major for scope changes.

## 8. Relationship to other spec documents

| Document | Authority |
|----------|-----------|
| `PRODUCTION_PARITY_V1.md` | Frozen architecture and requirements |
| `ACCEPTANCE_MATRIX_V1.yaml` | Machine-readable acceptance criteria |
| `CHANGE_CONTROL.md` | This document — scope and change authorization |
| `REPOSITORY_BASELINE_V1.md` | Verified system inventory |
| `TRACEABILITY_MATRIX_V1.md` | Requirement-to-code-to-test-to-evidence mapping |
| `DOCUMENTATION_REGISTER_V1.md` | Documentation status and contradictions |
| `SCHEMA_CATALOG_V1.md` | Database schema and migration mapping |
| `API_AND_EVENT_CONTRACTS_V1.md` | HTTP, Pydantic and event contracts |
| `RUNTIME_AND_CONFIGURATION_V1.md` | Services, entrypoints, env vars, runtime config |
| `OBSERVABILITY_CONTRACT_V1.md` | Metrics, logs, traces, dashboards, alerts |