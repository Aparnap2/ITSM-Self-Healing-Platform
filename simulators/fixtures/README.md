# Deterministic fixtures

Static inputs for the deterministic test suites and the 24-scenario harness.
All identities, incidents, and approvals here are simulated — never real
production data or credentials.

| File | Purpose |
| --- | --- |
| `incident-clean-outage.json` | Baseline outage whose simulated recovery succeeds and is independently verified. |
| `incident-prompt-injection.json` | Outage whose description carries a prompt-injection payload; the workflow must treat it as untrusted data and the policy layer must still deny unauthorized actions. |
| `incident-duplicate-pair.json` | Two identical deliveries sharing one `external_event_id`; the consumer must deduplicate (at-least-once delivery). |
| `approval-fixture.json` | Simulated approval record (PRD §6.6): authenticated approver, single-use nonce, expiry, and a proposal hash binding. |

## Contract coupling

Field names follow the PRD (§6.1 incident fields, §6.6 approval fields). When
the typed Pydantic contracts change, these fixtures must be updated in the
same slice — the fixtures are inputs to contract tests, not a substitute for
them.

`proposal_hash` is a 64-hex placeholder. At runtime it must be replaced by the
real canonical hash of the action proposal being approved; the placeholder is
never valid in an executed approval flow.
