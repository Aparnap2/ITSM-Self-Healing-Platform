# Source Integration Matrix

| Source | Auth | Pagination / Checkpoints | Rate Limits | Coverage Limitations |
|---|---|---|---|---|
| AWS CloudTrail | IAM role / access keys (simulated via Moto) | NextToken pagination; time-range checkpoints | AWS API throttling; exponential backoff | Management events default; data events optional; no real account |
| PostgreSQL (pgAudit) | DB role with audit read | WAL/LSN or timestamp checkpoints | Connection pool limits | pgAudit must be enabled; DDL/DML coverage depends on config |
| GitHub | PAT / GitHub App (simulated) | Cursor pagination; since checkpoints | 5000 req/hr (authenticated) | Audit log retention limits; org-level access required |
| Identity / Approvals | OAuth/OIDC or API key (simulated) | Cursor/time checkpoints | Provider-specific | Approval semantics vary; simulated in baseline |

## Known limitations

- All sources simulated in portfolio baseline; no real credentials.
- Rate limits are provider-dependent and may change.
- Coverage depends on source configuration (e.g., pgAudit settings).

## Event identity fallback rules

| Source | source_event_id availability | Fallback identity |
|---|---|---|
| AWS CloudTrail | `eventID` present | `(tenant, cloudtrail, eventID)` |
| AWS CloudTrail (missing eventID) | rare | `(tenant, cloudtrail, eventTime, eventName, requestID)` |
| PostgreSQL pgAudit | no native ID | `(tenant, pgaudit, session_id, statement_timestamp, statement_hash)` |
| GitHub | `id` / `_document_id` present | `(tenant, github, id)` |
| GitHub (missing id) | fallback | `(tenant, github, created_at, action, actor, org)` |
| Identity / approvals | provider ID present | `(tenant, identity, provider, provider_event_id)` |
| Identity / approvals (imported) | no ID | `(tenant, identity, import_batch, row_hash)` |

Fallbacks are stable across adapter versions. Payload hash alone is never the
universal identity.
