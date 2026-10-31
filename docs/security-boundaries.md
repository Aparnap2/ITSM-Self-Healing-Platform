# Security Boundaries (Task 15)

## Tenant isolation

- Every tenant-owned record carries `tenant_id`.
- Repositories are expected to be called with tenant scope; cross-tenant reads
  return no data when scoped by tenant_id.
- Tests: tests/security/test_tenant_isolation.py.

## Secrets and redaction

- Redaction at ingestion (redact_secrets); no secrets in logs/traces/audit.
- Secret scan required before merge.

## Prompt injection

- Source evidence is treated as untrusted data; never interpreted as
  instructions. Evidence passed to LLM as bounded summaries with IDs only.
- Model output validated with Pydantic; evidence references checked against
  snapshot.

## Arbitrary execution

- No shell, SQL, or code execution by models. Read-only tools only.

## Residual risks

- Redaction rules are source-specific and may miss novel patterns.
- Tenant isolation relies on caller scoping; full DB RLS not yet enabled.
