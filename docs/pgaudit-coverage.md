# PostgreSQL pgAudit Coverage (Task 9)

## Supported event classes

- SESSION: statement-level audit (SELECT/INSERT/UPDATE/DELETE/DDL).
- Authentication outcomes (login success/failure).
- Role and privilege changes (GRANT/REVOKE, ALTER ROLE).
- DDL operations (CREATE/ALTER/DROP).

## Redaction

- SQL string literals and numeric params (>=4 digits) are redacted before
  persistence. Raw SQL is never stored; only redacted excerpt in
  correlation_metadata.

## Limitations

- pgAudit must be enabled and configured per database.
- Coverage depends on `pgaudit.log` settings.
- Managed PostgreSQL (RDS) log delivery path differs (CloudWatch Logs).
- Multiline records handled best-effort; malformed lines skipped.
