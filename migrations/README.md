# Migrations

Forward-only, numbered plain SQL files (`001_*.sql`, ...). Each file is
idempotent (safe to re-apply) and runs in a single transaction.

## Apply via psycopg

From the repository root:

```bash
uv run python -m migrations.apply --dsn "postgresql://itsm:itsm@localhost:5432/itsm_test"
```

`apply.py`:

- connects with psycopg 3,
- ensures a `schema_migrations` bookkeeping table,
- applies each `NNN_*.sql` file exactly once (tracked by filename),
- commits per file, fails closed on the first error.

The integration test suite (`tests/integration/conftest.py`) applies the
same files automatically against `ITSM_TEST_PG_DSN` before running, so a
fresh empty database is migrated on demand.

Programmatic use (async):

```python
from itsm_agent.adapters.persistence.migrations import apply_migrations

applied = await apply_migrations(dsn)  # list of newly applied filenames
```
