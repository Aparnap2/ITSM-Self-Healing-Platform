"""Transaction-local tenant context for PostgreSQL row-level security.

Every tenant-scoped read/write must run on a connection whose transaction has
``itsm.tenant_id`` set. RLS policies compare a row's ``tenant_id`` against
``current_setting('itsm.tenant_id', true)::uuid``.

Two properties are load-bearing:

- The setting is written with ``is_local=true`` (the third argument to
  ``set_config``), so it is **transaction-local**: it is discarded at COMMIT or
  ROLLBACK and a pooled connection can never retain one tenant's context for
  the next borrower.
- An unset or NULL context makes the RLS predicate evaluate to NULL, so the
  policy filters every row out. Missing context therefore **fails closed**:
  zero rows are visible and no row passes a ``WITH CHECK`` clause.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import UUID

from psycopg import AsyncConnection
from psycopg_pool import AsyncConnectionPool

__all__ = ["tenant_transaction"]


@asynccontextmanager
async def tenant_transaction(
    pool: AsyncConnectionPool[AsyncConnection], tenant_id: UUID
) -> AsyncIterator[AsyncConnection]:
    """Open a pooled transaction with the tenant RLS context set.

    The context is set with ``is_local=true`` (transaction-local), so a pooled
    connection cannot retain one tenant's context after the transaction ends.
    With no context set (or a NULL one) RLS returns zero rows — fail closed.

    Yields the connection inside the transaction; the transaction commits on a
    clean exit and rolls back if the body raises.
    """
    async with pool.connection() as conn, conn.transaction():
        await conn.execute(
            "SELECT set_config('itsm.tenant_id', %s, true)",
            (str(tenant_id),),
        )
        yield conn
