"""Shared integration-test fixtures.

Skips automatically (with a clear reason) when PostgreSQL or NATS are
unreachable, so `uv run pytest tests/integration -q` exits 0 without
containers. Deterministic: bounded poll loops, no fixed sleeps.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import nats
import pytest
from psycopg import AsyncConnection

from itsm_agent.adapters.messaging.nats_bus import MessagingConfig
from itsm_agent.adapters.persistence.migrations import apply_migrations
from itsm_agent.adapters.persistence.pool import PersistenceConfig, create_pool
from itsm_agent.adapters.persistence.repositories import RepositoryBundle

PG_DSN = os.environ.get("ITSM_TEST_PG_DSN", "postgresql://itsm:itsm@localhost:5432/itsm_test")
NATS_URL = os.environ.get("ITSM_TEST_NATS_URL", "nats://localhost:4222")

TABLES = (
    "workflow_state",
    "audit_events",
    "approvals",
    "action_intents",
    "outbox",
    "event_inbox",
    "incidents",
)


@pytest.fixture(scope="session")
async def pg_dsn() -> AsyncIterator[str]:
    """Probe PostgreSQL with a fast timeout; skip the suite if unreachable."""
    try:
        conn = await AsyncConnection.connect(PG_DSN, connect_timeout=2)
    except Exception as exc:
        pytest.skip(f"PostgreSQL unreachable at {PG_DSN} — start docker compose: {exc}")
        return
    try:
        await conn.close()
        applied = await apply_migrations(PG_DSN)
        if applied:
            print(f"\napplied migrations: {applied}")
        yield PG_DSN
    finally:
        pass


@pytest.fixture(scope="session")
async def nats_url() -> AsyncIterator[str]:
    """Probe NATS with a fast timeout; skip the suite if unreachable."""
    try:
        nc = await nats.connect(servers=[NATS_URL], connect_timeout=2)
    except Exception as exc:
        pytest.skip(f"NATS unreachable at {NATS_URL} — start docker compose: {exc}")
        return
    try:
        await nc.drain()
        yield NATS_URL
    finally:
        pass


@pytest.fixture
async def repos(pg_dsn: str) -> AsyncIterator[RepositoryBundle]:
    pool = create_pool(PersistenceConfig(dsn=pg_dsn))
    await pool.open()
    try:
        async with pool.connection() as conn:
            await conn.execute(f"TRUNCATE {', '.join(TABLES)} CASCADE")
        yield RepositoryBundle(pool)
    finally:
        await pool.close()


@pytest.fixture
def messaging_config(nats_url: str) -> MessagingConfig:
    return MessagingConfig(servers=(nats_url,), connect_timeout_seconds=2.0)
