"""Shared pytest configuration and service fixtures for the ITSM agent suite.

The package is installed into the uv-managed virtual environment
(`uv sync`), so imports of ``itsm_agent`` resolve through the installed
package. No sys.path manipulation is required.

Test-phase markers (unit, contract, integration, security,
fault_injection, scenarios) are registered in ``pyproject.toml`` under
``[tool.pytest.ini_options]`` and enforced via ``--strict-markers``.

Determinism & isolation: the service fixtures below apply for the whole
``tests/`` tree. Every repository-backed test gets a truncated database
(all application tables, ``CASCADE``), so state never leaks between
tests regardless of the subdirectory the test lives in.

Strict mode: set ``ITSM_TEST_STRICT=1`` to make unreachable PostgreSQL
or NATS a hard failure (``pytest.fail``) instead of a skip. CI sets this
so failure-to-connect fails the CI job instead of silently skipping the
suite; locally it stays unset so suites skip cleanly (exit 0) without
containers.
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

#: When truthy, unreachable services fail the run instead of skipping it.
#: CI sets ``ITSM_TEST_STRICT=1`` so a missing local service is a red job.
STRICT = os.environ.get("ITSM_TEST_STRICT") == "1"

#: Full list of application tables from ``migrations/*.sql``. Truncating
#: all of them guarantees cross-test isolation; a new migration must add
#: its table here.
TABLES = (
    "incidents",
    "event_inbox",
    "outbox",
    "action_intents",
    "approvals",
    "audit_events",
    "workflow_state",
    "source_events",
    "source_checkpoints",
    "identity_mappings",
    "access_facts",
    "findings",
    "evidence_references",
    "coverage_status",
    "review_decisions",
)


def _unreachable(message: str, exc: Exception) -> None:
    """Fail (strict mode) or skip (default) on an unreachable service."""
    if STRICT:
        pytest.fail(f"{message} and ITSM_TEST_STRICT is set — hard fail: {exc}")
    pytest.skip(f"{message} — start docker compose: {exc}")


@pytest.fixture(scope="session")
async def pg_dsn() -> AsyncIterator[str]:
    """Probe PostgreSQL with a fast timeout; skip (or fail strictly when strict)."""
    try:
        conn = await AsyncConnection.connect(PG_DSN, connect_timeout=2)
    except Exception as exc:
        _unreachable(f"PostgreSQL unreachable at {PG_DSN}", exc)
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
    """Probe NATS with a fast timeout; skip (or fail strictly when strict)."""
    try:
        nc = await nats.connect(servers=[NATS_URL], connect_timeout=2)
    except Exception as exc:
        _unreachable(f"NATS unreachable at {NATS_URL}", exc)
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
        # Clean-slate isolation: every application table is truncated.
        yield RepositoryBundle(pool)
    finally:
        await pool.close()


@pytest.fixture
def messaging_config(nats_url: str) -> MessagingConfig:
    return MessagingConfig(servers=(nats_url,), connect_timeout_seconds=2.0)
