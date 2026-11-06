"""Async connection pool factory for psycopg 3."""

from __future__ import annotations

from dataclasses import dataclass

from psycopg import AsyncConnection
from psycopg_pool import AsyncConnectionPool


@dataclass(frozen=True)
class PersistenceConfig:
    dsn: str
    min_size: int = 1
    max_size: int = 10
    connect_timeout_seconds: float = 3.0


def create_pool(config: PersistenceConfig) -> AsyncConnectionPool[AsyncConnection]:
    """Create (not yet opened) async pool. Caller must ``await pool.open()``."""
    return AsyncConnectionPool(
        conninfo=config.dsn,
        min_size=config.min_size,
        max_size=config.max_size,
        timeout=config.connect_timeout_seconds,
        open=False,
        check=None,
    )
