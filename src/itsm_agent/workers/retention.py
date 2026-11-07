"""Packaged retention-scheduler entrypoint.

``python -m itsm_agent.workers.retention`` runs the resumable erasure
scheduler until SIGTERM/SIGINT. The scheduler already owns leasing, bounded
retries, legal-hold blocking, and per-tenant transactions; this module owns
only process lifecycle, the startup role assertion, and graceful shutdown.

Erasure is destructive, so startup fails closed: the process refuses to run
against a role that can bypass row-level security, and it exits non-zero if
PostgreSQL is unreachable.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
from collections.abc import Mapping
from dataclasses import dataclass

from psycopg import AsyncConnection
from psycopg_pool import AsyncConnectionPool

from itsm_agent.adapters.persistence.pool import PersistenceConfig, create_pool
from itsm_agent.adapters.persistence.privileges import verify_runtime_database
from itsm_agent.adapters.persistence.repositories import RepositoryBundle
from itsm_agent.config import ConfigError
from itsm_agent.privacy.scheduler import RetentionScheduler

logger = logging.getLogger("itsm.retention")


def _float_env(
    name: str,
    default: float,
    *,
    source: Mapping[str, str],
    allow_zero: bool = False,
) -> float:
    raw = source.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"Environment variable {name} must be a float") from exc
    if value < 0 or (value == 0 and not allow_zero):
        qualifier = "non-negative" if allow_zero else "positive"
        raise ConfigError(f"Environment variable {name} must be {qualifier}")
    return value


def _int_env(name: str, default: int, *, source: Mapping[str, str]) -> int:
    raw = source.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"Environment variable {name} must be an integer") from exc
    if value <= 0:
        raise ConfigError(f"Environment variable {name} must be positive")
    return value


@dataclass(frozen=True)
class RetentionConfig:
    """Validated scheduler settings; destructive bounds are never optional."""

    dsn: str
    interval_seconds: float = 60.0
    batch_size: int = 10
    lease_seconds: float = 60.0
    max_attempts: int = 5
    backoff_seconds: float = 30.0
    shutdown_timeout_seconds: float = 30.0

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> RetentionConfig:
        source = os.environ if env is None else env
        dsn = source.get("ITSM_POSTGRES_DSN") or source.get("DATABASE_URL")
        if not dsn:
            raise ConfigError(
                "Missing required environment variable: ITSM_POSTGRES_DSN or DATABASE_URL"
            )
        return cls(
            dsn=dsn,
            interval_seconds=_float_env("ITSM_RETENTION_INTERVAL_SECONDS", 60.0, source=source),
            batch_size=_int_env("ITSM_RETENTION_BATCH_SIZE", 10, source=source),
            lease_seconds=_float_env("ITSM_RETENTION_LEASE_SECONDS", 60.0, source=source),
            max_attempts=_int_env("ITSM_RETENTION_MAX_ATTEMPTS", 5, source=source),
            backoff_seconds=_float_env(
                "ITSM_RETENTION_BACKOFF_SECONDS",
                30.0,
                source=source,
                allow_zero=True,
            ),
            shutdown_timeout_seconds=_float_env(
                "ITSM_RETENTION_SHUTDOWN_SECONDS", 30.0, source=source
            ),
        )


def build_scheduler(
    *,
    pool: AsyncConnectionPool[AsyncConnection],
    config: RetentionConfig,
) -> RetentionScheduler:
    """Bind the scheduler to the shared repositories and tenant registry."""
    return RetentionScheduler(
        repos=RepositoryBundle(pool),
        batch_size=config.batch_size,
        lease_seconds=config.lease_seconds,
        max_attempts=config.max_attempts,
        backoff_seconds=config.backoff_seconds,
        interval_seconds=config.interval_seconds,
    )


async def serve(config: RetentionConfig) -> None:
    """Run passes until SIGTERM/SIGINT, then drain and close the pool."""
    pool = create_pool(PersistenceConfig(dsn=config.dsn))
    await pool.open()
    await pool.wait()
    await verify_runtime_database(pool)
    scheduler = build_scheduler(pool=pool, config=config)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)

    task = asyncio.create_task(scheduler.run_forever())
    stop_task = asyncio.create_task(stop.wait())
    logger.info(
        "retention scheduler started (batch=%d interval=%.0fs lease=%.0fs max_attempts=%d)",
        config.batch_size,
        config.interval_seconds,
        config.lease_seconds,
        config.max_attempts,
    )
    try:
        done, _ = await asyncio.wait({task, stop_task}, return_when=asyncio.FIRST_COMPLETED)
        if task in done:
            task.result()
    finally:
        # Let an in-flight pass finish before cancelling; the lease makes a
        # forced cancellation recoverable, not silent.
        scheduler.request_stop()
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(asyncio.shield(task), timeout=config.shutdown_timeout_seconds)
        stop_task.cancel()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        with contextlib.suppress(asyncio.CancelledError):
            await stop_task
        await pool.close()
        logger.info("retention scheduler stopped")


def main() -> int:
    logging.basicConfig(level=os.environ.get("ITSM_LOG_LEVEL", "INFO"))
    try:
        config = RetentionConfig.from_env()
    except ConfigError as exc:
        logger.error("startup config error: %s", exc)
        return 2
    try:
        asyncio.run(serve(config))
    except KeyboardInterrupt:
        return 0
    except Exception:  # noqa: BLE001 - process boundary: log and exit non-zero
        logger.exception("retention scheduler crashed")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
