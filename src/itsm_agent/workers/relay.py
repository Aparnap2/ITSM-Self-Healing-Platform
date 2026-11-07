"""Packaged outbox-relay entrypoint: ``python -m itsm_agent.workers.relay``.

The relay enumerates the tenant registry and runs one RLS-scoped pass per
tenant. It has no in-process stop flag, so this module owns cancellation on
SIGTERM/SIGINT. A relay that cannot reach PostgreSQL or NATS exits non-zero;
startup failures are never retried silently into a "green" process.
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

from itsm_agent.adapters.messaging.nats_bus import JetStreamPublisher, MessagingConfig
from itsm_agent.adapters.messaging.outbox_relay import OutboxRelay
from itsm_agent.adapters.persistence.pool import PersistenceConfig, create_pool
from itsm_agent.adapters.persistence.repositories import RepositoryBundle
from itsm_agent.config import ConfigError

logger = logging.getLogger("itsm.relay")


def _float_env(name: str, default: float, *, source: Mapping[str, str]) -> float:
    raw = source.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"Environment variable {name} must be a float") from exc
    if value <= 0:
        raise ConfigError(f"Environment variable {name} must be positive")
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
class RelayConfig:
    """Validated relay settings; every value must be present or defaulted."""

    dsn: str
    nats_url: str
    batch_size: int = 10
    poll_interval_seconds: float = 1.0
    lease_seconds: float = 60.0

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> RelayConfig:
        source = os.environ if env is None else env
        dsn = source.get("ITSM_POSTGRES_DSN") or source.get("DATABASE_URL")
        if not dsn:
            raise ConfigError(
                "Missing required environment variable: ITSM_POSTGRES_DSN or DATABASE_URL"
            )
        nats_url = source.get("ITSM_NATS_URL") or source.get("NATS_URL")
        if not nats_url:
            raise ConfigError("Missing required environment variable: ITSM_NATS_URL or NATS_URL")
        return cls(
            dsn=dsn,
            nats_url=nats_url,
            batch_size=_int_env("ITSM_RELAY_BATCH_SIZE", 10, source=source),
            poll_interval_seconds=_float_env("ITSM_RELAY_POLL_SECONDS", 1.0, source=source),
            lease_seconds=_float_env("ITSM_RELAY_LEASE_SECONDS", 60.0, source=source),
        )


def build_relay(
    *,
    pool: AsyncConnectionPool[AsyncConnection],
    publisher: JetStreamPublisher,
    config: RelayConfig,
) -> OutboxRelay:
    """Wire the relay to the shared repositories and tenant registry."""
    repositories = RepositoryBundle(pool)
    return OutboxRelay(
        repositories.outbox,
        publisher,
        batch_size=config.batch_size,
        lease_seconds=config.lease_seconds,
        tenants=repositories.tenants,
    )


async def serve(config: RelayConfig) -> None:
    """Run the relay until SIGTERM/SIGINT, then drain and close resources."""
    pool = create_pool(PersistenceConfig(dsn=config.dsn))
    await pool.open()
    await pool.wait()
    publisher = JetStreamPublisher(MessagingConfig(servers=(config.nats_url,)))
    relay = build_relay(pool=pool, publisher=publisher, config=config)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)

    task = asyncio.create_task(relay.run(poll_interval_seconds=config.poll_interval_seconds))
    stop_task = asyncio.create_task(stop.wait())
    logger.info(
        "outbox relay started (batch=%d poll=%.2fs lease=%.0fs)",
        config.batch_size,
        config.poll_interval_seconds,
        config.lease_seconds,
    )
    try:
        done, _ = await asyncio.wait({task, stop_task}, return_when=asyncio.FIRST_COMPLETED)
        if task in done:
            task.result()
    finally:
        stop_task.cancel()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        with contextlib.suppress(asyncio.CancelledError):
            await stop_task
        await publisher.close()
        await pool.close()
        logger.info("outbox relay stopped")


def main() -> int:
    logging.basicConfig(level=os.environ.get("ITSM_LOG_LEVEL", "INFO"))
    try:
        config = RelayConfig.from_env()
    except ConfigError as exc:
        logger.error("startup config error: %s", exc)
        return 2
    try:
        asyncio.run(serve(config))
    except KeyboardInterrupt:
        return 0
    except Exception:  # noqa: BLE001 - process boundary: log and exit non-zero
        logger.exception("outbox relay crashed")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
