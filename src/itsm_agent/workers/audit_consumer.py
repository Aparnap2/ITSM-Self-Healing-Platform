"""Packaged audit-consumer entrypoint: ``python -m itsm_agent.workers.audit_consumer``.

This is the process that turns source events into findings. It consumes
``itsm.events.>`` from NATS JetStream and runs the deterministic detection
engine. When the optional agentic investigation stage is enabled, the
*advisory* investigation stage runs after the detection transaction has
committed; a failure there is logged and swallowed, because detection stays
the source of truth.

Safety properties of this process:

* **Startup fails closed.** The runtime database role is checked with
  ``verify_runtime_database`` before any message is consumed; a role that can
  bypass row-level security aborts the start.
* **The investigation stage fails closed too.** If the stage is enabled but no
  model key is configured, the process exits with a configuration error
  instead of silently running a stage that cannot do its job.
* **The model proposes, it never authorizes.** The investigation service
  records a proposal verbatim; ``findings.status`` is never touched.
* **No secrets are logged.** The model key is only ever read from the
  environment and passed to the adapter.

Exit codes: ``0`` clean shutdown, ``1`` unexpected crash, ``2`` configuration
or startup-safety error (missing DSN/NATS, missing model key for an enabled
stage, unsafe runtime database role).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from psycopg import AsyncConnection
from psycopg_pool import AsyncConnectionPool

from itsm_agent.adapters.messaging.nats_bus import (
    JetStreamConsumer,
    JetStreamPublisher,
    MessagingConfig,
)
from itsm_agent.adapters.persistence.pool import PersistenceConfig, create_pool
from itsm_agent.adapters.persistence.privileges import (
    DatabaseSafetyError,
    verify_runtime_database,
)
from itsm_agent.adapters.persistence.repositories import RepositoryBundle
from itsm_agent.application.audit_consumer import (
    build_evidence_source,
    consume_source_event,
)
from itsm_agent.config import ConfigError
from itsm_agent.investigations.groq_model import GroqInvestigationModel
from itsm_agent.investigations.service import InvestigationService

logger = logging.getLogger("itsm.audit_consumer")

#: Sources whose approval coverage the platform considers complete. A source
#: outside this set produces a COVERAGE_GAP finding instead of a verdict.
DEFAULT_COVERED_SOURCES: tuple[str, ...] = ("cloudtrail", "github", "postgresql", "pgaudit")


def _bool_env(name: str, default: bool, *, source: Mapping[str, str]) -> bool:
    raw = source.get(name)
    if raw is None or raw == "":
        return default
    lowered = raw.strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"Environment variable {name} must be a boolean")


def _int_env(
    name: str, default: int, *, source: Mapping[str, str], minimum: int, maximum: int
) -> int:
    raw = source.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"Environment variable {name} must be an integer") from exc
    if value < minimum or value > maximum:
        raise ConfigError(f"Environment variable {name} must be between {minimum} and {maximum}")
    return value


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


@dataclass(frozen=True)
class AuditConsumerConfig:
    """Validated consumer settings; every value must be present or defaulted."""

    dsn: str
    nats_url: str
    investigation_enabled: bool = False
    investigation_max_model_calls: int = 2
    investigation_max_tool_calls: int = 5
    investigation_llm_budget_calls: int = 3
    groq_base_url: str = "https://api.groq.com/openai/v1"
    groq_model: str = "openai/gpt-oss-120b"
    groq_api_key: str | None = None
    groq_max_tokens: int = 2000
    groq_timeout_seconds: float = 30.0
    covered_sources: frozenset[str] = frozenset(DEFAULT_COVERED_SOURCES)
    fetch_timeout_seconds: float = 1.0
    poll_interval_seconds: float = 0.05
    shutdown_timeout_seconds: float = 30.0

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> AuditConsumerConfig:
        source = os.environ if env is None else env
        dsn = source.get("ITSM_POSTGRES_DSN") or source.get("DATABASE_URL")
        if not dsn:
            raise ConfigError(
                "Missing required environment variable: ITSM_POSTGRES_DSN or DATABASE_URL"
            )
        nats_url = source.get("ITSM_NATS_URL") or source.get("NATS_URL")
        if not nats_url:
            raise ConfigError("Missing required environment variable: ITSM_NATS_URL or NATS_URL")

        enabled = _bool_env("ITSM_INVESTIGATION_ENABLED", False, source=source)
        groq_api_key = source.get("ITSM_GROQ_API_KEY") or None
        if enabled and not groq_api_key:
            # Fail closed: an enabled investigation stage without a model is a
            # misconfiguration, not a degraded mode.
            raise ConfigError(
                "ITSM_INVESTIGATION_ENABLED is set but ITSM_GROQ_API_KEY is missing; "
                "the investigation stage cannot run without a model"
            )

        covered_raw = source.get("ITSM_AUDIT_COVERED_SOURCES")
        covered = (
            frozenset(part.strip() for part in covered_raw.split(",") if part.strip())
            if covered_raw
            else frozenset(DEFAULT_COVERED_SOURCES)
        )
        return cls(
            dsn=dsn,
            nats_url=nats_url,
            investigation_enabled=enabled,
            investigation_max_model_calls=_int_env(
                "ITSM_INVESTIGATION_MAX_MODEL_CALLS", 2, source=source, minimum=1, maximum=5
            ),
            investigation_max_tool_calls=_int_env(
                "ITSM_INVESTIGATION_MAX_TOOL_CALLS", 5, source=source, minimum=1, maximum=20
            ),
            investigation_llm_budget_calls=_int_env(
                "ITSM_INVESTIGATION_LLM_BUDGET_CALLS", 3, source=source, minimum=1, maximum=10
            ),
            groq_base_url=source.get("ITSM_GROQ_BASE_URL") or "https://api.groq.com/openai/v1",
            groq_model=source.get("ITSM_GROQ_MODEL") or "openai/gpt-oss-120b",
            groq_api_key=groq_api_key,
            groq_max_tokens=_int_env(
                "ITSM_GROQ_MAX_TOKENS", 2000, source=source, minimum=256, maximum=8192
            ),
            groq_timeout_seconds=_float_env("ITSM_GROQ_TIMEOUT_SECONDS", 30.0, source=source),
            covered_sources=covered,
            fetch_timeout_seconds=_float_env(
                "ITSM_AUDIT_FETCH_TIMEOUT_SECONDS", 1.0, source=source
            ),
            poll_interval_seconds=_float_env("ITSM_AUDIT_POLL_SECONDS", 0.05, source=source),
            shutdown_timeout_seconds=_float_env("ITSM_AUDIT_SHUTDOWN_SECONDS", 30.0, source=source),
        )


def build_investigation_service(
    *,
    repositories: RepositoryBundle,
    config: AuditConsumerConfig,
) -> tuple[InvestigationService | None, GroqInvestigationModel | None]:
    """Build the advisory investigation service, or ``None`` when disabled.

    Returns ``(service, model)``. Both are ``None`` when the stage is
    disabled -- that is the deterministic, completely offline default. Raises
    ``ConfigError`` when the stage is enabled but no model key is available:
    the caller must not silently run an investigation stage that cannot do
    its job.
    """
    if not config.investigation_enabled:
        return None, None
    if not config.groq_api_key:
        raise ConfigError(
            "ITSM_INVESTIGATION_ENABLED is set but ITSM_GROQ_API_KEY is missing; "
            "the investigation stage cannot run without a model"
        )
    model = GroqInvestigationModel(
        base_url=config.groq_base_url,
        api_key=config.groq_api_key,
        model=config.groq_model,
        max_tokens=config.groq_max_tokens,
        timeout_seconds=config.groq_timeout_seconds,
        max_retries=2,
    )
    # The evidence resolver is request-scoped: it resolves the canonical
    # source event that produced the finding, so the model reasons about real
    # evidence instead of a bare question.
    return (
        InvestigationService(
            repositories.investigation,
            model=model,
            evidence_source=build_evidence_source(repositories.pool),
        ),
        model,
    )


async def serve(config: AuditConsumerConfig) -> None:
    """Consume source events until SIGTERM/SIGINT, then drain and close."""
    pool = create_pool(PersistenceConfig(dsn=config.dsn))
    await pool.open()
    await pool.wait()
    consumer: JetStreamConsumer | None = None
    publisher: JetStreamPublisher | None = None
    model: GroqInvestigationModel | None = None
    try:
        await verify_runtime_database(pool)

        repositories = RepositoryBundle(pool)
        investigation_service, model = build_investigation_service(
            repositories=repositories, config=config
        )

        messaging = MessagingConfig(servers=(config.nats_url,), connect_timeout_seconds=5.0)
        publisher = JetStreamPublisher(messaging)
        await publisher.ensure_stream()
        await publisher.close()
        publisher = None
        consumer = JetStreamConsumer(messaging)
        await consumer.ensure_consumer()

        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, stop.set)

        logger.info(
            "audit consumer started (investigation=%s llm_budget=%d covered_sources=%d)",
            config.investigation_enabled,
            config.investigation_llm_budget_calls,
            len(config.covered_sources),
        )
        try:
            while not stop.is_set():
                outcome = await consume_source_event(
                    consumer=consumer,
                    pool=pool,
                    findings_repo=repositories.findings,
                    processing_repo=repositories.processing_records,
                    covered_sources=set(config.covered_sources),
                    clock_now=lambda: datetime.now(tz=UTC),
                    investigation_enabled=config.investigation_enabled,
                    investigation_service=investigation_service,
                    timeout_seconds=config.fetch_timeout_seconds,
                )
                if outcome != "none":
                    logger.info("message outcome=%s", outcome)
                if stop.is_set():
                    break
                await asyncio.sleep(config.poll_interval_seconds)
        finally:
            stop.set()
        logger.info("audit consumer stopped")
    finally:
        await _shutdown(
            consumer=consumer,
            publisher=publisher,
            model=model,
            pool=pool,
            timeout_seconds=config.shutdown_timeout_seconds,
        )


async def _shutdown(
    *,
    consumer: JetStreamConsumer | None,
    publisher: JetStreamPublisher | None,
    model: GroqInvestigationModel | None,
    pool: AsyncConnectionPool[AsyncConnection],
    timeout_seconds: float,
) -> None:
    """Close every resource within a bounded timeout."""
    try:
        await asyncio.wait_for(
            _close_all(consumer=consumer, publisher=publisher, model=model, pool=pool),
            timeout=timeout_seconds,
        )
    except TimeoutError:
        logger.warning("shutdown timeout exceeded after %.0fs; forcing close", timeout_seconds)


async def _close_all(
    *,
    consumer: JetStreamConsumer | None,
    publisher: JetStreamPublisher | None,
    model: GroqInvestigationModel | None,
    pool: AsyncConnectionPool[AsyncConnection],
) -> None:
    if consumer is not None:
        await consumer.close()
    if publisher is not None:
        await publisher.close()
    if model is not None:
        await model.aclose()
    await pool.close()


def main() -> int:
    logging.basicConfig(level=os.environ.get("ITSM_LOG_LEVEL", "INFO"))
    try:
        config = AuditConsumerConfig.from_env()
    except ConfigError as exc:
        logger.error("startup config error: %s", exc)
        return 2
    try:
        asyncio.run(serve(config))
    except DatabaseSafetyError as exc:
        # Fail closed: never serve traffic on a role that can bypass RLS.
        logger.error("startup config error: %s", exc)
        return 2
    except KeyboardInterrupt:
        return 0
    except Exception:  # noqa: BLE001 - process boundary: log and exit non-zero
        logger.exception("audit consumer crashed")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
