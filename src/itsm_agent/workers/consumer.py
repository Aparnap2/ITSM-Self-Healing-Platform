"""Long-running NATS JetStream consumer process.

Delegates all business processing to ``itsm_agent.application.worker``;
this module owns only the process lifecycle, connection management, and
graceful shutdown.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
from datetime import UTC, datetime
from typing import Any

from nats.aio.client import Client as NatsClient

from itsm_agent.adapters.messaging.nats_bus import (
    JetStreamConsumer,
    JetStreamPublisher,
    MessagingConfig,
)
from itsm_agent.adapters.persistence.audit_port import PsycopgAuditPort
from itsm_agent.adapters.persistence.pool import PersistenceConfig, create_pool
from itsm_agent.adapters.persistence.repositories import RepositoryBundle
from itsm_agent.application.commands import (
    ExecutionLimits,
    WorkflowDeps,
)
from itsm_agent.application.worker import consume_one
from itsm_agent.domain.policies import default_policy_snapshot
from itsm_agent.simulators.infrastructure.simulator import InfrastructureSimulator
from itsm_agent.simulators.infrastructure.verifier import IndependentVerifier

logger = logging.getLogger("itsm.worker")


def _env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None or value == "":
        raise RuntimeError(f"missing required env var: {name}")
    return value


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return int(raw)


class Worker:
    def __init__(
        self,
        *,
        pg_dsn: str,
        nats_url: str,
        concurrency: int = 4,
        shutdown_timeout: float = 30.0,
    ) -> None:
        self.pg_dsn = pg_dsn
        self.nats_url = nats_url
        self.concurrency = max(1, concurrency)
        self.shutdown_timeout = shutdown_timeout
        self._stop = asyncio.Event()
        self._inflight = 0
        self._inflight_lock = asyncio.Lock()
        self._nc: NatsClient | None = None
        self._consumer: JetStreamConsumer | None = None
        self._pool: Any = None
        self._repos: RepositoryBundle | None = None
        self._deps: WorkflowDeps | None = None

    async def start(self) -> None:
        # --- database -------------------------------------------------------
        self._pool = create_pool(PersistenceConfig(dsn=self.pg_dsn, min_size=1, max_size=10))
        await self._pool.open()
        self._repos = RepositoryBundle(self._pool)

        # --- simulator-backed adapters (deterministic, simulated env) --------
        sim = InfrastructureSimulator(seed=int(os.environ.get("ITSM_SIMULATOR_SEED", "42")))
        sim.seed_service(
            service_name="payments-api", environment="test", status="DOWN", restart_count=0
        )
        sim.seed_service(
            service_name="checkout-api", environment="test", status="DOWN", restart_count=0
        )
        sim.seed_service(
            service_name="search-api", environment="test", status="DOWN", restart_count=0
        )

        from itsm_agent.application.commands import ExecutorPort, VerifierPort

        class SimExecutor(ExecutorPort):
            def __init__(self, s: InfrastructureSimulator) -> None:
                self.s = s

            async def execute(self, proposal: Any, idempotency_key: str) -> Any:
                from itsm_agent.domain.events import ToolResult

                service = getattr(proposal, "service_name", "payments-api")
                env = getattr(proposal, "environment", "test")
                result = self.s.restart_service(
                    service_name=service, environment=env, idempotency_key=idempotency_key
                )
                return ToolResult(
                    action_attempt_id=__import__("uuid").uuid4(),
                    idempotency_key=idempotency_key,
                    status=result.status,
                    result_code=result.result_code,
                    summary="ok",
                    observed_at=datetime.now(UTC),
                    evidence_ids=[],
                )

        class SimVerifier(VerifierPort):
            def __init__(self, s: InfrastructureSimulator) -> None:
                self.s = s
                self.v = IndependentVerifier(s)

            async def verify(self, incident_id: Any, action_attempt_id: Any) -> Any:
                from itsm_agent.domain.events import VerificationResult

                obs = self.v.verify(
                    service_name="payments-api", environment="test", predicate="service_healthy"
                )
                return VerificationResult(
                    verification_id=__import__("uuid").uuid4(),
                    incident_id=incident_id,
                    action_attempt_id=action_attempt_id,
                    predicate="service_healthy",
                    passed=obs.passed,
                    observed_state=obs.observed_state,
                    evidence_id=__import__("uuid").uuid4(),
                    verified_at=datetime.now(UTC),
                    verifier_version=obs.verifier_version,
                )

        from itsm_agent.application.commands import DiagnosticsPort

        class FakeDiagnostics(DiagnosticsPort):
            async def collect(self, incident: Any, max_calls: int) -> list[Any]:
                from itsm_agent.domain.events import DiagnosticObservation

                return [
                    DiagnosticObservation(
                        evidence_id=__import__("uuid").uuid4(),
                        source="sim",
                        kind="HEALTH_CHECK",
                        observed_at=datetime.now(UTC),
                        content_hash="0" * 64,
                        sanitized_summary="unhealthy",
                        structured_facts={"healthy": False},
                        trust_level="SIMULATOR_OBSERVATION",
                    )
                ]

        from itsm_agent.ports.model import ModelPort, TriageOutput

        class FakeModel(ModelPort):
            async def triage(self, request: Any) -> TriageOutput:
                return TriageOutput(
                    category="SERVICE_UNHEALTHY",
                    suspected_failure_class="PROCESS_DOWN",
                    urgency="HIGH",
                    confidence=0.9,
                    rationale="simulated triage",
                )

        class FakeApprovals:
            async def create_request(
                self,
                incident_id: Any,
                workflow_id: Any,
                proposal_hash: str,
                action_type: str,
                resource_id: str,
                parameters_hash: str,
                requested_at: datetime,
                expires_at: datetime,
            ) -> Any:
                raise RuntimeError("approval not expected in test env")

            async def get_decision(self, approval_id: Any) -> None:
                return None

        class FakeClock:
            def now(self) -> datetime:
                return datetime.now(UTC)

        self._deps = WorkflowDeps(
            model=FakeModel(),
            diagnostics=FakeDiagnostics(),
            executor=SimExecutor(sim),
            verifier=SimVerifier(sim),
            approvals=FakeApprovals(),
            audit=PsycopgAuditPort(self._repos.audit),
            clock=FakeClock(),
            limits=ExecutionLimits(),
            policy_snapshot=default_policy_snapshot(),
        )

        # --- NATS -----------------------------------------------------------
        mc = MessagingConfig(servers=(self.nats_url,), connect_timeout_seconds=5.0)
        # ensure stream exists BEFORE creating the durable consumer
        pub = JetStreamPublisher(mc)
        await pub.ensure_stream()
        await pub.close()
        self._consumer = JetStreamConsumer(mc)
        await self._consumer.ensure_consumer()
        logger.info("worker started: concurrency=%d", self.concurrency)

    async def _handle(self, message: Any) -> None:
        assert self._consumer is not None
        assert self._repos is not None
        assert self._deps is not None
        async with self._inflight_lock:
            self._inflight += 1
        try:
            outcome = await consume_one(
                consumer=self._consumer,
                deps=self._deps,
                incidents=self._repos.incidents,
                workflow_states=self._repos.workflow_state,
                clock_now=lambda: datetime.now(UTC),
                max_deliver=3,
                timeout_seconds=2.0,
            )
            logger.info("message outcome=%s", outcome)
        except Exception as exc:  # noqa: BLE001
            logger.exception("unhandled error processing message: %s", exc)
        finally:
            async with self._inflight_lock:
                self._inflight -= 1

    async def run(self) -> None:
        await self.start()
        assert self._consumer is not None
        assert self._repos is not None
        assert self._deps is not None
        sem = asyncio.Semaphore(self.concurrency)
        tasks: set[asyncio.Task[None]] = set()

        async def worker_loop() -> None:
            while not self._stop.is_set():
                async with sem:
                    if self._stop.is_set():
                        break
                    task = asyncio.create_task(self._handle(None))
                    tasks.add(task)
                    task.add_done_callback(tasks.discard)
                await asyncio.sleep(0.05)

        # Simpler: poll fetch in a loop with bounded concurrency
        async def loop() -> None:
            while not self._stop.is_set():
                try:
                    from typing import cast

                    _consumer = cast(JetStreamConsumer, self._consumer)
                    _deps = cast(WorkflowDeps, self._deps)
                    _repos = cast(RepositoryBundle, self._repos)
                    outcome = await consume_one(
                        consumer=_consumer,
                        deps=_deps,
                        incidents=_repos.incidents,
                        workflow_states=_repos.workflow_state,
                        clock_now=lambda: datetime.now(UTC),
                        max_deliver=3,
                        timeout_seconds=1.0,
                    )
                    if outcome not in ("none",):
                        logger.info("message outcome=%s", outcome)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("consume error: %s", exc)
                    await asyncio.sleep(1.0)
                await asyncio.sleep(0.05)

        loop_task = asyncio.create_task(loop())
        await self._stop.wait()
        loop_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await loop_task
        # wait for in-flight
        if tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True), timeout=self.shutdown_timeout
                )
            except TimeoutError:
                logger.warning("shutdown timeout; %d tasks still in flight", len(tasks))

    async def stop(self) -> None:
        self._stop.set()
        if self._consumer is not None:
            await self._consumer.close()
        if self._pool is not None:
            await self._pool.close()
        logger.info("worker stopped")

    def request_stop(self) -> None:
        self._stop.set()


async def main() -> int:
    logging.basicConfig(level=os.environ.get("ITSM_LOG_LEVEL", "INFO"))
    try:
        pg_dsn = (
            os.environ.get("ITSM_POSTGRES_DSN")
            or os.environ.get("DATABASE_URL")
            or "postgresql://itsm:itsm@localhost:5432/itsm"
        )
        nats_url = (
            os.environ.get("ITSM_NATS_URL") or os.environ.get("NATS_URL") or "nats://localhost:4222"
        )
        if not pg_dsn or not nats_url:
            raise RuntimeError("missing database/nats url")
    except RuntimeError as exc:
        logger.error("startup config error: %s", exc)
        return 2
    concurrency = _int_env("ITSM_WORKER_CONCURRENCY", 4)
    shutdown_timeout = float(os.environ.get("ITSM_WORKER_SHUTDOWN_TIMEOUT", "30"))
    worker = Worker(
        pg_dsn=pg_dsn,
        nats_url=nats_url,
        concurrency=concurrency,
        shutdown_timeout=shutdown_timeout,
    )

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, worker.request_stop)

    try:
        await worker.run()
    except Exception as exc:  # noqa: BLE001
        logger.exception("worker crashed: %s", exc)
        await worker.stop()
        return 1
    await worker.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
