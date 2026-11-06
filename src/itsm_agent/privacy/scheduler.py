"""Resumable retention/erasure scheduler (security hardening slice).

The scheduler turns retention policy into an operational loop without turning
it into a data-loss engine:

- claims are durable and leased (``FOR UPDATE SKIP LOCKED`` + ``lease_until``),
  so a crashed process is recoverable and two schedulers do not process the
  same request;
- every attempt is counted, failures back off, and retry exhaustion marks the
  request ``FAILED`` (an escalation, never a silent success);
- erasure work and its audit record commit in the same tenant transaction;
- tombstones and derived-projection deletes are idempotent, so an interrupted
  run can be replayed without duplicating or losing records;
- ``source_events`` remains append-only: only a tombstone preserving the
  integrity hash is written;
- an active legal hold marks the request ``BLOCKED`` and performs no deletion.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from psycopg import AsyncConnection

from itsm_agent.adapters.persistence.audit_port import PsycopgAuditPort
from itsm_agent.adapters.persistence.repositories import RepositoryBundle
from itsm_agent.domain.events import AuditEvent
from itsm_agent.privacy.retention import (
    DataClass,
    ErasurePlan,
    ErasureRequest,
    LegalHold,
    RetentionPolicy,
    plan_erasure,
)

logger = logging.getLogger(__name__)

__all__ = ["RetentionRunResult", "RetentionScheduler"]


@dataclass
class RetentionRunResult:
    claimed: int = 0
    completed: int = 0
    blocked: int = 0
    failed: int = 0
    deferred: int = 0
    tombstones_written: int = 0
    derived_rows_deleted: int = 0
    tenants: list[UUID] = field(default_factory=list)


class RetentionScheduler:
    """One-shot and long-running retention execution."""

    def __init__(
        self,
        *,
        repos: RepositoryBundle,
        clock: Callable[[], datetime] | None = None,
        batch_size: int = 10,
        lease_seconds: float = 60.0,
        max_attempts: int = 5,
        backoff_seconds: float = 30.0,
        interval_seconds: float = 60.0,
    ) -> None:
        if batch_size < 1:
            raise ValueError("batch_size must be positive")
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        if backoff_seconds < 0:
            raise ValueError("backoff_seconds must be non-negative")
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        self._repos = repos
        self._clock = clock or (lambda: datetime.now(UTC))
        self._batch_size = batch_size
        self._lease_seconds = lease_seconds
        self._max_attempts = max_attempts
        self._backoff_seconds = backoff_seconds
        self._interval_seconds = interval_seconds
        self._stop = asyncio.Event()

    def request_stop(self) -> None:
        self._stop.set()

    async def run_once(self) -> RetentionRunResult:
        """Process all currently due requests for every registered tenant."""
        result = RetentionRunResult()
        tenant_ids = await self._repos.tenants.list_tenant_ids()
        result.tenants.extend(tenant_ids)
        for tenant_id in tenant_ids:
            await self._run_tenant(tenant_id, result)
        return result

    async def run_forever(self) -> None:
        """Run until ``request_stop``; a failed pass is logged and retried."""
        while not self._stop.is_set():
            try:
                await self.run_once()
            except Exception:  # noqa: BLE001 - one tenant must not stop the loop
                logger.exception("retention pass failed; will retry")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._interval_seconds)
            except TimeoutError:
                continue

    async def _run_tenant(self, tenant_id: UUID, result: RetentionRunResult) -> None:
        tenant_repos = self._repos.for_tenant(tenant_id)
        requests = await tenant_repos.retention.claim_due_requests(
            tenant_id, limit=self._batch_size, lease_seconds=self._lease_seconds
        )
        result.claimed += len(requests)
        policies = await tenant_repos.retention.effective_policies(tenant_id)
        holds = tuple(await tenant_repos.retention.active_holds(tenant_id))
        for request in requests:
            try:
                outcome, tombstoned, deleted = await self._execute_request(
                    tenant_repos, request, policies=policies, holds=holds
                )
                result.tombstones_written += tombstoned
                result.derived_rows_deleted += deleted
            except Exception as exc:  # noqa: BLE001 - release the lease, then escalate
                status = await tenant_repos.retention.retry_or_fail_request(
                    tenant_id,
                    request.id,
                    error=f"{type(exc).__name__}: {exc}",
                    max_attempts=self._max_attempts,
                    backoff_seconds=self._backoff_seconds,
                )
                if status == "FAILED":
                    result.failed += 1
                    await self._audit(
                        tenant_repos,
                        tenant_id,
                        request,
                        "RETENTION_ERASURE_FAILED",
                        {"error": f"{type(exc).__name__}: {exc}"[:500]},
                    )
                else:
                    result.deferred += 1
                    await self._audit(
                        tenant_repos,
                        tenant_id,
                        request,
                        "RETENTION_ERASURE_RETRY_SCHEDULED",
                        {"error": f"{type(exc).__name__}: {exc}"[:500]},
                    )
                continue

            if outcome == "BLOCKED":
                result.blocked += 1
            elif outcome == "COMPLETED":
                result.completed += 1
            else:
                result.deferred += 1

    async def _execute_request(
        self,
        tenant_repos: RepositoryBundle,
        request: ErasureRequest,
        *,
        policies: tuple[RetentionPolicy, ...],
        holds: tuple[LegalHold, ...],
    ) -> tuple[str, int, int]:
        now = self._clock()
        plan = plan_erasure(
            request,
            policies=policies,
            legal_holds=holds,
            now=now,
        )
        if plan.blocked:
            async with tenant_repos.transaction(request.tenant_id) as conn:
                await tenant_repos.retention.complete_request(
                    request.tenant_id, request.id, status="BLOCKED", conn=conn
                )
                await self._audit(
                    tenant_repos,
                    request.tenant_id,
                    request,
                    "RETENTION_ERASURE_BLOCKED",
                    {"reason": plan.blocked_reason or "legal hold"},
                    conn=conn,
                )
            return "BLOCKED", 0, 0

        async with tenant_repos.transaction(request.tenant_id) as conn:
            tombstoned, deleted = await self._execute_plan(tenant_repos, request, plan, conn=conn)
            await tenant_repos.retention.complete_request(
                request.tenant_id, request.id, status="COMPLETED", conn=conn
            )
            await self._audit(
                tenant_repos,
                request.tenant_id,
                request,
                "RETENTION_ERASURE_COMPLETED",
                {
                    "tombstones": tombstoned,
                    "derived_deleted": deleted,
                    "plan_version": "retention-v1",
                },
                conn=conn,
            )
        return "COMPLETED", tombstoned, deleted

    async def _execute_plan(
        self,
        tenant_repos: RepositoryBundle,
        request: ErasureRequest,
        plan: ErasurePlan,
        *,
        conn: AsyncConnection,
    ) -> tuple[int, int]:
        tombstoned = 0
        deleted = 0
        for data_class in request.data_classes:
            if not plan.may_execute(data_class):
                continue
            cutoff = plan.cutoffs[data_class]
            if data_class is DataClass.RAW_EVIDENCE:
                tombstoned += await tenant_repos.retention.tombstone_raw_evidence(
                    request.tenant_id,
                    older_than=cutoff,
                    erase_request_id=request.id,
                    conn=conn,
                )
            elif data_class is DataClass.DERIVED_PROJECTION:
                deleted += await tenant_repos.retention.delete_derived_facts(
                    request.tenant_id,
                    older_than=cutoff,
                    conn=conn,
                )
            # CANONICAL_EVENT / FINDING / INVESTIGATION / REVIEW_DECISION /
            # OPERATIONAL_LOG are retained or anonymized by a later,
            # explicitly-versioned transformation. They are never deleted here.
        return tombstoned, deleted

    async def _audit(
        self,
        tenant_repos: RepositoryBundle,
        tenant_id: UUID,
        request: ErasureRequest,
        event_type: str,
        payload: dict[str, str | int | float | bool | None],
        *,
        conn: AsyncConnection | None = None,
    ) -> None:
        port = PsycopgAuditPort(tenant_repos.audit)
        event = AuditEvent(
            event_id=uuid4(),
            tenant_id=tenant_id,
            occurred_at=self._clock(),
            correlation_id=request.id,
            incident_id=None,
            workflow_id=None,
            actor_type="SYSTEM",
            actor_id="retention-scheduler",
            event_type=event_type,
            entity_type="erasure_request",
            entity_id=request.id,
            payload_redacted={**payload, "request_status": request.status},
        )
        if conn is None:
            await port.append(event)
        else:
            # PsycopgAuditPort intentionally has no conn parameter; use the
            # repository directly for the atomic path.
            from itsm_agent.domain.models import AuditEventRecord

            await tenant_repos.audit.append(
                AuditEventRecord(
                    id=event.event_id,
                    tenant_id=event.tenant_id,
                    occurred_at=event.occurred_at,
                    correlation_id=event.correlation_id,
                    incident_id=event.incident_id,
                    workflow_id=event.workflow_id,
                    actor_type=event.actor_type,
                    actor_id=event.actor_id,
                    event_type=event.event_type,
                    entity_type=event.entity_type,
                    entity_id=event.entity_id,
                    payload_redacted=event.payload_redacted,
                ),
                conn=conn,
            )
