"""Durable action-intent adapter for the workflow graph.

Satisfies ``IntentStorePort``. Intent recording is *idempotent*: replaying
a workflow after a crash re-derives the same idempotency key and observes
the existing row instead of overwriting it, so an in-flight or completed
mutation is never re-executed.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from itsm_agent.domain.models import ActionAttemptRecord, ActionStatus
from itsm_agent.ports.repositories import (
    ActionIntentRepository,
    DuplicateIdempotencyKeyError,
)


class WorkflowIntentStore:
    """``IntentStorePort`` backed by the durable ``action_intents`` table."""

    def __init__(self, intents: ActionIntentRepository) -> None:
        self._intents = intents

    async def record_intent(
        self,
        *,
        incident_id: UUID,
        workflow_id: UUID,
        action_type: str,
        resource_id: str,
        idempotency_key: str,
        proposal_hash: str,
        adapter_name: str,
        attempt_number: int,
        recorded_at: datetime,
    ) -> tuple[str, int]:
        intent = ActionAttemptRecord(
            id=uuid4(),
            incident_id=incident_id,
            workflow_id=workflow_id,
            action_type=action_type,
            resource_id=resource_id,
            idempotency_key=idempotency_key,
            proposal_hash=proposal_hash,
            status=ActionStatus.INTENT_RECORDED,
            attempt_number=attempt_number,
            intent_recorded_at=recorded_at,
            adapter_name=adapter_name,
        )
        try:
            await self._intents.record(intent)
        except DuplicateIdempotencyKeyError:
            existing = await self._intents.get_by_idempotency_key(idempotency_key)
            if existing is None:
                raise
            return str(existing.status), existing.attempt_number
        return str(ActionStatus.INTENT_RECORDED), attempt_number

    async def mark_outcome(
        self,
        *,
        idempotency_key: str,
        status: str,
        result_code: str | None = None,
        result_summary: str | None = None,
    ) -> None:
        await self._intents.mark_result(
            idempotency_key,
            status=status,
            result_code=result_code,
            result_summary=result_summary,
        )


__all__ = ["WorkflowIntentStore"]
