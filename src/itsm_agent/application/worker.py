"""Worker: consume an accepted event, run the remediation workflow, persist.

This is the composition of ingestion -> workflow -> durable state. It is
idempotent: re-processing an event whose incident already exists returns
the recorded terminal status without re-running side effects.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from itsm_agent.adapters.messaging.nats_bus import JetStreamConsumer
from itsm_agent.application.commands import WorkflowDeps
from itsm_agent.application.services import WorkflowState
from itsm_agent.application.workflow import build_workflow
from itsm_agent.domain.events import IncidentCreated
from itsm_agent.domain.models import Incident, IncidentStatus
from itsm_agent.ports.repositories import (
    IncidentRepository,
    WorkflowStateRepository,
)

WORKFLOW_VERSION = "1.0.0"


@dataclass
class ProcessResult:
    incident_id: UUID
    workflow_id: UUID
    status: str
    already_processed: bool


async def process_event(
    *,
    event: IncidentCreated,
    deps: WorkflowDeps,
    incidents: IncidentRepository,
    workflow_states: WorkflowStateRepository,
    clock_now: datetime,
) -> ProcessResult:
    """Process one accepted event end-to-end. Idempotent on external_event_id."""
    existing = await incidents.find_by_external_event(event.source_system, event.external_event_id)
    if existing is not None:
        # Already processed (or in flight): do not re-run side effects.
        status = existing.status
        return ProcessResult(
            incident_id=existing.id,
            workflow_id=existing.current_workflow_id or uuid4(),
            status=str(status),
            already_processed=True,
        )

    incident_id = uuid4()
    workflow_id = uuid4()
    now = clock_now
    incident = Incident(
        id=incident_id,
        source_system=event.source_system,
        source_incident_id=event.source_incident_id,
        external_event_id=event.external_event_id,
        title=event.title,
        description=event.description,
        service_name=event.service_name,
        severity=event.severity,
        status=IncidentStatus.NEW,
        created_at=now,
        updated_at=now,
        correlation_id=event.correlation_id,
        current_workflow_id=workflow_id,
    )
    await incidents.create(incident)

    await workflow_states.create(
        _workflow_run_stub(workflow_id, incident_id, event.correlation_id, now)
    )

    initial_state: WorkflowState = {
        "workflow_id": str(workflow_id),
        "incident_id": str(incident_id),
        "correlation_id": str(event.correlation_id),
        "workflow_version": WORKFLOW_VERSION,
        "incident": event.model_dump(mode="json"),
        "status": "NEW",
        "current_node": "",
        "triage": None,
        "evidence_ids": [],
        "evidence_indicates_unhealthy": False,
        "candidate": None,
        "policy_decision": None,
        "policy_revalidated": False,
        "approval": None,
        "approval_decision": None,
        "action_attempt_id": None,
        "idempotency_key": None,
        "tool_result": None,
        "action_attempts": 0,
        "verification": None,
        "model_attempts": 0,
        "tool_calls": 0,
        "deadline_at": None,
        "error_code": None,
        "error_detail": None,
        "itsm_updated": False,
        "audit_event_ids": [],
        "resolution_summary": None,
    }

    graph = build_workflow(deps)
    final = await graph.ainvoke(initial_state)

    final_status = str(final.get("status", "UNKNOWN"))
    current_node = str(final.get("current_node", ""))
    error_code = final.get("error_code")
    wf_status = "SUCCEEDED" if final_status == "RESOLVED" else final_status
    await workflow_states.update(
        workflow_id,
        status=wf_status,
        current_node=current_node,
        attempt_count=int(final.get("action_attempts", 0)),
        last_error_code=error_code,
        finished=True,
    )
    await incidents.update_status(
        incident_id,
        status=final_status,
        current_workflow_id=workflow_id,
    )
    return ProcessResult(
        incident_id=incident_id,
        workflow_id=workflow_id,
        status=final_status,
        already_processed=False,
    )


def _workflow_run_stub(
    workflow_id: UUID, incident_id: UUID, correlation_id: UUID, now: datetime
) -> Any:
    from itsm_agent.domain.models import WorkflowRun as WorkflowStateModel

    return WorkflowStateModel(
        id=workflow_id,
        incident_id=incident_id,
        workflow_version=WORKFLOW_VERSION,
        status="PENDING",
        current_node="start",
        attempt_count=0,
        started_at=now,
        updated_at=now,
        correlation_id=correlation_id,
    )


logger = logging.getLogger(__name__)


async def consume_one(
    *,
    consumer: JetStreamConsumer,
    deps: WorkflowDeps,
    incidents: IncidentRepository,
    workflow_states: WorkflowStateRepository,
    clock_now: Callable[[], datetime],
    max_deliver: int = 3,
    timeout_seconds: float = 1.0,
) -> str:
    """Fetch and process one JetStream message.

    Returns one of: "none", "processed", "duplicate", "retry", "poison",
    "dead_lettered". Acknowledges only after durable processing succeeds.
    """
    msgs = await consumer.fetch(timeout_seconds=timeout_seconds, batch=1)
    if not msgs:
        return "none"
    message = msgs[0]
    # --- validate envelope --------------------------------------------------
    try:
        raw = json.loads(message.payload.decode("utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("envelope must be a JSON object")
        envelope = raw.get("payload", raw)
        event = IncidentCreated.model_validate(envelope)
    except Exception as exc:  # noqa: BLE001 — poison message path
        logger.warning("poison message on %s: %s", message.subject, exc)
        await consumer.dead_letter(message, error=f"invalid envelope: {exc}")
        return "poison"

    # --- durable processing -------------------------------------------------
    try:
        result = await process_event(
            event=event,
            deps=deps,
            incidents=incidents,
            workflow_states=workflow_states,
            clock_now=clock_now(),
        )
    except Exception as exc:  # noqa: BLE001 — transient/unknown failure
        if message.delivery_attempt >= max_deliver:
            logger.error(
                "dead-lettering %s after %s attempts: %s",
                message.subject,
                message.delivery_attempt,
                exc,
            )
            await consumer.dead_letter(message, error=str(exc))
            return "dead_lettered"
        logger.warning("retrying %s: %s", message.subject, exc)
        await consumer.nak(message, delay_seconds=0.5)
        return "retry"

    await consumer.ack(message)
    return "duplicate" if result.already_processed else "processed"
