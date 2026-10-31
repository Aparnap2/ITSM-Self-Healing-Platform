"""Adapter: ``AuditPort`` (application) backed by ``PsycopgAuditRepository``."""

from __future__ import annotations

from typing import Any

from itsm_agent.domain.events import AuditEvent as DomainAuditEvent
from itsm_agent.domain.models import AuditEventRecord


class PsycopgAuditPort:
    def __init__(self, repo: Any) -> None:
        self._repo = repo

    async def append(self, event: DomainAuditEvent) -> None:
        record = AuditEventRecord(
            id=event.event_id,
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
        )
        await self._repo.append(record)


__all__ = ["PsycopgAuditPort"]
