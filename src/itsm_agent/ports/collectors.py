"""Collector ports (Task 8): read-only source adapters."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from itsm_agent.domain.events import SourceEvent


@runtime_checkable
class CollectorPort(Protocol):
    async def collect(self, since: datetime) -> list[SourceEvent]: ...
