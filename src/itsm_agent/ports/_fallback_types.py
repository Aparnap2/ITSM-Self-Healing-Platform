"""Shared fallback types used by port modules.

``SafeIdentifier``/``ShortText`` are imported from ``domain.events``.
``UTCDateTime`` is a local annotated type built on the domain's
``ensure_utc`` normalizer.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from pydantic import BeforeValidator

from itsm_agent.domain.events import SafeIdentifier, ShortText


def _ensure_aware_utc(value: datetime | str) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


UTCDateTime = Annotated[datetime, BeforeValidator(_ensure_aware_utc)]

__all__ = ["SafeIdentifier", "ShortText", "UTCDateTime"]
