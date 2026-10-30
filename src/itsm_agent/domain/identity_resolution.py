"""Identity resolution helpers (Task 11). Pure domain, no I/O."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from itsm_agent.domain.models import IdentityMapping


def resolve_identity(
    mappings: list[IdentityMapping],
    *,
    at: datetime,
) -> tuple[UUID | None, Literal["RESOLVED", "AMBIGUOUS", "UNRESOLVED"]]:
    """Resolve a source identity to an internal identity at a point in time.

    - No valid mapping -> UNRESOLVED.
    - Exactly one valid mapping -> RESOLVED.
    - Multiple distinct internal identities -> AMBIGUOUS.
    """
    valid = [m for m in mappings if m.valid_from <= at and (m.valid_to is None or m.valid_to >= at)]
    if not valid:
        return None, "UNRESOLVED"
    distinct = {m.internal_identity_id for m in valid}
    if len(distinct) == 1:
        return next(iter(distinct)), "RESOLVED"
    return None, "AMBIGUOUS"


__all__ = ["resolve_identity"]
