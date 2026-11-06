"""Identity resolution helpers (Task 11). Pure domain, no I/O.

Resolves source identities (AWS principal, DB user, GitHub actor, approval
approver) to canonical internal identities, with explicit ambiguity and
unresolved outcomes. Never silently merges identities on name/email alone.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from itsm_agent.domain.models import IdentityMapping


def _valid(m: IdentityMapping, at: datetime) -> bool:
    return m.valid_from <= at and (m.valid_to is None or m.valid_to >= at)


def resolve_identity(
    mappings: list[IdentityMapping],
    *,
    at: datetime,
) -> tuple[UUID | None, Literal["RESOLVED", "AMBIGUOUS", "UNRESOLVED"]]:
    """Resolve a single source identity to an internal identity at a point in time.

    - No valid mapping -> UNRESOLVED.
    - Exactly one distinct internal identity -> RESOLVED.
    - Multiple distinct internal identities -> AMBIGUOUS.
    """
    valid = [m for m in mappings if _valid(m, at)]
    if not valid:
        return None, "UNRESOLVED"
    distinct = {m.internal_identity_id for m in valid}
    if len(distinct) == 1:
        return next(iter(distinct)), "RESOLVED"
    return None, "AMBIGUOUS"


def resolve_cross_source(
    mappings_by_source: dict[str, list[IdentityMapping]],
    *,
    at: datetime,
) -> tuple[UUID | None, Literal["RESOLVED", "AMBIGUOUS", "UNRESOLVED"], list[str]]:
    """Resolve an actor observed across multiple source systems.

    Each source independently resolves (via :func:`resolve_identity`). Sources
    that resolve must agree on a single internal identity; a disagreement is
    AMBIGUOUS and the conflicting sources are reported. Sources that do not
    resolve are reported as unresolved but do not by themselves make the
    result ambiguous if at least one source resolves and all resolved sources
    agree.

    Returns (internal_id, status, provenance_notes).
    """
    notes: list[str] = []
    resolved_ids: set[UUID] = set()
    any_resolved = False
    for source, mappings in mappings_by_source.items():
        iid, status = resolve_identity(mappings, at=at)
        if status == "RESOLVED" and iid is not None:
            resolved_ids.add(iid)
            any_resolved = True
            notes.append(f"{source}: resolved {iid}")
        elif status == "AMBIGUOUS":
            notes.append(f"{source}: ambiguous")
            return None, "AMBIGUOUS", notes
        else:
            notes.append(f"{source}: unresolved")
    if not any_resolved:
        return None, "UNRESOLVED", notes
    if len(resolved_ids) == 1:
        return next(iter(resolved_ids)), "RESOLVED", notes
    return None, "AMBIGUOUS", notes


def resolve_assumed_role(
    role_mappings: list[IdentityMapping],
    base_identity_mappings: list[IdentityMapping],
    *,
    at: datetime,
) -> tuple[UUID | None, Literal["RESOLVED", "AMBIGUOUS", "UNRESOLVED"]]:
    """Resolve an STS assumed-role session to its base identity.

    ``role_mappings`` describe the role session identity; ``base_identity_mappings``
    describe the underlying human/service identity that assumed the role. If the
    role resolves and a base identity is available, prefer the base identity
    (session attribution). Otherwise fall back to the role identity.
    """
    role_id, role_status = resolve_identity(role_mappings, at=at)
    base_id, base_status = resolve_identity(base_identity_mappings, at=at)
    if base_status == "RESOLVED" and base_id is not None:
        return base_id, "RESOLVED"
    if role_status == "RESOLVED" and role_id is not None:
        return role_id, "RESOLVED"
    if role_status == "AMBIGUOUS" or base_status == "AMBIGUOUS":
        return None, "AMBIGUOUS"
    return None, "UNRESOLVED"


def resolve_resource_alias(
    aliases: dict[str, str],
    resource_id: str | None,
) -> str | None:
    """Resolve a source-specific resource identifier to its canonical id.

    Unknown resources are returned as-is only if present; None stays None.
    Never invents a canonical id for an unknown resource.
    """
    if resource_id is None:
        return None
    return aliases.get(resource_id, resource_id)


__all__ = [
    "resolve_assumed_role",
    "resolve_cross_source",
    "resolve_identity",
    "resolve_resource_alias",
]
