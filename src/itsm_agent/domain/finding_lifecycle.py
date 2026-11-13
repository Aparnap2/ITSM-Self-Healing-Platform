"""Finding lifecycle state machine (stdlib + pydantic only, no I/O).

Pure domain policy for the finding transition graph. Deterministic code owns
authorization; a proposed transition is never authorization by itself. The
independence rule is fail-closed:

* ``VERIFIED`` requires an independent verifier identity.
* If the finding's recorded history (``finding_transitions``) cannot establish
  who performed the close-out (``RESOLVED``), independence cannot be proven.
  In particular, a LEGACY finding with status ``RESOLVED`` and no transition
  rows MUST raise :class:`VerifierNotIndependentError` — we never soften this
  into a pass, and we never guess a resolver.

Statuses align with the reviewer decision vocabulary already enforced by
``itsm_agent.api.rbac`` (``CONFIRMED``, ``FALSE_POSITIVE``,
``ACCEPTED_RISK``, ``NEEDS_MORE_EVIDENCE``) plus the legacy detection
statuses and the two lifecycle-only statuses ``ACKNOWLEDGED`` and
``VERIFIED``.

Terminal statuses (no outgoing transition):
* ``VERIFIED`` / ``FALSE_POSITIVE`` / ``ACCEPTED_RISK`` / ``ESCALATED``.
* ``RESOLVED`` is closed but remains reachable by exactly one edge
  (``RESOLVED -> VERIFIED``), the independent postcondition close-out.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final
from uuid import UUID, uuid4

from pydantic import Field

from itsm_agent.domain.models import StrictModel


class FindingStatus(StrEnum):
    """Lifecycle statuses; matches migration 015's
    ``findings_status_lifecycle_check``."""

    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    CONFIRMED = "CONFIRMED"
    RESOLVED = "RESOLVED"
    VERIFIED = "VERIFIED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    ESCALATED = "ESCALATED"


ALLOWED_TRANSITIONS: Final[Mapping[str, frozenset[str]]] = {
    FindingStatus.OPEN: frozenset(
        {
            FindingStatus.ACKNOWLEDGED,
            FindingStatus.INVESTIGATING,
            FindingStatus.RESOLVED,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.ACCEPTED_RISK,
            FindingStatus.ESCALATED,
        }
    ),
    FindingStatus.ACKNOWLEDGED: frozenset(
        {
            FindingStatus.INVESTIGATING,
            FindingStatus.CONFIRMED,
            FindingStatus.RESOLVED,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.ACCEPTED_RISK,
            FindingStatus.ESCALATED,
        }
    ),
    FindingStatus.INVESTIGATING: frozenset(
        {
            FindingStatus.CONFIRMED,
            FindingStatus.RESOLVED,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.ACCEPTED_RISK,
            FindingStatus.ESCALATED,
        }
    ),
    FindingStatus.CONFIRMED: frozenset(
        {
            FindingStatus.RESOLVED,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.ACCEPTED_RISK,
            FindingStatus.ESCALATED,
        }
    ),
    # Closed-out findings are verifiable by an independent verifier only. A
    # resolution is never silently reclassified after the fact: re-opening a
    # closed finding is a governance decision, not a lifecycle edge.
    FindingStatus.RESOLVED: frozenset({FindingStatus.VERIFIED}),
    FindingStatus.FALSE_POSITIVE: frozenset(),
    FindingStatus.ACCEPTED_RISK: frozenset(),
    FindingStatus.ESCALATED: frozenset(),
    FindingStatus.VERIFIED: frozenset(),
}

#: Statuses from which no further transition is possible. ``RESOLVED`` is
#: excluded by design: the single RESOLVED -> VERIFIED edge remains.
TERMINAL_STATUSES: Final[frozenset[str]] = frozenset(
    {
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.ACCEPTED_RISK,
        FindingStatus.ESCALATED,
        FindingStatus.VERIFIED,
    }
)


class InvalidTransitionError(ValueError):
    """Raised when a transition is not in ``ALLOWED_TRANSITIONS``."""

    def __init__(self, message: str, code: str = "INVALID_TRANSITION") -> None:
        super().__init__(message)
        self.code = code


class VerifierNotIndependentError(ValueError):
    """Raised when verifier independence for VERIFIED cannot be established.

    Fail-closed reasons: unknown verifier, unknown resolver provenance
    (legacy finding with no transition history), or the verifier being the
    same actor that performed the close-out.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.code = "VERIFIER_NOT_INDEPENDENT"


def is_terminal(status: str | FindingStatus) -> bool:
    """True for statuses with no outgoing lifecycle transitions."""
    return str(status) in TERMINAL_STATUSES


def validate_transition(
    current: str | FindingStatus,
    target: str | FindingStatus,
    *,
    reason: str,
) -> None:
    """Raise :class:`InvalidTransitionError` unless the edge is allowed.

    Unknown statuses (not in the matrix) are invalid by the same rule, and a
    transition must carry a non-empty reason: a lifecycle change without a
    recorded justification is not an auditable decision.
    """
    current_key = str(current)
    target_key = str(target)
    if current_key not in ALLOWED_TRANSITIONS or target_key not in ALLOWED_TRANSITIONS:
        raise InvalidTransitionError(
            f"unknown finding status: {current_key!r} -> {target_key!r}",
            code="UNKNOWN_STATUS",
        )
    if not reason or not reason.strip():
        raise InvalidTransitionError(
            "a lifecycle transition requires a non-empty reason",
            code="MISSING_REASON",
        )
    if is_terminal(current_key):
        raise InvalidTransitionError(
            f"finding status {current_key} is terminal and cannot transition",
            code="TERMINAL_STATE",
        )
    if target_key not in ALLOWED_TRANSITIONS[current_key]:
        raise InvalidTransitionError(
            f"finding transition not allowed: {current_key} -> {target_key}",
            code="INVALID_TRANSITION",
        )


def assert_verifier_independent(verifier_id: str | None, resolver_id: str | None) -> None:
    """Fail closed unless ``verifier_id`` provably differs from ``resolver_id``.

    ``resolver_id is None`` means the finding's close-out actor could not be
    established (e.g. a legacy RESOLVED finding with no transition rows);
    independence is unprovable, so this raises.
    """
    if verifier_id is None or not verifier_id.strip():
        raise VerifierNotIndependentError("VERIFIED requires an explicit verifier identity")
    if resolver_id is None:
        raise VerifierNotIndependentError(
            "VERIFIED requires the RESOLVED actor's identity from the transition "
            "history; a finding with no recorded transition history fails closed"
        )
    if verifier_id.strip() == resolver_id:
        raise VerifierNotIndependentError(
            f"verifier {verifier_id!r} is not independent: the same actor closed out "
            "the finding (RESOLVED) and attempts to verify it"
        )


class FindingTransition(StrictModel):
    """Append-only lifecycle transition record.

    Immutability is enforced durably by the append-only trigger in migration
    015; this model mirrors the row shape with the StrictModel discipline
    (unknown fields rejected, whitespace stripped).
    """

    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    finding_id: UUID
    from_status: str
    to_status: str
    actor_id: str
    verifier_id: str | None = None
    reason: str
    transitioned_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
