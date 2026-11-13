"""Selective investigation policy (pure domain, no I/O).

The PRD pipeline is::

    ... -> deterministic analysis (rules + policy)
        -> investigation requested (selective, bounded agentic reasoning)
        -> verification + audit + report

This module owns the *decision* to investigate and the *shape* of the request.
It is deliberately boring: no LLM, no network, no database and no clock of its
own (the caller injects ``now``).

Two rules matter for safety:

* **Selection is deterministic and conservative.** ``COVERAGE_GAP`` and
  ``INCONCLUSIVE`` findings are statements about *uncertainty*, not about a
  policy violation, so they are never escalated to the agentic stage. No model
  participates in this decision.
* **The request is bounded.** Tool calls, model calls, evidence snapshot size,
  question length and the deadline are fixed here, so an upstream caller cannot
  widen the blast radius of an investigation.

The request itself is the existing trust-boundary contract
``itsm_agent.domain.events.InvestigationRequest``; this module only fills it in
deterministically.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Final
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import ConfigDict, Field

from itsm_agent.domain.events import InvestigationRequest
from itsm_agent.domain.models import Finding, StrictModel

__all__ = [
    "DEADLINE_SECONDS",
    "INVESTIGATION_QUESTION",
    "INVESTIGATION_OUTCOMES",
    "INVESTIGATION_SEVERITIES",
    "MAX_EVIDENCE_SNAPSHOT_IDS",
    "MAX_MODEL_CALLS",
    "MAX_REQUESTED_BY_LENGTH",
    "MAX_TOOL_CALLS",
    "MIN_RISK_SCORE",
    "TERMINAL_STATUSES",
    "InvestigationProposalRecord",
    "InvestigationRequestRecord",
    "build_investigation_request",
    "current_request_status",
    "should_investigate",
]


#: Outcomes that justify an agentic pass. ``COVERAGE_GAP`` and ``INCONCLUSIVE``
#: describe *uncertainty* (missing or ambiguous evidence), never a suspected
#: violation, so they are never escalated.
INVESTIGATION_OUTCOMES: Final[frozenset[str]] = frozenset({"VIOLATION", "SUSPICIOUS"})

#: Severities worth an agentic pass. P3/P4 are triaged by a human directly.
INVESTIGATION_SEVERITIES: Final[frozenset[str]] = frozenset({"P1", "P2"})

#: Minimum risk score for the agentic stage.
MIN_RISK_SCORE: Final[int] = 60

#: Bounds for one investigation.
MAX_TOOL_CALLS: Final[int] = 5
MAX_MODEL_CALLS: Final[int] = 2
MAX_EVIDENCE_SNAPSHOT_IDS: Final[int] = 50
DEADLINE_SECONDS: Final[float] = 60.0

#: Maximum length of the requester identity.
MAX_REQUESTED_BY_LENGTH: Final[int] = 128

#: Fixed, model-independent question. It is a constant on purpose: the model
#: must not be able to influence what it is asked, and the audit trail must be
#: reproducible from the finding alone.
INVESTIGATION_QUESTION: Final[str] = (
    "Explain the identity, action, and authorization evidence for this finding "
    "and state what is missing."
)

#: Terminal states of the investigation request ledger.
TERMINAL_STATUSES: Final[frozenset[str]] = frozenset({"COMPLETED", "SKIPPED", "FAILED"})

#: Stable namespace for deterministic investigation identifiers.
_INVESTIGATION_NAMESPACE: Final[UUID] = uuid5(NAMESPACE_URL, "urn:itsm-agent:investigation")


def should_investigate(finding: Finding, *, enabled: bool) -> bool:
    """Decide whether a finding warrants a bounded agentic investigation.

    Purely deterministic: the switch is off by default and no model is
    consulted. A finding qualifies when it is *enabled*, its outcome expresses
    a suspected violation, its severity is P1/P2 and its risk score is at or
    above :data:`MIN_RISK_SCORE`.
    """
    if not enabled:
        return False
    if finding.outcome not in INVESTIGATION_OUTCOMES:
        return False
    if str(finding.severity) not in INVESTIGATION_SEVERITIES:
        return False
    return finding.risk_score >= MIN_RISK_SCORE


def build_investigation_request(
    finding: Finding,
    *,
    tenant_id: UUID,
    evidence_snapshot_ids: Sequence[UUID],
    requested_by: str,
    now: datetime,
) -> InvestigationRequest:
    """Build the bounded investigation request for one finding.

    The request is fully deterministic given ``(finding, tenant_id,
    evidence_snapshot_ids, requested_by, now)``: the question is a constant and
    the identifier is derived from those inputs, so the same inputs always
    produce the same request.

    Raises:
        ValueError: if the tenant does not own the finding, or the requester
            identity is empty/over-long. Failing closed here is preferred over
            investigating a finding under the wrong tenant.
    """
    if finding.tenant_id != tenant_id:
        raise ValueError(
            f"tenant mismatch for finding {finding.id}: "
            f"request={tenant_id} finding={finding.tenant_id}"
        )
    requester = requested_by.strip()
    if not requester:
        raise ValueError("requested_by must not be empty")
    if len(requester) > MAX_REQUESTED_BY_LENGTH:
        raise ValueError(f"requested_by exceeds {MAX_REQUESTED_BY_LENGTH} characters")

    snapshot_ids = list(evidence_snapshot_ids)[:MAX_EVIDENCE_SNAPSHOT_IDS]
    return InvestigationRequest(
        investigation_id=_investigation_id(tenant_id, finding.id, requester, now),
        tenant_id=tenant_id,
        finding_id=finding.id,
        evidence_snapshot_ids=snapshot_ids,
        question=INVESTIGATION_QUESTION,
        max_tool_calls=MAX_TOOL_CALLS,
        max_model_calls=MAX_MODEL_CALLS,
        deadline_seconds=DEADLINE_SECONDS,
    )


def current_request_status(records: Sequence[InvestigationRequestRecord]) -> str:
    """Latest durable status for a request ledger.

    The ledger is append-only, so a request that ran a model has a
    ``REQUESTED`` row followed by a terminal row. A terminal status always wins
    over ``REQUESTED`` regardless of row order.
    """
    for record in reversed(records):
        if record.status in TERMINAL_STATUSES:
            return record.status
    return "REQUESTED"


def _investigation_id(tenant_id: UUID, finding_id: UUID, requested_by: str, now: datetime) -> UUID:
    """Deterministic identifier for one investigation attempt."""
    key = f"{tenant_id}|{finding_id}|{requested_by}|{now.isoformat()}"
    return uuid5(_INVESTIGATION_NAMESPACE, key)


class InvestigationRequestRecord(StrictModel):
    """One immutable row of the append-only investigation request ledger."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, frozen=True)

    id: UUID
    tenant_id: UUID
    finding_id: UUID
    requested_by: str
    question: str
    evidence_snapshot_ids: list[UUID] = Field(default_factory=list, max_length=50)
    max_tool_calls: int
    max_model_calls: int
    status: str
    created_at: datetime


class InvestigationProposalRecord(StrictModel):
    """One immutable row of the append-only investigation proposal ledger.

    A proposal is a *model opinion*. It never carries authority: the recorded
    ``recommended_disposition`` is stored verbatim and is never applied to the
    finding lifecycle (that remains the reviewer transition path).
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, frozen=True)

    id: UUID
    tenant_id: UUID
    request_id: UUID
    finding_id: UUID
    hypothesis: str
    supporting_evidence: list[UUID] = Field(default_factory=list, max_length=50)
    contradicting_evidence: list[UUID] = Field(default_factory=list, max_length=50)
    missing_evidence: list[str] = Field(default_factory=list, max_length=20)
    uncertainty: str
    recommended_disposition: str
    model_calls_used: int
    created_at: datetime
