"""Selective agentic investigation (Task 13). Bounded, read-only, validated."""

from __future__ import annotations

from typing import Any, Protocol
from uuid import UUID

from itsm_agent.domain.events import InvestigationProposal, InvestigationRequest


class InvestigationModel(Protocol):
    async def investigate(
        self,
        request: InvestigationRequest,
        evidence: dict[UUID, str],
    ) -> InvestigationProposal: ...


class InvestigationBudgetExceeded(Exception):
    pass


async def run_investigation(
    request: InvestigationRequest,
    *,
    fetch_evidence: Any,
    model: InvestigationModel,
    model_calls_used: int = 0,
) -> InvestigationProposal:
    """Run a bounded investigation.

    - fetch_evidence: async callable (ids) -> dict[id, redacted_summary]
    - model calls bounded by request.max_model_calls.
    - Output evidence references validated against the snapshot.
    """
    if model_calls_used >= request.max_model_calls:
        raise InvestigationBudgetExceeded("model call budget exhausted")

    # Gather evidence (bounded by request.evidence_snapshot_ids)
    ids = request.evidence_snapshot_ids[: request.max_tool_calls]
    evidence = await fetch_evidence(ids)

    # Redact: only pass bounded summaries (already redacted by fetcher)
    bounded_evidence = {
        k: (v[:500] if isinstance(v, str) else str(v)[:500]) for k, v in evidence.items()
    }

    proposal = await model.investigate(request, bounded_evidence)

    # Validate evidence references against snapshot
    allowed = set(request.evidence_snapshot_ids)
    for ref in proposal.supporting_evidence + proposal.contradicting_evidence:
        if ref not in allowed:
            raise ValueError(f"invalid evidence reference: {ref}")

    if proposal.investigation_id != request.investigation_id:
        raise ValueError("investigation_id mismatch")

    return proposal


__all__ = ["InvestigationBudgetExceeded", "InvestigationModel", "run_investigation"]
