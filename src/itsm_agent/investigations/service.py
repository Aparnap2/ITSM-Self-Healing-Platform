"""Bounded, optional agentic investigation service (application layer).

The model PROPOSES; deterministic policy and the independent verifier remain
in charge. This service therefore:

* builds a **bounded** request from the deterministic selection policy;
* records what it did in an **append-only** ledger;
* never touches ``findings.status`` -- the finding lifecycle stays owned by
  the reviewer transition path, and a recorded ``recommended_disposition`` is
  stored verbatim and never applied.

With no model configured (the production default) the stage is deterministic
and completely offline: one ``SKIPPED`` ledger row, no network, no LLM.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID, uuid4

from itsm_agent.domain.events import InvestigationProposal, InvestigationRequest
from itsm_agent.domain.investigation_policy import (
    InvestigationProposalRecord,
    InvestigationRequestRecord,
    build_investigation_request,
)
from itsm_agent.domain.models import Finding
from itsm_agent.investigations.orchestrator import (
    InvestigationBudgetExceeded,
    InvestigationModel,
    run_investigation,
)
from itsm_agent.privacy.redaction import redact_secrets

logger = logging.getLogger(__name__)

__all__ = [
    "MAX_REASON_CHARS",
    "MAX_SUMMARY_CHARS",
    "EvidenceFetcher",
    "InvestigationLedger",
    "InvestigationService",
]

#: Hard cap on the evidence summary handed to the model.
MAX_SUMMARY_CHARS = 500

#: Hard cap on a recorded failure reason.
MAX_REASON_CHARS = 500


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


#: Async callable that resolves evidence ids to bounded, redacted summaries.
EvidenceFetcher = Callable[[Sequence[UUID]], Awaitable[dict[UUID, str]]]


class InvestigationLedger(Protocol):
    """Append-only ledger the service writes to.

    Satisfied by ``itsm_agent.adapters.persistence.repositories.
    PsycopgInvestigationRepository``; the signature here is deliberately the
    same minus the optional ``conn=`` escape hatch, so the service never needs
    a database handle.
    """

    async def record_request(
        self,
        request: InvestigationRequest,
        *,
        requested_by: str,
        status: str = "REQUESTED",
        row_id: UUID | None = None,
        created_at: datetime | None = None,
    ) -> InvestigationRequestRecord: ...

    async def record_proposal(
        self,
        proposal: InvestigationProposal,
        *,
        tenant_id: UUID,
        request_id: UUID,
        finding_id: UUID,
        model_calls_used: int,
        created_at: datetime | None = None,
    ) -> InvestigationProposalRecord: ...


class InvestigationService:
    """Run one bounded investigation for one finding.

    ``model=None`` (the default) means "no agentic stage": the request is
    recorded as ``SKIPPED`` and nothing else happens -- no LLM call, no
    network, no proposal.
    """

    def __init__(
        self,
        repo: InvestigationLedger,
        *,
        model: InvestigationModel | None = None,
        clock: Callable[[], datetime] | None = None,
        evidence_source: EvidenceFetcher | None = None,
    ) -> None:
        self._repo = repo
        self._model = model
        self._clock: Callable[[], datetime] = clock if clock is not None else _utcnow
        self._evidence_source = evidence_source

    async def investigate_finding(
        self,
        *,
        tenant_id: UUID,
        finding: Finding,
        evidence_snapshot_ids: Sequence[UUID] = (),
        requested_by: str,
    ) -> str:
        """Investigate one finding and return the recorded status.

        Returns ``REQUESTED`` | ``COMPLETED`` | ``SKIPPED`` | ``FAILED``. The
        return value is the durable status of the ledger row, never an
        authorization signal.
        """
        now = self._clock()
        request = build_investigation_request(
            finding,
            tenant_id=tenant_id,
            evidence_snapshot_ids=list(evidence_snapshot_ids),
            requested_by=requested_by,
            now=now,
        )
        if self._model is None:
            # Deterministic and offline: no model, no network, no proposal.
            await self._repo.record_request(
                request,
                requested_by=requested_by,
                status="SKIPPED",
                created_at=now,
            )
            return "SKIPPED"

        # Durable intent BEFORE the external call.
        await self._repo.record_request(
            request,
            requested_by=requested_by,
            status="REQUESTED",
            created_at=now,
        )
        try:
            proposal = await run_investigation(
                request,
                fetch_evidence=self._fetch_evidence,
                model=self._model,
                model_calls_used=0,
            )
        except Exception as exc:  # noqa: BLE001 - a failed stage is recorded, not raised
            reason = _bounded_reason(exc)
            if isinstance(exc, InvestigationBudgetExceeded):
                reason = f"model budget exhausted: {reason}"
            logger.warning("investigation failed for finding %s: %s", finding.id, reason)
            await self._append_terminal(
                request,
                requested_by=requested_by,
                status="FAILED",
                created_at=self._clock(),
            )
            return "FAILED"

        await self._repo.record_proposal(
            proposal,
            tenant_id=tenant_id,
            request_id=request.investigation_id,
            finding_id=finding.id,
            model_calls_used=1,
            created_at=self._clock(),
        )
        await self._append_terminal(
            request,
            requested_by=requested_by,
            status="COMPLETED",
            created_at=self._clock(),
        )
        return "COMPLETED"

    async def _append_terminal(
        self,
        request: InvestigationRequest,
        *,
        requested_by: str,
        status: str,
        created_at: datetime,
    ) -> InvestigationRequestRecord:
        """Append the terminal state row; the canonical row is never updated."""
        return await self._repo.record_request(
            request,
            requested_by=requested_by,
            status=status,
            row_id=uuid4(),
            created_at=created_at,
        )

    async def _fetch_evidence(self, ids: Sequence[UUID]) -> dict[UUID, str]:
        """Bounded, redacted evidence summaries for the model."""
        if self._evidence_source is None:
            return {}
        raw = await self._evidence_source(ids)
        return {
            key: redact_secrets(value if isinstance(value, str) else str(value))[:MAX_SUMMARY_CHARS]
            for key, value in raw.items()
        }


def _bounded_reason(exc: Exception) -> str:
    """A short, bounded description of a failure (never a secret-bearing dump)."""
    return f"{type(exc).__name__}: {exc}"[:MAX_REASON_CHARS]
