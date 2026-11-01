"""Findings queue + reviewer decisions (Task 14 HTTP surface).

Read-only listing and append-only reviewer decisions over the durable
findings / review_decisions stores. Tenant scoping is required on every
request; cross-tenant access is rejected (a finding in another tenant is
indistinguishable from a missing finding: 404).

Dependencies are declared as narrow protocols so the HTTP surface can be
exercised offline with fakes, while production passes the psycopg repos.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any, Protocol

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from itsm_agent.domain.models import Finding, ReviewDecision

router = APIRouter(prefix="/v1/findings", tags=["findings"])

DECISION_PATTERN = "^(CONFIRMED|FALSE_POSITIVE|ACCEPTED_RISK|NEEDS_MORE_EVIDENCE)$"


class FindingDecisionRequest(BaseModel):
    reviewer_id: str = Field(min_length=1, max_length=128)
    decision: str = Field(pattern=DECISION_PATTERN)
    rationale: str = Field(min_length=1, max_length=2000)
    evidence_pack_ref: str | None = None


class FindingsReader(Protocol):
    async def get(self, tenant_id: uuid.UUID, finding_id: uuid.UUID) -> Finding | None: ...

    async def list_for_tenant(self, tenant_id: uuid.UUID) -> list[Finding]: ...


class DecisionsStore(Protocol):
    async def record(self, decision: ReviewDecision) -> ReviewDecision: ...

    async def list_for_finding(
        self, tenant_id: uuid.UUID, finding_id: uuid.UUID
    ) -> list[ReviewDecision]: ...


class FindingsDeps:
    def __init__(
        self,
        *,
        findings_repo: FindingsReader,
        review_decisions_repo: DecisionsStore,
    ) -> None:
        self.findings_repo = findings_repo
        self.review_decisions_repo = review_decisions_repo


_deps: FindingsDeps | None = None


def configure_findings(deps: FindingsDeps | None) -> None:
    global _deps
    _deps = deps


def _deps_or_503() -> FindingsDeps:
    if _deps is None:
        raise HTTPException(status_code=503, detail="findings store not configured")
    return _deps


def _finding_json(finding: Finding) -> dict[str, Any]:
    return {
        "id": str(finding.id),
        "tenant_id": str(finding.tenant_id),
        "finding_type": finding.finding_type,
        "severity": str(finding.severity),
        "status": finding.status,
        "title": finding.title,
        "description": finding.description,
        "detected_at": finding.detected_at.isoformat(),
        "rule_version": finding.rule_version,
        "risk_score": finding.risk_score,
        "outcome": finding.outcome,
    }


def _decision_json(decision: ReviewDecision) -> dict[str, Any]:
    return {
        "id": str(decision.id),
        "reviewer_id": decision.reviewer_id,
        "decision": decision.decision,
        "decided_at": decision.decided_at.isoformat(),
        "rationale": decision.rationale,
        "evidence_pack_ref": decision.evidence_pack_ref,
    }


@router.get("")
async def list_findings(tenant_id: Annotated[uuid.UUID, Query()]) -> list[dict[str, Any]]:
    deps = _deps_or_503()
    findings = await deps.findings_repo.list_for_tenant(tenant_id)
    return [_finding_json(f) for f in findings]


@router.get("/{finding_id}")
async def get_finding(
    finding_id: uuid.UUID, tenant_id: Annotated[uuid.UUID, Query()]
) -> dict[str, Any]:
    deps = _deps_or_503()
    finding = await deps.findings_repo.get(tenant_id, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    decisions = await deps.review_decisions_repo.list_for_finding(tenant_id, finding_id)
    return {
        **_finding_json(finding),
        "review_decisions": [_decision_json(d) for d in decisions],
    }


@router.post("/{finding_id}/decisions", status_code=201)
async def record_decision(
    finding_id: uuid.UUID,
    body: FindingDecisionRequest,
    tenant_id: Annotated[uuid.UUID, Query()],
) -> dict[str, Any]:
    deps = _deps_or_503()
    finding = await deps.findings_repo.get(tenant_id, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    decision = ReviewDecision(
        tenant_id=tenant_id,
        finding_id=finding_id,
        reviewer_id=body.reviewer_id,
        decision=body.decision,  # validated by pattern; narrowed by Literal below
        rationale=body.rationale,
        evidence_pack_ref=body.evidence_pack_ref,
    )
    stored = await deps.review_decisions_repo.record(decision)
    return {"id": str(stored.id), "status": "recorded"}


@router.get("/{finding_id}/decisions")
async def list_decisions(
    finding_id: uuid.UUID, tenant_id: Annotated[uuid.UUID, Query()]
) -> list[dict[str, Any]]:
    deps = _deps_or_503()
    finding = await deps.findings_repo.get(tenant_id, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    decisions = await deps.review_decisions_repo.list_for_finding(tenant_id, finding_id)
    return [_decision_json(d) for d in decisions]


__all__ = [
    "DECISION_PATTERN",
    "DecisionsStore",
    "FindingDecisionRequest",
    "FindingsDeps",
    "FindingsReader",
    "configure_findings",
    "router",
]
