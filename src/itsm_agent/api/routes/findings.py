"""Findings queue + reviewer decisions (authenticated, tenant-scoped).

Security properties enforced here (and re-enforced by PostgreSQL RLS):
- Every request requires a verified bearer credential; identity is never taken
  from the request body. ``reviewer_id`` is derived from the principal.
- ``tenant_id`` in the query string is only a *requested scope*; it must be one
  of the principal's memberships or the request is rejected with 403.
- Reads require ``findings:read`` / ``decisions:read``; submitting a decision
  requires ``decisions:write`` plus the permission for that decision type.
- Authorization is evaluated before any database write.
- Cross-tenant access is indistinguishable from absence (404).
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any, Protocol, cast

from fastapi import APIRouter, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field

from itsm_agent.api.auth import AuthenticationError, Authenticator, Principal
from itsm_agent.api.rbac import (
    AuthorizationError,
    Permission,
    authorize_decision,
    require_permission,
)
from itsm_agent.domain.models import Finding, ReviewDecision

router = APIRouter(prefix="/v1/findings", tags=["findings"])

DECISION_PATTERN = "^(CONFIRMED|FALSE_POSITIVE|ACCEPTED_RISK|NEEDS_MORE_EVIDENCE)$"


class FindingDecisionRequest(BaseModel):
    """Decision body. ``reviewer_id`` is intentionally absent: the actor is the
    authenticated principal, and unknown fields are rejected rather than ignored."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

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
        findings_repo: FindingsReader | None,
        review_decisions_repo: DecisionsStore | None,
        authenticator: Authenticator | None,
    ) -> None:
        self.findings_repo = findings_repo
        self.review_decisions_repo = review_decisions_repo
        self.authenticator = authenticator


_deps: FindingsDeps | None = None


def configure_findings(deps: FindingsDeps | None) -> None:
    """Deprecated process-global hook (kept only for import compatibility).

    .. deprecated::
       Do not use. The app factory now stores dependencies on
       ``app.state.findings_deps`` so independent app instances cannot share
       mutable configuration. This function remains as a no-op-shaped shim and
       is removed in the next slice.
    """
    global _deps
    _deps = deps


def _configured_deps(request: Request) -> FindingsDeps:
    deps = cast(FindingsDeps | None, getattr(request.app.state, "findings_deps", None))
    if (
        deps is None
        or deps.findings_repo is None
        or deps.review_decisions_repo is None
        or deps.authenticator is None
    ):
        # Fail closed: no unauthenticated findings surface is ever served.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="findings store or authentication not configured",
        )
    return deps


async def _authenticated_principal(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> Principal:
    deps = _configured_deps(request)
    assert deps.authenticator is not None
    try:
        return await deps.authenticator.authenticate(authorization)
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def _authorize_tenant(principal: Principal, tenant_id: uuid.UUID) -> None:
    if not principal.may_access_tenant(tenant_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="principal is not a member of the requested tenant",
        )


def _authorize(principal: Principal, permission: Permission) -> None:
    try:
        require_permission(principal, permission)
    except AuthorizationError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"missing permission: {permission.value}",
        ) from exc


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
async def list_findings(
    request: Request,
    tenant_id: Annotated[uuid.UUID, Query()],
    authorization: Annotated[str | None, Header()] = None,
) -> list[dict[str, Any]]:
    deps = _configured_deps(request)
    principal = await _authenticated_principal(request, authorization)
    _authorize_tenant(principal, tenant_id)
    _authorize(principal, Permission.FINDINGS_READ)
    assert deps.findings_repo is not None
    findings = await deps.findings_repo.list_for_tenant(tenant_id)
    return [_finding_json(f) for f in findings]


@router.get("/{finding_id}")
async def get_finding(
    request: Request,
    finding_id: uuid.UUID,
    tenant_id: Annotated[uuid.UUID, Query()],
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    deps = _configured_deps(request)
    principal = await _authenticated_principal(request, authorization)
    _authorize_tenant(principal, tenant_id)
    _authorize(principal, Permission.FINDINGS_READ)
    _authorize(principal, Permission.DECISIONS_READ)
    assert deps.findings_repo is not None
    assert deps.review_decisions_repo is not None
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
    request: Request,
    finding_id: uuid.UUID,
    body: FindingDecisionRequest,
    tenant_id: Annotated[uuid.UUID, Query()],
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    deps = _configured_deps(request)
    principal = await _authenticated_principal(request, authorization)
    _authorize_tenant(principal, tenant_id)
    try:
        authorize_decision(principal, body.decision)
    except AuthorizationError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="decision type not permitted for this principal",
        ) from exc

    assert deps.findings_repo is not None
    assert deps.review_decisions_repo is not None
    finding = await deps.findings_repo.get(tenant_id, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")

    decision = ReviewDecision(
        tenant_id=tenant_id,
        finding_id=finding_id,
        # Actor provenance comes from the verified credential, never the body.
        reviewer_id=principal.principal_id,
        decision=body.decision,
        rationale=body.rationale,
        evidence_pack_ref=body.evidence_pack_ref,
    )
    stored = await deps.review_decisions_repo.record(decision)
    return {"id": str(stored.id), "status": "recorded"}


@router.get("/{finding_id}/decisions")
async def list_decisions(
    request: Request,
    finding_id: uuid.UUID,
    tenant_id: Annotated[uuid.UUID, Query()],
    authorization: Annotated[str | None, Header()] = None,
) -> list[dict[str, Any]]:
    deps = _configured_deps(request)
    principal = await _authenticated_principal(request, authorization)
    _authorize_tenant(principal, tenant_id)
    _authorize(principal, Permission.DECISIONS_READ)
    assert deps.findings_repo is not None
    assert deps.review_decisions_repo is not None
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
