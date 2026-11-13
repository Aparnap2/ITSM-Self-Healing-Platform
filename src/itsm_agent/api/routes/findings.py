"""Findings queue + reviewer decisions (authenticated, tenant-scoped).

Security properties enforced here (and re-enforced by PostgreSQL RLS):
- Every request requires a verified bearer credential; identity is never taken
  from the request body. ``reviewer_id`` is derived from the principal.
- ``tenant_id`` in the query string is only a *requested scope*; it must be one
  of the principal's memberships or the request is rejected with 403.
- Reads require ``findings:read`` / ``decisions:read``; submitting a decision
  requires ``decisions:write`` plus the permission for that decision type.
- Lifecycle transitions require ``finding:transition`` — or the stronger
  ``finding:verify`` for ``VERIFIED``, whose independence rule is enforced by
  the domain, never by the caller.
- Authorization is evaluated before any database write.
- Cross-tenant access is indistinguishable from absence (404).
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any, Protocol, cast

from fastapi import APIRouter, Header, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from itsm_agent.api.auth import AuthenticationError, Authenticator, Principal
from itsm_agent.api.rbac import (
    AuthorizationError,
    Permission,
    authorize_decision,
    authorize_transition,
    require_permission,
)
from itsm_agent.domain.finding_lifecycle import (
    FindingStatus,
    FindingTransition,
    InvalidTransitionError,
    VerifierNotIndependentError,
)
from itsm_agent.domain.models import EvidenceReference, Finding, ReviewDecision
from itsm_agent.reporting.evidence_bundle import build_evidence_bundle

router = APIRouter(prefix="/v1/findings", tags=["findings"])

DECISION_PATTERN = "^(CONFIRMED|FALSE_POSITIVE|ACCEPTED_RISK|NEEDS_MORE_EVIDENCE)$"

#: Maximum length of the justification attached to a lifecycle transition.
MAX_TRANSITION_REASON_LENGTH = 1000


class FindingDecisionRequest(BaseModel):
    """Decision body. ``reviewer_id`` is intentionally absent: the actor is the
    authenticated principal, and unknown fields are rejected rather than ignored."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    decision: str = Field(pattern=DECISION_PATTERN)
    rationale: str = Field(min_length=1, max_length=2000)
    evidence_pack_ref: str | None = None


class FindingTransitionRequest(BaseModel):
    """Transition body. The actor is intentionally absent: it is the
    authenticated principal, and unknown fields are rejected rather than
    ignored."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    to_status: FindingStatus
    reason: str = Field(min_length=1, max_length=MAX_TRANSITION_REASON_LENGTH)


class FindingsReader(Protocol):
    async def get(self, tenant_id: uuid.UUID, finding_id: uuid.UUID) -> Finding | None: ...

    async def list_for_tenant(self, tenant_id: uuid.UUID) -> list[Finding]: ...


class EvidenceReferencesReader(Protocol):
    async def list_for_tenant_finding(
        self, tenant_id: uuid.UUID, finding_id: uuid.UUID
    ) -> list[EvidenceReference]: ...


class DecisionsStore(Protocol):
    async def record(self, decision: ReviewDecision) -> ReviewDecision: ...

    async def list_for_finding(
        self, tenant_id: uuid.UUID, finding_id: uuid.UUID
    ) -> list[ReviewDecision]: ...


class FindingTransitionsStore(Protocol):
    """Append-only lifecycle ledger for findings.

    ``apply_transition`` returns the updated finding, or ``None`` when no
    finding is visible for that tenant (the caller maps that to a 404). It
    raises the domain errors ``InvalidTransitionError`` and
    ``VerifierNotIndependentError``; the route never re-implements that
    policy.
    """

    async def apply_transition(
        self,
        tenant_id: uuid.UUID,
        finding_id: uuid.UUID,
        to_status: str,
        *,
        actor_id: str,
        reason: str,
        verifier_id: str | None = None,
    ) -> Finding | None: ...

    async def list_for_finding(
        self, tenant_id: uuid.UUID, finding_id: uuid.UUID
    ) -> list[FindingTransition]: ...


class FindingsDeps:
    def __init__(
        self,
        *,
        findings_repo: FindingsReader | None,
        review_decisions_repo: DecisionsStore | None,
        authenticator: Authenticator | None,
        evidence_references_repo: EvidenceReferencesReader | None = None,
        finding_transitions: FindingTransitionsStore | None = None,
    ) -> None:
        self.findings_repo = findings_repo
        self.review_decisions_repo = review_decisions_repo
        self.authenticator = authenticator
        self.evidence_references_repo = evidence_references_repo
        self.finding_transitions = finding_transitions


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


def _transition_json(transition: FindingTransition) -> dict[str, Any]:
    return {
        "id": str(transition.id),
        "from_status": transition.from_status,
        "to_status": transition.to_status,
        "actor_id": transition.actor_id,
        "verifier_id": transition.verifier_id,
        "reason": transition.reason,
        "transitioned_at": transition.transitioned_at.isoformat(),
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


@router.post("/{finding_id}/transition")
async def transition_finding(
    request: Request,
    finding_id: uuid.UUID,
    body: FindingTransitionRequest,
    tenant_id: Annotated[uuid.UUID, Query()],
    authorization: Annotated[str | None, Header()] = None,
) -> Response:
    """Apply one lifecycle transition to a finding.

    Authorization order is authenticate -> tenant membership -> permission ->
    existence, so an under-privileged caller is rejected before anything is
    read or written, and a caller who may not see the finding learns nothing
    beyond "finding not found".
    """
    deps = _configured_deps(request)
    if deps.finding_transitions is None:
        # Fail closed: a lifecycle change without its append-only ledger cannot
        # be applied — the ledger *is* the audit trail for the decision.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="finding transition store not configured",
        )
    principal = await _authenticated_principal(request, authorization)
    _authorize_tenant(principal, tenant_id)
    try:
        authorize_transition(principal, body.to_status.value)
    except AuthorizationError as exc:
        detail = (
            f"missing permission: {exc.permission.value}"
            if exc.permission is not None
            else "transition target not permitted for this principal"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
        ) from exc

    assert deps.finding_transitions is not None
    # Actor provenance comes from the verified credential, never the body. The
    # verifier is the same principal; the domain independently checks that the
    # verifier is not the actor that closed the finding out.
    verifier_id = principal.principal_id if body.to_status is FindingStatus.VERIFIED else None
    try:
        updated = await deps.finding_transitions.apply_transition(
            tenant_id,
            finding_id,
            body.to_status.value,
            actor_id=principal.principal_id,
            reason=body.reason,
            verifier_id=verifier_id,
        )
    except InvalidTransitionError as exc:
        return JSONResponse(status_code=409, content={"detail": str(exc), "code": exc.code})
    except VerifierNotIndependentError as exc:
        return JSONResponse(status_code=409, content={"detail": str(exc), "code": exc.code})
    if updated is None:
        # A finding owned by another tenant is indistinguishable from a
        # missing one; nothing was written.
        raise HTTPException(status_code=404, detail="finding not found")
    return JSONResponse(status_code=200, content=_finding_json(updated))


@router.get("/{finding_id}/transitions")
async def list_transitions(
    request: Request,
    finding_id: uuid.UUID,
    tenant_id: Annotated[uuid.UUID, Query()],
    authorization: Annotated[str | None, Header()] = None,
) -> list[dict[str, Any]]:
    """The append-only lifecycle ledger for one finding, newest first."""
    deps = _configured_deps(request)
    if deps.finding_transitions is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="finding transition store not configured",
        )
    principal = await _authenticated_principal(request, authorization)
    _authorize_tenant(principal, tenant_id)
    _authorize(principal, Permission.FINDINGS_READ)
    assert deps.findings_repo is not None
    assert deps.finding_transitions is not None
    finding = await deps.findings_repo.get(tenant_id, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    transitions = await deps.finding_transitions.list_for_finding(tenant_id, finding_id)
    # Newest first, independent of the collaborator's ordering.
    ordered = sorted(transitions, key=lambda t: (t.transitioned_at, t.id), reverse=True)
    return [_transition_json(t) for t in ordered]


@router.get("/{finding_id}/bundle")
async def get_evidence_bundle(
    request: Request,
    finding_id: uuid.UUID,
    tenant_id: Annotated[uuid.UUID, Query()],
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    deps = _configured_deps(request)
    if deps.evidence_references_repo is None:
        # Fail closed: an evidence bundle without its store cannot be served.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="evidence reference store not configured",
        )
    principal = await _authenticated_principal(request, authorization)
    _authorize_tenant(principal, tenant_id)
    _authorize(principal, Permission.FINDINGS_READ)
    _authorize(principal, Permission.DECISIONS_READ)
    assert deps.findings_repo is not None
    assert deps.review_decisions_repo is not None
    finding = await deps.findings_repo.get(tenant_id, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    evidence = await deps.evidence_references_repo.list_for_tenant_finding(tenant_id, finding_id)
    decisions = await deps.review_decisions_repo.list_for_finding(tenant_id, finding_id)
    return build_evidence_bundle(finding, evidence, [_decision_json(d) for d in decisions])


__all__ = [
    "DECISION_PATTERN",
    "MAX_TRANSITION_REASON_LENGTH",
    "DecisionsStore",
    "FindingDecisionRequest",
    "FindingTransitionRequest",
    "FindingTransitionsStore",
    "FindingsDeps",
    "FindingsReader",
    "configure_findings",
    "router",
]
