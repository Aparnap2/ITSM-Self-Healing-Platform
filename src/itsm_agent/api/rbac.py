"""Deterministic reviewer authorization (RBAC).

Permissions are a fixed, explicit allowlist. Roles map to permissions in code
(not in the database, not in the request), and every check is deny-by-default:
an unknown permission, role, or decision type grants nothing.

The decision-type permissions exist because not every reviewer may close every
kind of finding: an analyst may request more evidence but may not confirm a
violation, while a reviewer may decide the full set. That distinction is
tested, not assumed.

The same reasoning applies to finding lifecycle transitions: moving a
finding between lifecycle statuses is a separate authority from reading it,
and independently *verifying* a closed-out finding is a stronger authority
still (``finding:verify`` vs ``finding:transition``).
"""

from __future__ import annotations

from enum import StrEnum

from itsm_agent.api.auth import Principal, Role
from itsm_agent.domain.finding_lifecycle import FindingStatus


class Permission(StrEnum):
    FINDINGS_READ = "findings:read"
    DECISIONS_READ = "decisions:read"
    DECISIONS_WRITE = "decisions:write"
    DECISION_CONFIRM = "decision:confirm"
    DECISION_FALSE_POSITIVE = "decision:false_positive"
    DECISION_ACCEPTED_RISK = "decision:accepted_risk"
    DECISION_NEEDS_MORE_EVIDENCE = "decision:needs_more_evidence"
    FINDING_TRANSITION = "finding:transition"
    FINDING_VERIFY = "finding:verify"
    ADMIN_MANAGE = "admin:manage"


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.AUDITOR: frozenset(
        {
            Permission.FINDINGS_READ,
            Permission.DECISIONS_READ,
        }
    ),
    Role.ANALYST: frozenset(
        {
            Permission.FINDINGS_READ,
            Permission.DECISIONS_READ,
            Permission.DECISIONS_WRITE,
            Permission.DECISION_NEEDS_MORE_EVIDENCE,
        }
    ),
    Role.REVIEWER: frozenset(
        {
            Permission.FINDINGS_READ,
            Permission.DECISIONS_READ,
            Permission.DECISIONS_WRITE,
            Permission.DECISION_CONFIRM,
            Permission.DECISION_FALSE_POSITIVE,
            Permission.DECISION_ACCEPTED_RISK,
            Permission.DECISION_NEEDS_MORE_EVIDENCE,
            Permission.FINDING_TRANSITION,
            Permission.FINDING_VERIFY,
        }
    ),
    Role.ADMIN: frozenset(Permission),
}

DECISION_PERMISSIONS: dict[str, Permission] = {
    "CONFIRMED": Permission.DECISION_CONFIRM,
    "FALSE_POSITIVE": Permission.DECISION_FALSE_POSITIVE,
    "ACCEPTED_RISK": Permission.DECISION_ACCEPTED_RISK,
    "NEEDS_MORE_EVIDENCE": Permission.DECISION_NEEDS_MORE_EVIDENCE,
}

#: Permission required to move a finding into each target status.
#:
#: ``VERIFIED`` carries its own permission: independent verification of a
#: closed-out finding is a stronger authority than an ordinary lifecycle
#: move, so it must be granted (and can be revoked) independently. Every
#: other status is an ordinary transition.
TRANSITION_PERMISSIONS: dict[str, Permission] = {
    FindingStatus.OPEN.value: Permission.FINDING_TRANSITION,
    FindingStatus.ACKNOWLEDGED.value: Permission.FINDING_TRANSITION,
    FindingStatus.INVESTIGATING.value: Permission.FINDING_TRANSITION,
    FindingStatus.CONFIRMED.value: Permission.FINDING_TRANSITION,
    FindingStatus.RESOLVED.value: Permission.FINDING_TRANSITION,
    FindingStatus.VERIFIED.value: Permission.FINDING_VERIFY,
    FindingStatus.FALSE_POSITIVE.value: Permission.FINDING_TRANSITION,
    FindingStatus.ACCEPTED_RISK.value: Permission.FINDING_TRANSITION,
    FindingStatus.ESCALATED.value: Permission.FINDING_TRANSITION,
}


class AuthorizationError(Exception):
    """The authenticated principal may not perform the requested operation."""

    def __init__(self, permission: Permission | None = None, detail: str = "") -> None:
        self.permission = permission
        super().__init__(detail or (permission.value if permission else "forbidden"))


class UnknownDecisionError(AuthorizationError):
    """Decision value outside the explicit allowlist."""


class UnknownTransitionError(AuthorizationError):
    """Transition target outside the explicit allowlist."""


def permissions_for(principal: Principal) -> frozenset[Permission]:
    granted: set[Permission] = set()
    for role in principal.roles:
        granted |= ROLE_PERMISSIONS.get(role, frozenset())
    return frozenset(granted)


def has_permission(principal: Principal, permission: Permission) -> bool:
    return permission in permissions_for(principal)


def require_permission(principal: Principal, permission: Permission) -> None:
    if not has_permission(principal, permission):
        raise AuthorizationError(permission)


def authorize_decision(principal: Principal, decision: str) -> Permission:
    """Authorize a decision submission; returns the decision-type permission.

    Denies before any write: unknown decision types, missing write permission,
    and decision types the principal's roles do not include.
    """
    decision_permission = DECISION_PERMISSIONS.get(decision)
    if decision_permission is None:
        raise UnknownDecisionError(detail="decision type is not allowlisted")
    require_permission(principal, Permission.DECISIONS_WRITE)
    require_permission(principal, decision_permission)
    return decision_permission


def authorize_transition(principal: Principal, to_status: str) -> Permission:
    """Authorize a finding lifecycle transition; returns the required permission.

    Denies before any write: an unknown target grants nothing, and the target
    must be one this principal's roles permit. Whether the *edge* is legal
    from the finding's current status is decided by the domain state machine
    (``itsm_agent.domain.finding_lifecycle``) — authorization never depends on
    mutable finding state, and a transition is never authorized by the fact
    that it was proposed.
    """
    transition_permission = TRANSITION_PERMISSIONS.get(to_status)
    if transition_permission is None:
        raise UnknownTransitionError(detail="transition target is not allowlisted")
    require_permission(principal, transition_permission)
    return transition_permission


__all__ = [
    "DECISION_PERMISSIONS",
    "ROLE_PERMISSIONS",
    "TRANSITION_PERMISSIONS",
    "AuthorizationError",
    "Permission",
    "UnknownDecisionError",
    "UnknownTransitionError",
    "authorize_decision",
    "authorize_transition",
    "has_permission",
    "permissions_for",
    "require_permission",
]
