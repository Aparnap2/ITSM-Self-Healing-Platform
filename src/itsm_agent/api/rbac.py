"""Deterministic reviewer authorization (RBAC).

Permissions are a fixed, explicit allowlist. Roles map to permissions in code
(not in the database, not in the request), and every check is deny-by-default:
an unknown permission, role, or decision type grants nothing.

The decision-type permissions exist because not every reviewer may close every
kind of finding: an analyst may request more evidence but may not confirm a
violation, while a reviewer may decide the full set. That distinction is
tested, not assumed.
"""

from __future__ import annotations

from enum import StrEnum

from itsm_agent.api.auth import Principal, Role


class Permission(StrEnum):
    FINDINGS_READ = "findings:read"
    DECISIONS_READ = "decisions:read"
    DECISIONS_WRITE = "decisions:write"
    DECISION_CONFIRM = "decision:confirm"
    DECISION_FALSE_POSITIVE = "decision:false_positive"
    DECISION_ACCEPTED_RISK = "decision:accepted_risk"
    DECISION_NEEDS_MORE_EVIDENCE = "decision:needs_more_evidence"
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


class AuthorizationError(Exception):
    """The authenticated principal may not perform the requested operation."""

    def __init__(self, permission: Permission | None = None, detail: str = "") -> None:
        self.permission = permission
        super().__init__(detail or (permission.value if permission else "forbidden"))


class UnknownDecisionError(AuthorizationError):
    """Decision value outside the explicit allowlist."""


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


__all__ = [
    "DECISION_PERMISSIONS",
    "ROLE_PERMISSIONS",
    "AuthorizationError",
    "Permission",
    "UnknownDecisionError",
    "authorize_decision",
    "has_permission",
    "permissions_for",
    "require_permission",
]
