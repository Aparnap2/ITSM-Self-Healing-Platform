"""Unit tests for reviewer authentication and RBAC (security slice).

Pure and offline: token minting/verification is HMAC over an in-process secret.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from itsm_agent.api.auth import (
    DEFAULT_ISSUER,
    ExpiredCredentialsError,
    InvalidCredentialsError,
    Principal,
    Role,
    TokenAuthenticator,
    mint_token,
)
from itsm_agent.api.rbac import (
    DECISION_PERMISSIONS,
    ROLE_PERMISSIONS,
    AuthorizationError,
    Permission,
    UnknownDecisionError,
    authorize_decision,
    has_permission,
    permissions_for,
    require_permission,
)

pytestmark = pytest.mark.unit

SECRET = "rbac-unit-test-secret-0123456789"
TENANT = uuid.uuid4()
OTHER_TENANT = uuid.uuid4()


def _principal(*roles: Role, tenants: tuple[uuid.UUID, ...] = (TENANT,)) -> Principal:
    return Principal(
        principal_id="reviewer-1",
        tenant_ids=tenants,
        roles=roles or (Role.REVIEWER,),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


async def test_valid_token_resolves_principal() -> None:
    token = mint_token(
        SECRET,
        principal_id="alice",
        tenant_ids=[TENANT, OTHER_TENANT],
        roles=["reviewer", "auditor"],
    )
    principal = await TokenAuthenticator(secret=SECRET).authenticate(f"Bearer {token}")
    assert principal.principal_id == "alice"
    assert principal.tenant_ids == (TENANT, OTHER_TENANT)
    assert principal.roles == (Role.REVIEWER, Role.AUDITOR)
    assert principal.issuer == DEFAULT_ISSUER
    assert principal.may_access_tenant(TENANT)


@pytest.mark.parametrize(
    "header",
    [None, "", "Bearer", "Bearer ", "Basic abc", "Bearer not-a-token", "Bearer  a.b"],
)
async def test_malformed_credentials_are_rejected(header: str | None) -> None:
    with pytest.raises(InvalidCredentialsError):
        await TokenAuthenticator(secret=SECRET).authenticate(header)


async def test_non_ascii_token_is_rejected_not_crashed() -> None:
    with pytest.raises(InvalidCredentialsError):
        await TokenAuthenticator(secret=SECRET).authenticate("Bearer v1.é.ü")


async def test_tampered_payload_is_rejected() -> None:
    token = mint_token(SECRET, principal_id="alice", tenant_ids=[TENANT], roles=["admin"])
    version, payload, signature = token.split(".")
    forged = f"{version}.{payload}.{'A' * len(signature)}"
    with pytest.raises(InvalidCredentialsError):
        await TokenAuthenticator(secret=SECRET).authenticate(f"Bearer {forged}")


async def test_expired_token_is_rejected_with_specific_error() -> None:
    past = datetime.now(UTC) - timedelta(hours=1)
    token = mint_token(
        SECRET,
        principal_id="alice",
        tenant_ids=[TENANT],
        roles=["reviewer"],
        issued_at=past,
        ttl_seconds=30,
    )
    with pytest.raises(ExpiredCredentialsError):
        await TokenAuthenticator(secret=SECRET).authenticate(f"Bearer {token}")


async def test_wrong_issuer_is_rejected() -> None:
    token = mint_token(
        SECRET,
        principal_id="alice",
        tenant_ids=[TENANT],
        roles=["reviewer"],
        issuer="someone-else",
    )
    with pytest.raises(InvalidCredentialsError):
        await TokenAuthenticator(secret=SECRET).authenticate(f"Bearer {token}")


async def test_token_without_tenants_is_rejected() -> None:
    token = mint_token(SECRET, principal_id="alice", tenant_ids=[], roles=["reviewer"])
    with pytest.raises(InvalidCredentialsError):
        await TokenAuthenticator(secret=SECRET).authenticate(f"Bearer {token}")


def test_short_secret_is_refused() -> None:
    with pytest.raises(ValueError):
        TokenAuthenticator(secret="short")


def test_principal_requires_aware_expiry() -> None:
    with pytest.raises(ValidationError):
        Principal(
            principal_id="alice",
            tenant_ids=(TENANT,),
            roles=(Role.REVIEWER,),
            expires_at=datetime(2030, 1, 1),  # noqa: DTZ001 - intentionally naive
        )


# ---------------------------------------------------------------------------
# RBAC matrix
# ---------------------------------------------------------------------------


def test_role_permission_matrix_is_explicit() -> None:
    assert permissions_for(_principal(Role.AUDITOR)) == {
        Permission.FINDINGS_READ,
        Permission.DECISIONS_READ,
    }
    assert Permission.DECISIONS_WRITE not in permissions_for(_principal(Role.AUDITOR))
    assert Permission.DECISION_CONFIRM not in permissions_for(_principal(Role.ANALYST))
    assert Permission.DECISION_NEEDS_MORE_EVIDENCE in permissions_for(_principal(Role.ANALYST))
    assert permissions_for(_principal(Role.ADMIN)) == frozenset(Permission)
    # Every role maps to at least one permission and every permission is known.
    for role, granted in ROLE_PERMISSIONS.items():
        assert granted, f"{role} has no permissions"
        assert granted <= frozenset(Permission)


def test_unknown_role_cannot_be_constructed() -> None:
    with pytest.raises(ValidationError):
        Principal(
            principal_id="alice",
            tenant_ids=(TENANT,),
            roles=("superuser",),
            expires_at=datetime.now(UTC) + timedelta(minutes=1),
        )


def test_require_permission_fails_closed() -> None:
    with pytest.raises(AuthorizationError):
        require_permission(_principal(Role.AUDITOR), Permission.DECISIONS_WRITE)
    assert has_permission(_principal(Role.REVIEWER), Permission.DECISIONS_WRITE)


def test_every_decision_type_has_a_permission() -> None:
    assert set(DECISION_PERMISSIONS) == {
        "CONFIRMED",
        "FALSE_POSITIVE",
        "ACCEPTED_RISK",
        "NEEDS_MORE_EVIDENCE",
    }
    assert all(isinstance(p, Permission) for p in DECISION_PERMISSIONS.values())


def test_authorize_decision_enforces_role_and_type() -> None:
    assert authorize_decision(_principal(Role.REVIEWER), "CONFIRMED") == Permission.DECISION_CONFIRM
    with pytest.raises(AuthorizationError):
        authorize_decision(_principal(Role.ANALYST), "CONFIRMED")
    with pytest.raises(AuthorizationError):
        authorize_decision(_principal(Role.AUDITOR), "NEEDS_MORE_EVIDENCE")
    with pytest.raises(UnknownDecisionError):
        authorize_decision(_principal(Role.ADMIN), "APPROVED")


def test_tenant_membership_is_authoritative() -> None:
    principal = _principal(Role.REVIEWER, tenants=(TENANT,))
    assert principal.may_access_tenant(TENANT)
    assert not principal.may_access_tenant(OTHER_TENANT)
