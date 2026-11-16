"""Unit tests for the reviewer provisioning path (offline).

Marker: ``unit``. No database and no network: these tests pin the refusal
rules — the ones that keep the administration plane from becoming a
general-purpose authorization bypass.
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
import uuid
from pathlib import Path
from types import ModuleType

import pytest

from itsm_agent.adapters.persistence.reviewer_admin import (
    ProvisioningRefused,
    ReviewerGrant,
    next_authorization_version,
)

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CLI_PATH = REPO_ROOT / "tools" / "provision_reviewer.py"


def _load_cli() -> ModuleType:
    spec = importlib.util.spec_from_file_location("provision_reviewer_cli", CLI_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CLI = _load_cli()


def _args(**overrides: object) -> argparse.Namespace:
    base: dict[str, object] = {
        "issuer": "https://issuer.staging.test",
        "subject": ["reviewer-a"],
        "roles": "reviewer",
        "tenants": str(uuid.uuid4()),
        "reason": "staging rehearsal",
        "actor": "secops.admin",
        "revoke": False,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


# ---------------------------------------------------------------------------
# Request validation
# ---------------------------------------------------------------------------


def test_valid_request_is_accepted() -> None:
    request = CLI.parse_request(_args())

    assert request.issuer == "https://issuer.staging.test"
    assert request.subjects == ("reviewer-a",)
    assert request.roles == ("reviewer",)
    assert len(request.tenant_ids) == 1


def test_multiple_subjects_are_accepted_and_deduplicated() -> None:
    request = CLI.parse_request(_args(subject=["reviewer-a", "reviewer-b", "reviewer-a"]))

    assert request.subjects == ("reviewer-a", "reviewer-b")


def test_unknown_role_is_refused() -> None:
    with pytest.raises(CLI.RequestError, match="unknown role"):
        CLI.parse_request(_args(roles="reviewer,wizard"))


def test_empty_role_list_is_refused() -> None:
    with pytest.raises(CLI.RequestError, match="role"):
        CLI.parse_request(_args(roles=" , "))


def test_empty_subject_list_is_refused() -> None:
    with pytest.raises(CLI.RequestError, match="subject"):
        CLI.parse_request(_args(subject=[]))


def test_blank_subject_is_refused() -> None:
    with pytest.raises(CLI.RequestError, match="subject"):
        CLI.parse_request(_args(subject=["   "]))


def test_missing_tenant_is_refused() -> None:
    with pytest.raises(CLI.RequestError, match="tenant"):
        CLI.parse_request(_args(tenants=""))


def test_invalid_tenant_uuid_is_refused() -> None:
    with pytest.raises(CLI.RequestError, match="not a valid tenant UUID"):
        CLI.parse_request(_args(tenants="not-a-uuid"))


def test_duplicate_tenants_are_refused() -> None:
    tenant = str(uuid.uuid4())
    with pytest.raises(CLI.RequestError, match="duplicates"):
        CLI.parse_request(_args(tenants=f"{tenant},{tenant}"))


def test_missing_reason_is_refused() -> None:
    with pytest.raises(CLI.RequestError, match="reason"):
        CLI.parse_request(_args(reason="   "))


def test_missing_issuer_is_refused() -> None:
    with pytest.raises(CLI.RequestError, match="issuer"):
        CLI.parse_request(_args(issuer="  "))


def test_cli_without_admin_dsn_refuses_before_touching_anything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ITSM_ADMIN_DSN", raising=False)
    monkeypatch.setattr(CLI, "run", _fail_if_called("the CLI must refuse before connecting"))

    argv = [
        "--issuer",
        "https://issuer.staging.test",
        "--subject",
        "reviewer-a",
        "--roles",
        "reviewer",
        "--tenants",
        str(uuid.uuid4()),
        "--reason",
        "staging rehearsal",
    ]
    assert CLI.main(argv) == CLI.EXIT_REFUSED


def _fail_if_called(message: str):  # type: ignore[no-untyped-def]
    async def _run(*args: object, **kwargs: object) -> list[object]:
        raise AssertionError(message)

    return _run


# ---------------------------------------------------------------------------
# Grant model
# ---------------------------------------------------------------------------


def test_grant_requires_roles_tenants_and_reason() -> None:
    tenant = uuid.uuid4()
    with pytest.raises(ProvisioningRefused, match="role"):
        ReviewerGrant(
            issuer="https://issuer.test",
            subject="reviewer-a",
            tenant_ids=(tenant,),
            roles=(),
        )
    with pytest.raises(ProvisioningRefused, match="tenant"):
        ReviewerGrant(
            issuer="https://issuer.test",
            subject="reviewer-a",
            tenant_ids=(),
            roles=("reviewer",),
        )
    with pytest.raises(ProvisioningRefused, match="reason"):
        ReviewerGrant(
            issuer="https://issuer.test",
            subject="reviewer-a",
            tenant_ids=(tenant,),
            roles=("reviewer",),
            reason="  ",
        )


def test_grant_rejects_duplicate_tenants_and_roles() -> None:
    tenant = uuid.uuid4()
    with pytest.raises(ProvisioningRefused, match="duplicate"):
        ReviewerGrant(
            issuer="https://issuer.test",
            subject="reviewer-a",
            tenant_ids=(tenant, tenant),
            roles=("reviewer",),
        )
    with pytest.raises(ProvisioningRefused, match="duplicate"):
        ReviewerGrant(
            issuer="https://issuer.test",
            subject="reviewer-a",
            tenant_ids=(tenant,),
            roles=("reviewer", "reviewer"),
        )


def test_entity_id_is_stable_for_the_same_issuer_and_subject() -> None:
    tenant = uuid.uuid4()
    first = ReviewerGrant(
        issuer="https://issuer.test",
        subject="reviewer-a",
        tenant_ids=(tenant,),
        roles=("reviewer",),
        reason="provision",
    )
    second = ReviewerGrant(
        issuer="https://issuer.test",
        subject="reviewer-a",
        tenant_ids=(tenant,),
        roles=("admin",),
        reason="change",
    )

    assert first.entity_id == second.entity_id


def test_version_sequence_increments_and_survives_legacy_values() -> None:
    assert next_authorization_version(None) == "1"
    assert next_authorization_version("1") == "2"
    assert next_authorization_version("9") == "10"
    # A legacy non-numeric version restarts the numeric sequence.
    assert next_authorization_version("legacy") == "1"
