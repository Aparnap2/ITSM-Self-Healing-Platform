"""Unit tests for identity resolution (no I/O)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from itsm_agent.domain.identity_resolution import (
    resolve_assumed_role,
    resolve_cross_source,
    resolve_identity,
    resolve_resource_alias,
)
from itsm_agent.domain.models import IdentityMapping

TENANT = uuid.uuid4()
INTERNAL_A = uuid.uuid4()
INTERNAL_B = uuid.uuid4()
NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _mapping(
    internal: uuid.UUID,
    valid_from: datetime = NOW,
    valid_to: datetime | None = None,
) -> IdentityMapping:
    return IdentityMapping(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        source_system="github",
        source_identifier="alice",
        internal_identity_id=internal,
        confidence="HIGH",
        provenance="test",
        valid_from=valid_from,
        valid_to=valid_to,
    )


def test_resolved_single() -> None:
    iid, status = resolve_identity([_mapping(INTERNAL_A)], at=NOW)
    assert status == "RESOLVED"
    assert iid == INTERNAL_A


def test_unresolved_none() -> None:
    iid, status = resolve_identity([], at=NOW)
    assert status == "UNRESOLVED"
    assert iid is None


def test_ambiguous_multiple() -> None:
    iid, status = resolve_identity([_mapping(INTERNAL_A), _mapping(INTERNAL_B)], at=NOW)
    assert status == "AMBIGUOUS"
    assert iid is None


def test_time_validity() -> None:
    past = NOW - timedelta(days=10)
    m = _mapping(INTERNAL_A, valid_from=past, valid_to=NOW - timedelta(days=1))
    iid, status = resolve_identity([m], at=NOW)
    assert status == "UNRESOLVED"


def test_cross_tenant_not_resolved_here() -> None:
    # resolver operates on provided mappings; tenant filtering is caller's job
    m = _mapping(INTERNAL_A)
    iid, status = resolve_identity([m], at=NOW)
    assert status == "RESOLVED"


def test_cross_source_resolved_agreeing() -> None:
    # build mappings per source
    aws_m = IdentityMapping(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        source_system="aws",
        source_identifier="arn:aws:iam::123:user/alice",
        internal_identity_id=INTERNAL_A,
        confidence="HIGH",
        provenance="aws",
        valid_from=NOW,
        valid_to=None,
    )
    gh_m = IdentityMapping(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        source_system="github",
        source_identifier="alice",
        internal_identity_id=INTERNAL_A,
        confidence="HIGH",
        provenance="github",
        valid_from=NOW,
        valid_to=None,
    )
    iid, status, notes = resolve_cross_source({"aws": [aws_m], "github": [gh_m]}, at=NOW)
    assert status == "RESOLVED"
    assert iid == INTERNAL_A
    assert len(notes) == 2


def test_cross_source_ambiguous_disagreement() -> None:
    aws_m = IdentityMapping(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        source_system="aws",
        source_identifier="arn:aws:iam::123:user/alice",
        internal_identity_id=INTERNAL_A,
        confidence="HIGH",
        provenance="aws",
        valid_from=NOW,
        valid_to=None,
    )
    gh_m = IdentityMapping(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        source_system="github",
        source_identifier="alice",
        internal_identity_id=INTERNAL_B,
        confidence="HIGH",
        provenance="github",
        valid_from=NOW,
        valid_to=None,
    )
    iid, status, notes = resolve_cross_source({"aws": [aws_m], "github": [gh_m]}, at=NOW)
    assert status == "AMBIGUOUS"
    assert iid is None


def test_cross_source_unresolved_all() -> None:
    iid, status, notes = resolve_cross_source({"aws": [], "github": []}, at=NOW)
    assert status == "UNRESOLVED"
    assert iid is None


def test_cross_source_partial_unresolved_still_resolved() -> None:
    aws_m = IdentityMapping(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        source_system="aws",
        source_identifier="arn:aws:iam::123:user/alice",
        internal_identity_id=INTERNAL_A,
        confidence="HIGH",
        provenance="aws",
        valid_from=NOW,
        valid_to=None,
    )
    iid, status, notes = resolve_cross_source({"aws": [aws_m], "github": []}, at=NOW)
    assert status == "RESOLVED"
    assert iid == INTERNAL_A


def test_assumed_role_prefers_base_identity() -> None:
    role_m = IdentityMapping(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        source_system="aws",
        source_identifier="arn:aws:sts::123:assumed-role/Admin/session",
        internal_identity_id=INTERNAL_B,
        confidence="MEDIUM",
        provenance="sts",
        valid_from=NOW,
        valid_to=None,
    )
    base_m = IdentityMapping(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        source_system="aws",
        source_identifier="arn:aws:iam::123:user/alice",
        internal_identity_id=INTERNAL_A,
        confidence="HIGH",
        provenance="aws",
        valid_from=NOW,
        valid_to=None,
    )
    iid, status = resolve_assumed_role([role_m], [base_m], at=NOW)
    assert status == "RESOLVED"
    assert iid == INTERNAL_A


def test_assumed_role_falls_back_to_role() -> None:
    role_m = IdentityMapping(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        source_system="aws",
        source_identifier="arn:aws:sts::123:assumed-role/Admin/session",
        internal_identity_id=INTERNAL_B,
        confidence="MEDIUM",
        provenance="sts",
        valid_from=NOW,
        valid_to=None,
    )
    iid, status = resolve_assumed_role([role_m], [], at=NOW)
    assert status == "RESOLVED"
    assert iid == INTERNAL_B


def test_resource_alias_known() -> None:
    assert (
        resolve_resource_alias({"bucket-a": "canonical-bucket"}, "bucket-a") == "canonical-bucket"
    )


def test_resource_alias_unknown_passthrough() -> None:
    assert resolve_resource_alias({}, "bucket-x") == "bucket-x"


def test_resource_alias_none() -> None:
    assert resolve_resource_alias({}, None) is None


pytestmark = pytest.mark.unit
