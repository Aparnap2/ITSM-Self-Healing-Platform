"""Unit tests for identity resolution (no I/O)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from itsm_agent.domain.identity_resolution import resolve_identity
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
