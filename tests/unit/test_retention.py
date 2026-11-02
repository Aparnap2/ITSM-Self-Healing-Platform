"""Unit tests for retention planning and erasure semantics (privacy slice)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from itsm_agent.privacy.retention import (
    DEFAULT_POLICIES,
    DataClass,
    ErasureRequest,
    ExpiryAction,
    LegalHold,
    RetentionPolicy,
    plan_erasure,
)

pytestmark = pytest.mark.unit

NOW = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)
TENANT = uuid.uuid4()
OTHER_TENANT = uuid.uuid4()


def _request(*classes: DataClass, tenant_id: uuid.UUID = TENANT) -> ErasureRequest:
    return ErasureRequest(
        tenant_id=tenant_id,
        requested_by="privacy.officer",
        reason="data subject erasure request",
        data_classes=classes or (DataClass.RAW_EVIDENCE,),
        requested_at=NOW,
    )


def test_defaults_cover_every_data_class() -> None:
    classes = {p.data_class for p in DEFAULT_POLICIES}
    assert classes == set(DataClass)
    assert all(p.tenant_id is None for p in DEFAULT_POLICIES)


def test_plan_computes_cutoffs_from_policy() -> None:
    plan = plan_erasure(_request(DataClass.RAW_EVIDENCE), now=NOW)
    assert plan.blocked is False
    assert plan.actions[DataClass.RAW_EVIDENCE] == ExpiryAction.ANONYMIZE
    raw_days = next(
        p.retention_days for p in DEFAULT_POLICIES if p.data_class == DataClass.RAW_EVIDENCE
    )
    assert plan.cutoffs[DataClass.RAW_EVIDENCE] == NOW - timedelta(days=raw_days)
    assert plan.may_execute(DataClass.RAW_EVIDENCE) is True


def test_retained_class_is_not_executable() -> None:
    plan = plan_erasure(_request(DataClass.CANONICAL_EVENT, DataClass.FINDING), now=NOW)
    assert plan.actions[DataClass.CANONICAL_EVENT] == ExpiryAction.RETAIN
    assert plan.actions[DataClass.FINDING] == ExpiryAction.RETAIN
    assert plan.may_execute(DataClass.CANONICAL_EVENT) is False
    assert plan.may_execute(DataClass.FINDING) is False


def test_legal_hold_blocks_the_request() -> None:
    hold = LegalHold(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        data_class=None,
        reason="litigation",
        placed_by="legal",
        placed_at=NOW - timedelta(days=1),
    )
    plan = plan_erasure(_request(DataClass.RAW_EVIDENCE), legal_holds=(hold,), now=NOW)
    assert plan.blocked is True
    assert plan.blocked_reason is not None and str(hold.id) in plan.blocked_reason
    assert plan.may_execute(DataClass.RAW_EVIDENCE) is False


def test_released_hold_does_not_block() -> None:
    hold = LegalHold(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        data_class=DataClass.RAW_EVIDENCE,
        reason="closed investigation",
        placed_by="legal",
        placed_at=NOW - timedelta(days=10),
        released_at=NOW - timedelta(days=1),
    )
    plan = plan_erasure(_request(DataClass.RAW_EVIDENCE), legal_holds=(hold,), now=NOW)
    assert plan.blocked is False


def test_hold_on_another_tenant_or_class_does_not_block() -> None:
    other_tenant_hold = LegalHold(
        id=uuid.uuid4(),
        tenant_id=OTHER_TENANT,
        data_class=None,
        reason="litigation",
        placed_by="legal",
        placed_at=NOW,
    )
    other_class_hold = LegalHold(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        data_class=DataClass.FINDING,
        reason="litigation",
        placed_by="legal",
        placed_at=NOW,
    )
    plan = plan_erasure(
        _request(DataClass.RAW_EVIDENCE),
        legal_holds=(other_tenant_hold, other_class_hold),
        now=NOW,
    )
    assert plan.blocked is False


def test_tenant_override_wins_over_default() -> None:
    override = RetentionPolicy(
        tenant_id=TENANT,
        data_class=DataClass.RAW_EVIDENCE,
        retention_days=7,
        on_expiry=ExpiryAction.ANONYMIZE,
    )
    plan = plan_erasure(
        _request(DataClass.RAW_EVIDENCE),
        policies=(*DEFAULT_POLICIES, override),
        now=NOW,
    )
    assert plan.cutoffs[DataClass.RAW_EVIDENCE] == NOW - timedelta(days=7)


def test_missing_policy_fails_closed_to_retain() -> None:
    plan = plan_erasure(_request(DataClass.INVESTIGATION), policies=(), now=NOW)
    assert plan.actions[DataClass.INVESTIGATION] == ExpiryAction.RETAIN
    assert plan.may_execute(DataClass.INVESTIGATION) is False


def test_naive_clock_is_rejected() -> None:
    with pytest.raises(ValueError):
        plan_erasure(_request(), now=datetime(2026, 11, 2, 12, 0))  # noqa: DTZ001


def test_request_requires_at_least_one_data_class() -> None:
    with pytest.raises(ValueError):
        ErasureRequest(
            tenant_id=TENANT,
            requested_by="privacy.officer",
            reason="empty",
            data_classes=(),
        )
