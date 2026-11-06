"""Retention, legal hold, and erasure semantics (privacy slice).

This module is deliberately split in two:

- **Pure planning** (``plan_erasure``): decides, per data class, whether a
  record may be anonymized, has a deletable derived projection, or must be
  retained. It never touches a database, so it is deterministic and testable
  offline.
- **Execution** (``PsycopgRetentionRepository`` in the persistence adapter):
  records the request, writes tombstones, and deletes only derived,
  rebuildable projections.

Rules that this module encodes:

- Immutable canonical evidence (``source_events``) is never updated or deleted.
  Erasing its raw payload records a *tombstone* that preserves the integrity
  hash, so the record stays verifiable while the payload is acknowledged gone.
- Derived projections (``access_facts``) may be deleted and rebuilt.
- Findings and reviewer decisions are retained as audit records; retention may
  later anonymize free text, but there is no cascading delete of audit history.
- An active legal hold blocks erasure of the held data class, and the request
  is marked ``BLOCKED`` rather than silently ignored.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class DataClass(StrEnum):
    RAW_EVIDENCE = "RAW_EVIDENCE"
    CANONICAL_EVENT = "CANONICAL_EVENT"
    DERIVED_PROJECTION = "DERIVED_PROJECTION"
    FINDING = "FINDING"
    INVESTIGATION = "INVESTIGATION"
    REVIEW_DECISION = "REVIEW_DECISION"
    OPERATIONAL_LOG = "OPERATIONAL_LOG"


class ExpiryAction(StrEnum):
    ANONYMIZE = "ANONYMIZE"
    DELETE_DERIVED = "DELETE_DERIVED"
    RETAIN = "RETAIN"


class RetentionPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    data_class: DataClass
    retention_days: int = Field(gt=0)
    on_expiry: ExpiryAction
    tenant_id: UUID | None = None


# Conservative platform defaults; a tenant may override per data class.
DEFAULT_POLICIES: tuple[RetentionPolicy, ...] = (
    # Raw payloads are the most sensitive and the least useful over time.
    RetentionPolicy(
        data_class=DataClass.RAW_EVIDENCE, retention_days=90, on_expiry=ExpiryAction.ANONYMIZE
    ),
    # Canonical events are the audit spine; kept for the long retention window.
    RetentionPolicy(
        data_class=DataClass.CANONICAL_EVENT, retention_days=2555, on_expiry=ExpiryAction.RETAIN
    ),
    RetentionPolicy(
        data_class=DataClass.DERIVED_PROJECTION,
        retention_days=90,
        on_expiry=ExpiryAction.DELETE_DERIVED,
    ),
    RetentionPolicy(
        data_class=DataClass.FINDING, retention_days=2555, on_expiry=ExpiryAction.RETAIN
    ),
    RetentionPolicy(
        data_class=DataClass.INVESTIGATION, retention_days=365, on_expiry=ExpiryAction.RETAIN
    ),
    RetentionPolicy(
        data_class=DataClass.REVIEW_DECISION, retention_days=2555, on_expiry=ExpiryAction.RETAIN
    ),
    RetentionPolicy(
        data_class=DataClass.OPERATIONAL_LOG,
        retention_days=30,
        on_expiry=ExpiryAction.DELETE_DERIVED,
    ),
)


class ErasureRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    requested_by: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=1000)
    data_classes: tuple[DataClass, ...] = Field(min_length=1)
    status: str = "REQUESTED"
    requested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None


class LegalHold(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    tenant_id: UUID
    data_class: DataClass | None = None  # None = all classes
    reason: str
    placed_by: str
    placed_at: datetime
    released_at: datetime | None = None

    def is_active(self) -> bool:
        return self.released_at is None

    def covers(self, data_class: DataClass) -> bool:
        return self.is_active() and (self.data_class is None or self.data_class == data_class)


class ErasurePlan(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    tenant_id: UUID
    request_id: UUID
    blocked: bool = False
    blocked_reason: str | None = None
    # data class -> expiry cutoff (records strictly older than this are in scope)
    cutoffs: dict[DataClass, datetime] = Field(default_factory=dict)
    actions: dict[DataClass, ExpiryAction] = Field(default_factory=dict)

    def may_execute(self, data_class: DataClass) -> bool:
        if self.blocked:
            return False
        return self.actions.get(data_class) in {
            ExpiryAction.ANONYMIZE,
            ExpiryAction.DELETE_DERIVED,
        }


def _policy_for(
    data_class: DataClass, policies: tuple[RetentionPolicy, ...], tenant_id: UUID
) -> RetentionPolicy:
    tenant_override = next(
        (p for p in policies if p.tenant_id == tenant_id and p.data_class == data_class),
        None,
    )
    if tenant_override is not None:
        return tenant_override
    default = next(
        (p for p in policies if p.tenant_id is None and p.data_class == data_class), None
    )
    if default is None:
        # Unknown policy is fail-closed: retain.
        return RetentionPolicy(
            data_class=data_class, retention_days=1, on_expiry=ExpiryAction.RETAIN
        )
    return default


def plan_erasure(
    request: ErasureRequest,
    *,
    policies: tuple[RetentionPolicy, ...] = DEFAULT_POLICIES,
    legal_holds: tuple[LegalHold, ...] = (),
    now: datetime | None = None,
) -> ErasurePlan:
    """Compute the erasure plan for a request. Pure and deterministic."""
    moment = now or datetime.now(UTC)
    if moment.tzinfo is None:
        raise ValueError("now must be timezone-aware")

    held = [hold for hold in legal_holds if hold.tenant_id == request.tenant_id]
    for data_class in request.data_classes:
        for hold in held:
            if hold.covers(data_class):
                return ErasurePlan(
                    tenant_id=request.tenant_id,
                    request_id=request.id,
                    blocked=True,
                    blocked_reason=f"legal hold {hold.id} covers {data_class.value}",
                )

    cutoffs: dict[DataClass, datetime] = {}
    actions: dict[DataClass, ExpiryAction] = {}
    for data_class in request.data_classes:
        policy = _policy_for(data_class, policies, request.tenant_id)
        actions[data_class] = policy.on_expiry
        cutoffs[data_class] = moment - timedelta(days=policy.retention_days)

    return ErasurePlan(
        tenant_id=request.tenant_id,
        request_id=request.id,
        cutoffs=cutoffs,
        actions=actions,
    )


class ErasureTombstone(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    tenant_id: UUID
    data_class: DataClass
    record_id: UUID | None = None
    integrity_hash: str
    detail: str | None = None
    erase_request_id: UUID
    erased_at: datetime


__all__ = [
    "DEFAULT_POLICIES",
    "DataClass",
    "ErasurePlan",
    "ErasureRequest",
    "ErasureTombstone",
    "ExpiryAction",
    "LegalHold",
    "RetentionPolicy",
    "plan_erasure",
]
