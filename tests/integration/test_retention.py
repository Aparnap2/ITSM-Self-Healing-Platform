"""Integration: retention, legal hold and erasure against real PostgreSQL.

Guarantees exercised here:
- a request is tenant-scoped and recorded durably;
- erasing raw evidence writes tombstones preserving the integrity hash and
  leaves the append-only canonical event untouched;
- only derived projections are deleted;
- a second run is idempotent;
- a legal hold blocks execution rather than silently skipping it;
- another tenant's tombstones are never visible.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from psycopg import errors

from itsm_agent.adapters.persistence.repositories import RepositoryBundle
from itsm_agent.privacy.retention import (
    DataClass,
    ErasureRequest,
    LegalHold,
    plan_erasure,
)

pytestmark = pytest.mark.integration

NOW = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)


async def _seed_source_event(
    repos: RepositoryBundle,
    tenant: uuid.UUID,
    *,
    observed_at: datetime,
    raw_reference: str | None,
    payload_hash: str,
) -> uuid.UUID:
    event_id = uuid.uuid4()
    async with repos.findings._pool.connection() as conn:  # noqa: SLF001 - test seeding
        await conn.execute(
            """
            INSERT INTO source_events (
                id, tenant_id, source, idempotency_key, canonical_schema_version,
                event_type, event_category, event_time, observed_at, action,
                payload_hash, raw_evidence_reference
            ) VALUES (%s, %s, 'cloudtrail', %s, '1.0', 'AwsApiCall', 'access',
                      %s, %s, 'sts:AssumeRole', %s, %s)
            """,
            (
                event_id,
                tenant,
                f"idem-{uuid.uuid4().hex}",
                observed_at,
                observed_at,
                payload_hash,
                raw_reference,
            ),
        )
    return event_id


async def _seed_access_fact(
    repos: RepositoryBundle, tenant: uuid.UUID, observed_at: datetime
) -> uuid.UUID:
    fact_id = uuid.uuid4()
    async with repos.findings._pool.connection() as conn:  # noqa: SLF001 - test seeding
        await conn.execute(
            """
            INSERT INTO access_facts (
                id, tenant_id, source_event_id, action, observed_at, fact_hash
            ) VALUES (%s, %s, %s, 'sts:AssumeRole', %s, %s)
            """,
            (fact_id, tenant, uuid.uuid4(), observed_at, f"hash-{uuid.uuid4().hex}"),
        )
    return fact_id


async def test_erasure_tombstones_raw_evidence_without_touching_the_event(
    repos: RepositoryBundle,
) -> None:
    tenant = uuid.uuid4()
    old = await _seed_source_event(
        repos,
        tenant,
        observed_at=NOW - timedelta(days=200),
        raw_reference="s3://evidence/old.json.gz",
        payload_hash="sha256:abc123",
    )
    fresh = await _seed_source_event(
        repos,
        tenant,
        observed_at=NOW - timedelta(days=1),
        raw_reference="s3://evidence/fresh.json.gz",
        payload_hash="sha256:def456",
    )
    request = ErasureRequest(
        tenant_id=tenant,
        requested_by="privacy.officer",
        reason="retention expiry",
        data_classes=(DataClass.RAW_EVIDENCE,),
        requested_at=NOW,
    )
    await repos.retention.record_request(request)
    plan = plan_erasure(request, now=NOW)
    assert plan.blocked is False

    inserted = await repos.retention.tombstone_raw_evidence(
        tenant,
        older_than=plan.cutoffs[DataClass.RAW_EVIDENCE],
        erase_request_id=request.id,
    )
    assert inserted == 1

    tombstones = await repos.retention.list_tombstones(tenant, erase_request_id=request.id)
    assert [t.record_id for t in tombstones] == [old]
    assert tombstones[0].integrity_hash == "sha256:abc123"
    assert tombstones[0].detail is not None

    # The canonical event is still present (append-only, retained).
    async with repos.findings._pool.connection() as conn:  # noqa: SLF001
        rows = await (
            await conn.execute(
                "SELECT id FROM source_events WHERE tenant_id = %s ORDER BY id", (tenant,)
            )
        ).fetchall()
    assert {row[0] for row in rows} == {old, fresh}
    assert fresh not in {t.record_id for t in tombstones}

    # Idempotent: re-running the same request inserts nothing.
    again = await repos.retention.tombstone_raw_evidence(
        tenant,
        older_than=plan.cutoffs[DataClass.RAW_EVIDENCE],
        erase_request_id=request.id,
    )
    assert again == 0

    await repos.retention.complete_request(tenant, request.id, status="COMPLETED")


async def test_append_only_trigger_still_rejects_updates(repos: RepositoryBundle) -> None:
    tenant = uuid.uuid4()
    event_id = await _seed_source_event(
        repos,
        tenant,
        observed_at=NOW - timedelta(days=10),
        raw_reference="s3://evidence/x.json",
        payload_hash="sha256:xyz",
    )
    async with repos.findings._pool.connection() as conn:  # noqa: SLF001
        with pytest.raises(errors.RaiseException):
            await conn.execute(
                "UPDATE source_events SET raw_evidence_reference = NULL WHERE id = %s",
                (event_id,),
            )


async def test_derived_projections_are_deletable(repos: RepositoryBundle) -> None:
    tenant = uuid.uuid4()
    old_fact = await _seed_access_fact(repos, tenant, NOW - timedelta(days=200))
    fresh_fact = await _seed_access_fact(repos, tenant, NOW - timedelta(days=1))
    request = ErasureRequest(
        tenant_id=tenant,
        requested_by="privacy.officer",
        reason="retention expiry",
        data_classes=(DataClass.DERIVED_PROJECTION,),
        requested_at=NOW,
    )
    await repos.retention.record_request(request)
    plan = plan_erasure(request, now=NOW)

    deleted = await repos.retention.delete_derived_facts(
        tenant, older_than=plan.cutoffs[DataClass.DERIVED_PROJECTION]
    )
    assert deleted == 1
    async with repos.findings._pool.connection() as conn:  # noqa: SLF001
        remaining = await (
            await conn.execute("SELECT id FROM access_facts WHERE tenant_id = %s", (tenant,))
        ).fetchall()
    assert {row[0] for row in remaining} == {fresh_fact}
    assert old_fact not in {row[0] for row in remaining}


async def test_legal_hold_blocks_execution(repos: RepositoryBundle) -> None:
    tenant = uuid.uuid4()
    hold = LegalHold(
        id=uuid.uuid4(),
        tenant_id=tenant,
        data_class=DataClass.RAW_EVIDENCE,
        reason="regulatory investigation",
        placed_by="legal",
        placed_at=NOW - timedelta(days=2),
    )
    async with repos.findings._pool.connection() as conn:  # noqa: SLF001
        await conn.execute(
            """
            INSERT INTO legal_holds (id, tenant_id, data_class, reason, placed_by, placed_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                hold.id,
                tenant,
                DataClass.RAW_EVIDENCE.value,
                hold.reason,
                hold.placed_by,
                hold.placed_at,
            ),
        )
    active = await repos.retention.active_holds(tenant)
    assert [h.id for h in active] == [hold.id]

    request = ErasureRequest(
        tenant_id=tenant,
        requested_by="privacy.officer",
        reason="erasure request",
        data_classes=(DataClass.RAW_EVIDENCE,),
        requested_at=NOW,
    )
    await repos.retention.record_request(request)
    plan = plan_erasure(request, legal_holds=tuple(active), now=NOW)
    assert plan.blocked is True
    await repos.retention.complete_request(tenant, request.id, status="BLOCKED")

    async with repos.findings._pool.connection() as conn:  # noqa: SLF001
        row = await (
            await conn.execute("SELECT status FROM erasure_requests WHERE id = %s", (request.id,))
        ).fetchone()
    assert row is not None
    assert row[0] == "BLOCKED"


async def test_tombstones_are_tenant_isolated(repos: RepositoryBundle) -> None:
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    await _seed_source_event(
        repos,
        tenant_a,
        observed_at=NOW - timedelta(days=200),
        raw_reference="s3://evidence/a.json",
        payload_hash="sha256:aaa",
    )
    request = ErasureRequest(
        tenant_id=tenant_a,
        requested_by="privacy.officer",
        reason="retention expiry",
        data_classes=(DataClass.RAW_EVIDENCE,),
        requested_at=NOW,
    )
    await repos.retention.record_request(request)
    await repos.retention.tombstone_raw_evidence(
        tenant_a,
        older_than=NOW - timedelta(days=90),
        erase_request_id=request.id,
    )

    assert len(await repos.retention.list_tombstones(tenant_a)) == 1
    assert await repos.retention.list_tombstones(tenant_b) == []


async def test_default_policies_are_returned_when_table_is_empty(
    repos: RepositoryBundle,
) -> None:
    policies = await repos.retention.effective_policies(uuid.uuid4())
    assert {p.data_class for p in policies} == set(DataClass)
    assert all(p.tenant_id is None for p in policies)
