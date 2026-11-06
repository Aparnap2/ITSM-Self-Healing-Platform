"""End-to-end lifecycle tests for the retention/erasure scheduler.

The scheduler is the only automated path that deletes anything, so its
recovery semantics are security-critical:

- every pass covers every registered tenant, not just one;
- a crashed process leaves a PROCESSING lease that the next pass reclaims
  only after expiry (``FOR UPDATE SKIP LOCKED``);
- poison requests are retried with backoff and, once the cap is reached,
  become FAILED (an escalation signal) rather than loops or silent success;
- a legal hold blocks erasure and is recorded as an audit event;
- a successful pass is idempotent — a second pass claims nothing.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from psycopg import AsyncConnection

from itsm_agent.adapters.persistence.repositories import RepositoryBundle
from itsm_agent.privacy.retention import DataClass, ErasureRequest
from itsm_agent.privacy.scheduler import RetentionScheduler

pytestmark = pytest.mark.integration

NOW = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)


async def _seed_tenant(dsn: str, tenant_id: uuid.UUID) -> None:
    async with await AsyncConnection.connect(dsn) as conn:
        await conn.execute(
            "INSERT INTO tenants (id, name) VALUES (%s, %s) ON CONFLICT (id) DO NOTHING",
            (tenant_id, f"test-{tenant_id.hex[:8]}"),
        )


async def _seed_old_source_event(
    dsn: str, tenant_id: uuid.UUID, payload_hash: str = "sha256:abc"
) -> uuid.UUID:
    event_id = uuid.uuid4()
    async with await AsyncConnection.connect(dsn) as conn:
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
                tenant_id,
                f"idem-{uuid.uuid4().hex}",
                NOW - timedelta(days=200),
                NOW - timedelta(days=200),
                payload_hash,
                f"s3://evidence/{event_id}.json.gz",
            ),
        )
    return event_id


async def _record_erase_request(
    repos: RepositoryBundle, tenant_id: uuid.UUID, data_classes: tuple[DataClass, ...]
) -> ErasureRequest:
    request = ErasureRequest(
        tenant_id=tenant_id,
        requested_by="privacy.officer",
        reason="retention expiry",
        data_classes=data_classes,
        requested_at=NOW,
    )
    await repos.retention.record_request(request)
    return request


async def _request_status(dsn: str, request_id: uuid.UUID) -> str:
    async with await AsyncConnection.connect(dsn) as conn:
        row = await (
            await conn.execute("SELECT status FROM erasure_requests WHERE id = %s", (request_id,))
        ).fetchone()
    assert row is not None
    return str(row[0])


async def _audit_types(dsn: str, tenant_id: uuid.UUID) -> list[str]:
    async with await AsyncConnection.connect(dsn) as conn:
        rows = await (
            await conn.execute(
                "SELECT event_type FROM audit_events WHERE tenant_id = %s", (tenant_id,)
            )
        ).fetchall()
    return [str(row[0]) for row in rows]


async def _force_request_state(
    dsn: str,
    request_id: uuid.UUID,
    *,
    status: str,
    lease_until: datetime | None,
    attempt_count: int,
) -> None:
    async with await AsyncConnection.connect(dsn) as conn:
        await conn.execute(
            "UPDATE erasure_requests"
            " SET status = %s, lease_until = %s, attempt_count = %s"
            " WHERE id = %s",
            (status, lease_until, attempt_count, request_id),
        )


async def test_run_once_processes_all_tenants_and_is_idempotent(
    repos: RepositoryBundle, pg_dsn: str
) -> None:
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    for tenant in (tenant_a, tenant_b):
        await _seed_tenant(pg_dsn, tenant)
        await _seed_old_source_event(pg_dsn, tenant)

    await _record_erase_request(repos, tenant_a, (DataClass.RAW_EVIDENCE,))
    await _record_erase_request(repos, tenant_b, (DataClass.RAW_EVIDENCE,))

    scheduler = RetentionScheduler(
        repos=repos,
        clock=lambda: NOW,
        batch_size=10,
        lease_seconds=60.0,
        max_attempts=3,
        backoff_seconds=0.0,
    )
    first = await scheduler.run_once()

    assert first.claimed == 2
    assert first.completed == 2
    assert first.failed == 0
    assert set(first.tenants) == {tenant_a, tenant_b}

    for tenant in (tenant_a, tenant_b):
        assert (
            await _request_status(pg_dsn, (await _single_request_id(pg_dsn, tenant))) == "COMPLETED"
        )
        assert "RETENTION_ERASURE_COMPLETED" in await _audit_types(pg_dsn, tenant)

    second = await scheduler.run_once()
    assert second.claimed == 0
    assert second.completed == 0


async def _single_request_id(dsn: str, tenant_id: uuid.UUID) -> uuid.UUID:
    async with await AsyncConnection.connect(dsn) as conn:
        row = await (
            await conn.execute("SELECT id FROM erasure_requests WHERE tenant_id = %s", (tenant_id,))
        ).fetchone()
    assert row is not None
    return uuid.UUID(str(row[0]))


async def test_legal_hold_blocks_request_and_emits_audit(
    repos: RepositoryBundle, pg_dsn: str
) -> None:
    tenant = uuid.uuid4()
    await _seed_tenant(pg_dsn, tenant)
    await _seed_old_source_event(pg_dsn, tenant)
    async with await AsyncConnection.connect(pg_dsn) as conn:
        await conn.execute(
            """
            INSERT INTO legal_holds (
                id, tenant_id, data_class, reason, placed_by, placed_at
            ) VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                uuid.uuid4(),
                tenant,
                DataClass.RAW_EVIDENCE.value,
                "regulatory investigation",
                "legal",
                NOW - timedelta(days=2),
            ),
        )

    request = await _record_erase_request(repos, tenant, (DataClass.RAW_EVIDENCE,))

    scheduler = RetentionScheduler(
        repos=repos, clock=lambda: NOW, lease_seconds=60.0, max_attempts=3
    )
    result = await scheduler.run_once()

    assert result.blocked == 1
    assert result.completed == 0
    assert await _request_status(pg_dsn, request.id) == "BLOCKED"
    assert "RETENTION_ERASURE_BLOCKED" in await _audit_types(pg_dsn, tenant)

    async with await AsyncConnection.connect(pg_dsn) as conn:
        rows = await (
            await conn.execute(
                "SELECT count(*) FROM erasure_tombstones WHERE tenant_id = %s", (tenant,)
            )
        ).fetchone()
    assert rows == (0,)


async def test_poison_request_exhausts_attempts_and_becomes_failed(
    repos: RepositoryBundle, pg_dsn: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = uuid.uuid4()
    await _seed_tenant(pg_dsn, tenant)
    await _seed_old_source_event(pg_dsn, tenant)
    request = await _record_erase_request(repos, tenant, (DataClass.RAW_EVIDENCE,))

    async def boom(self: object, *args: object, **kwargs: object) -> None:
        raise RuntimeError("injected execution failure")

    monkeypatch.setattr(RetentionScheduler, "_execute_request", boom)

    scheduler = RetentionScheduler(
        repos=repos,
        clock=lambda: NOW,
        lease_seconds=60.0,
        max_attempts=1,
        backoff_seconds=0.0,
    )
    result = await scheduler.run_once()

    assert result.claimed == 1
    assert result.failed == 1
    assert await _request_status(pg_dsn, request.id) == "FAILED"
    assert "RETENTION_ERASURE_FAILED" in await _audit_types(pg_dsn, tenant)


async def test_expired_lease_from_crashed_process_is_reclaimed(
    repos: RepositoryBundle, pg_dsn: str
) -> None:
    tenant = uuid.uuid4()
    await _seed_tenant(pg_dsn, tenant)
    await _seed_old_source_event(pg_dsn, tenant)
    request = await _record_erase_request(repos, tenant, (DataClass.RAW_EVIDENCE,))

    # Simulate a crashed scheduler holding an expired lease.
    await _force_request_state(
        pg_dsn,
        request.id,
        status="PROCESSING",
        lease_until=datetime.now(UTC) - timedelta(seconds=5),
        attempt_count=1,
    )

    scheduler = RetentionScheduler(
        repos=repos, clock=lambda: NOW, lease_seconds=60.0, max_attempts=3
    )
    result = await scheduler.run_once()

    assert result.claimed == 1
    assert result.completed == 1
    assert await _request_status(pg_dsn, request.id) == "COMPLETED"


async def test_active_lease_is_not_reclaimed(repos: RepositoryBundle, pg_dsn: str) -> None:
    tenant = uuid.uuid4()
    await _seed_tenant(pg_dsn, tenant)
    await _seed_old_source_event(pg_dsn, tenant)
    request = await _record_erase_request(repos, tenant, (DataClass.RAW_EVIDENCE,))

    # Simulate a healthy in-progress scheduler holding an active lease.
    await _force_request_state(
        pg_dsn,
        request.id,
        status="PROCESSING",
        lease_until=datetime.now(UTC) + timedelta(hours=1),
        attempt_count=1,
    )

    scheduler = RetentionScheduler(
        repos=repos, clock=lambda: NOW, lease_seconds=60.0, max_attempts=3
    )
    result = await scheduler.run_once()

    assert result.claimed == 0
    assert await _request_status(pg_dsn, request.id) == "PROCESSING"
