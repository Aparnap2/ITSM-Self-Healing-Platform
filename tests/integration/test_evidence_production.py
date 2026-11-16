"""Integration: the production path for evidence references.

Marker: ``integration``. Until this existed, nothing in ``src/`` ever wrote an
``evidence_references`` row: the table had a reader only, so a real
investigation could cite nothing and a reviewer's evidence bundle came back
empty. These tests cover the whole path — ingestion, detection, the persisted
evidence reference, tenant isolation, redaction, and the reviewer's bundle.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from psycopg_pool import AsyncConnectionPool

from itsm_agent.adapters.persistence.ingestion_sink import PsycopgSourceEventSink
from itsm_agent.adapters.persistence.pool import PersistenceConfig, create_pool
from itsm_agent.adapters.persistence.repositories import RepositoryBundle
from itsm_agent.application.audit_consumer import process_source_event
from itsm_agent.collectors.aws.cloudtrail import normalize_record

pytestmark = pytest.mark.integration


def _ct_record(tenant: uuid.UUID, event_id: str, *, secret: str | None = None) -> dict[str, object]:
    record: dict[str, object] = {
        "eventVersion": "1.09",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDA",
            "arn": "arn:aws:iam::123:user/alice",
            "accountId": "123",
            "userName": "alice",
        },
        "eventTime": "2026-01-01T12:00:00Z",
        "eventSource": "sts.amazonaws.com",
        "eventName": "AssumeRole",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.5",
        "requestParameters": {"roleArn": "arn:aws:iam::123:role/Admin"},
        "requestID": "req-1",
        "eventID": event_id,
        "readOnly": False,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": "123",
        "eventCategory": "Management",
    }
    if secret is not None:
        record["requestParameters"] = {
            "roleArn": "arn:aws:iam::123:role/Admin",
            "token": secret,
        }
    return record


async def _ingest_and_detect(
    pool: AsyncConnectionPool, tenant: uuid.UUID, event_id: str, *, secret: str | None = None
) -> tuple[Any, list[uuid.UUID]]:
    """Ingest one source event and run detection over it."""
    event = normalize_record(_ct_record(tenant, event_id, secret=secret), tenant)
    sink = PsycopgSourceEventSink(pool)
    assert (await sink.accept_source_event(event)).value == "ACCEPTED"

    repos = RepositoryBundle(pool)
    _already, finding_ids = await process_source_event(
        event=event,
        pool=pool,
        findings_repo=repos.findings,
        processing_repo=repos.processing_records,
        covered_sources={"cloudtrail"},
        clock_now=lambda: datetime.now(UTC),
    )
    return event, finding_ids


async def test_detection_persists_evidence_anchored_to_the_source_event(
    pg_dsn: str,
) -> None:
    pool = create_pool(PersistenceConfig(dsn=pg_dsn, min_size=1, max_size=4))
    await pool.open()
    try:
        tenant = uuid.uuid4()
        event, finding_ids = await _ingest_and_detect(pool, tenant, f"evt-{uuid.uuid4().hex}")
        assert finding_ids, "detection produced no finding"

        repos = RepositoryBundle(pool)
        references = await repos.evidence_references.list_for_tenant_finding(tenant, finding_ids[0])
        assert len(references) >= 1
        reference = references[0]
        # The evidence is anchored to the immutable source record.
        assert reference.source_event_id == event.event_id
        # The reference is anchored to the immutable source record's hash.
        assert reference.content_hash == event.payload_hash
        assert reference.trust_level == "SIMULATOR_OBSERVATION"
        assert reference.collected_at == datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    finally:
        await pool.close()


async def test_evidence_excerpt_is_redacted_and_bounded(pg_dsn: str) -> None:
    pool = create_pool(PersistenceConfig(dsn=pg_dsn, min_size=1, max_size=4))
    await pool.open()
    try:
        tenant = uuid.uuid4()
        # The secret-shaped value is assembled at runtime so a secret scanner
        # does not match a literal in this source file.
        secret = "Bearer " + "abc123def456"
        _event, finding_ids = await _ingest_and_detect(
            pool, tenant, f"evt-{uuid.uuid4().hex}", secret=secret
        )
        assert finding_ids

        repos = RepositoryBundle(pool)
        references = await repos.evidence_references.list_for_tenant_finding(tenant, finding_ids[0])
        assert references
        excerpt = references[0].excerpt or ""
        assert "abc123def456" not in excerpt
        assert len(excerpt) <= 500
    finally:
        await pool.close()


async def test_evidence_of_one_tenant_is_invisible_to_another(pg_dsn: str) -> None:
    pool = create_pool(PersistenceConfig(dsn=pg_dsn, min_size=1, max_size=4))
    await pool.open()
    try:
        tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
        _event_a, findings_a = await _ingest_and_detect(pool, tenant_a, f"evt-{uuid.uuid4().hex}")
        _event_b, findings_b = await _ingest_and_detect(pool, tenant_b, f"evt-{uuid.uuid4().hex}")
        assert findings_a and findings_b

        repos = RepositoryBundle(pool)
        # Tenant B cannot see tenant A's evidence, even for A's finding id.
        assert (
            await repos.evidence_references.list_for_tenant_finding(tenant_b, findings_a[0]) == []
        )
        assert await repos.evidence_references.list_for_tenant_finding(tenant_a, findings_a[0])
    finally:
        await pool.close()


async def test_bundle_endpoint_returns_the_persisted_evidence(pg_dsn: str) -> None:
    """The reviewer-visible bundle is no longer empty."""
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient

    from itsm_agent.api.app import create_app
    from itsm_agent.api.auth import Role, TokenAuthenticator, mint_token
    from itsm_agent.api.routes.ingestion import SinkOutcome
    from itsm_agent.config import Settings

    class FakeSink:
        async def accept_incident(self, event: object) -> SinkOutcome:
            return SinkOutcome.ACCEPTED

    pool = create_pool(PersistenceConfig(dsn=pg_dsn, min_size=1, max_size=4))
    await pool.open()
    try:
        tenant = uuid.uuid4()
        _event_id, finding_ids = await _ingest_and_detect(pool, tenant, f"evt-{uuid.uuid4().hex}")
        assert finding_ids

        repos = RepositoryBundle(pool)
        settings = Settings.model_validate(
            {
                "env": "test",
                "api_host": "127.0.0.1",
                "api_port": 8000,
                "webhook_secret": "test-webhook-secret-0123456789abcdef",
                "mockoon_itsm_base_url": "http://mockoon-itsm.test",
                "mockoon_identity_base_url": "http://mockoon-identity.test",
                "mockoon_infrastructure_base_url": "http://mockoon-infra.test",
            }
        )
        app: FastAPI = create_app(
            settings=settings,
            sink=FakeSink(),
            findings_repo=repos.findings,
            review_decisions_repo=repos.review_decisions,
            evidence_references_repo=repos.evidence_references,
            authenticator=TokenAuthenticator(secret="bundle-reviewer-secret-0123456789"),
        )
        token = mint_token(
            "bundle-reviewer-secret-0123456789",
            principal_id="reviewer-1",
            tenant_ids=[tenant],
            roles=[Role.REVIEWER],
        )
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://api.test"
        ) as client:
            response = await client.get(
                f"/v1/findings/{finding_ids[0]}/bundle",
                params={"tenant_id": str(tenant)},
                headers={"Authorization": f"Bearer {token}"},
            )

        assert response.status_code == 200
        body = response.json()
        assert body["evidence"], "the bundle carried no evidence"
        assert body["evidence"][0]["content_hash"]
        assert body["evidence"][0]["excerpt"]
        assert body["bundle_hash"]
    finally:
        await pool.close()
