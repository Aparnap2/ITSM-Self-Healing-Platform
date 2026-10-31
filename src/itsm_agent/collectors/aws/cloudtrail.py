"""AWS CloudTrail collector (Task 8).

Read-only adapter: fetches CloudTrail records (via an injected fetcher for
testability; production uses boto3 S3/SQS or the CloudTrail LookupEvents API),
normalizes them into canonical SourceEvents, persists checkpoints. No mutations.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID, uuid4

from itsm_agent.domain.events import SourceEvent
from itsm_agent.ports.collectors import CollectorPort
from itsm_agent.ports.repositories import SourceCheckpointRepository

FetchRecords = Callable[[datetime], Awaitable[list[dict[str, Any]]]]


class _CheckpointRepo(Protocol):
    async def get(self, tenant_id: UUID, source: str) -> Any: ...
    async def upsert(
        self, tenant_id: UUID, source: str, checkpoint_token: str, last_event_time: Any = None
    ) -> None: ...


def _parse_dt(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    s = str(value)
    # CloudTrail eventTime is ISO-8601
    s = s.replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _idempotency_key(tenant_id: UUID, record: dict[str, Any]) -> str:
    event_id = record.get("eventID")
    if event_id:
        return f"{tenant_id}:cloudtrail:{event_id}"
    # fallback: (eventTime, eventName, requestID)
    event_time = record.get("eventTime", "")
    event_name = record.get("eventName", "")
    request_id = record.get("requestID", "")
    return f"{tenant_id}:cloudtrail:fallback:{event_time}:{event_name}:{request_id}"


def _category(event_name: str, event_source: str) -> str:
    name = event_name.lower()
    if "assumerole" in name or "assume" in name:
        return "auth"
    if (
        "create" in name
        or "delete" in name
        or "put" in name
        or "attach" in name
        or "detach" in name
    ):
        return "config"
    if "get" in name or "list" in name or "describe" in name:
        return "access"
    return "data"


def normalize_record(record: dict[str, Any], tenant_id: UUID) -> SourceEvent:
    """Pure normalization: CloudTrail record -> canonical SourceEvent."""
    event_time = _parse_dt(record.get("eventTime"))
    observed_at = datetime.now(tz=UTC)
    event_name = str(record.get("eventName", "Unknown"))
    event_source = str(record.get("eventSource", ""))
    action = f"{event_source}:{event_name}" if event_source else event_name

    user_identity = record.get("userIdentity") or {}
    actor_id = (
        user_identity.get("arn")
        or user_identity.get("userName")
        or user_identity.get("principalId")
    )
    principal_id = user_identity.get("principalId") or user_identity.get("arn")
    session_id = (
        user_identity.get("sessionContext", {}).get("sessionIssuer", {}).get("arn")
        if isinstance(user_identity.get("sessionContext"), dict)
        else None
    )
    # request parameters may contain resource identifiers
    request_params = record.get("requestParameters") or {}
    resource_type = None
    resource_id = None
    if isinstance(request_params, dict):
        for k in ("roleArn", "resource", "bucketName", "tableName"):
            if k in request_params:
                resource_id = str(request_params[k])
                resource_type = k
                break

    outcome = "success"
    error_code = record.get("errorCode")
    if error_code:
        outcome = "failure"

    source_ip = record.get("sourceIPAddress")
    correlation_metadata: dict[str, object] = {}
    if source_ip:
        correlation_metadata["source_ip"] = source_ip
    if record.get("userAgent"):
        correlation_metadata["user_agent"] = record.get("userAgent")
    if record.get("awsRegion"):
        correlation_metadata["aws_region"] = record.get("awsRegion")

    # payload hash over redacted record (no secrets in record by default)
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    payload_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    idem = _idempotency_key(tenant_id, record)

    return SourceEvent(
        event_id=uuid4(),
        tenant_id=tenant_id,
        source="cloudtrail",
        source_event_id=record.get("eventID"),
        idempotency_key=idem,
        source_schema_version=record.get("apiVersion") or None,
        canonical_schema_version="1.0",
        event_type=event_name,
        event_category=_category(event_name, event_source),
        event_time=event_time,
        observed_at=observed_at,
        actor_id=actor_id,
        principal_id=principal_id,
        session_id=session_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        permission_context={},
        payload_hash=payload_hash,
        raw_evidence_reference=record.get("eventID"),
        correlation_metadata=correlation_metadata,
    )


class CloudTrailCollector(CollectorPort):
    """Read-only CloudTrail collector."""

    SOURCE = "cloudtrail"

    def __init__(
        self,
        tenant_id: UUID,
        fetch_records: FetchRecords,
        checkpoint_repo: SourceCheckpointRepository | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self._fetch = fetch_records
        self._checkpoint_repo = checkpoint_repo

    async def collect(self, since: datetime) -> list[SourceEvent]:
        records = await self._fetch(since)
        events: list[SourceEvent] = []
        latest: datetime | None = None
        for rec in records:
            try:
                ev = normalize_record(rec, self.tenant_id)
            except Exception:
                # Malformed source records are skipped, not retried.
                continue  # nosec B112
            events.append(ev)
            if latest is None or ev.event_time > latest:
                latest = ev.event_time
        if self._checkpoint_repo is not None and latest is not None:
            await self._checkpoint_repo.upsert(
                self.tenant_id, self.SOURCE, f"cloudtrail:{latest.isoformat()}", latest
            )
        return events
