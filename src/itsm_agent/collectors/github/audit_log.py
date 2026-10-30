"""GitHub organization audit log collector (Task 10).

Read-only adapter: paginated fetch (via injected fetcher), normalization,
rate-limit handling, checkpointing. No mutations.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import httpx

from itsm_agent.domain.events import SourceEvent
from itsm_agent.ports.collectors import CollectorPort
from itsm_agent.ports.repositories import SourceCheckpointRepository


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, (int, float)):
        # GitHub @timestamp is epoch millis
        return datetime.fromtimestamp(value / 1000.0, tz=UTC)
    s = str(value).replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _idempotency_key(tenant_id: UUID, rec: dict[str, Any]) -> str:
    doc_id = rec.get("_document_id") or rec.get("id")
    if doc_id:
        return f"{tenant_id}:github:{doc_id}"
    # fallback
    ts = rec.get("@timestamp")
    act = rec.get("action")
    actor = rec.get("actor")
    return f"{tenant_id}:github:fallback:{ts}:{act}:{actor}"


def normalize_record(record: dict[str, Any], tenant_id: UUID) -> SourceEvent:
    action = str(record.get("action", "unknown"))
    actor = record.get("actor") or record.get("user")
    actor_id = str(actor) if actor is not None else None
    target = record.get("user") or record.get("repo") or record.get("team")
    resource_id = str(target) if target is not None else None
    resource_type = (
        "repo"
        if record.get("repo")
        else ("user" if record.get("user") else ("team" if record.get("team") else None))
    )
    ts = _parse_ts(record.get("@timestamp") or record.get("created_at"))
    payload_hash = hashlib.sha256(
        json.dumps(record, sort_keys=True, default=str).encode()
    ).hexdigest()
    return SourceEvent(
        event_id=uuid4(),
        tenant_id=tenant_id,
        source="github",
        source_event_id=str(record.get("_document_id") or record.get("id") or ""),
        idempotency_key=_idempotency_key(tenant_id, record),
        source_schema_version=None,
        canonical_schema_version="1.0",
        event_type=action,
        event_category="access" if "permission" in action or "access" in action else "config",
        event_time=ts,
        observed_at=datetime.now(tz=UTC),
        actor_id=actor_id,
        principal_id=actor_id,
        session_id=None,
        action=f"github:{action}",
        resource_type=resource_type,
        resource_id=resource_id,
        outcome="success",
        permission_context={},
        payload_hash=payload_hash,
        raw_evidence_reference=str(record.get("_document_id") or record.get("id") or ""),
        correlation_metadata={"org": record.get("org"), "repo": record.get("repo")},
    )


class GitHubAuditCollector(CollectorPort):
    SOURCE = "github"

    def __init__(
        self,
        tenant_id: UUID,
        fetch_records: Any,
        checkpoint_repo: SourceCheckpointRepository | None = None,
        org: str = "org",
        token: str | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self._fetch = fetch_records
        self._checkpoint_repo = checkpoint_repo
        self.org = org
        self.token = token

    async def collect(self, since: datetime) -> list[SourceEvent]:
        records = await self._fetch(since)
        events: list[SourceEvent] = []
        latest = None
        for rec in records:
            try:
                ev = normalize_record(rec, self.tenant_id)
            except Exception:
                continue
            events.append(ev)
            if latest is None or ev.event_time > latest:
                latest = ev.event_time
        if self._checkpoint_repo is not None and latest is not None:
            await self._checkpoint_repo.upsert(
                self.tenant_id, self.SOURCE, f"github:{latest.isoformat()}", latest
            )
        return events


async def fetch_github_audit_log(
    org: str,
    token: str,
    since: datetime,
    client: httpx.AsyncClient | None = None,
) -> list[dict[str, Any]]:
    """Real GitHub org audit log fetcher (paginated, rate-limit aware)."""
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    owns_client = client is None
    if owns_client:
        client = httpx.AsyncClient(timeout=30.0)
    assert client is not None
    records: list[dict[str, Any]] = []
    url: str | None = f"https://api.github.com/orgs/{org}/audit-log"
    params: dict[str, Any] = {
        "include": "all",
        "per_page": 100,
        "phrase": f"created:>={since.isoformat()}",
    }
    try:
        while url:
            resp = await client.get(url, headers=headers, params=params)
            if resp.status_code == 429:
                # rate limited; stop and return partial (caller retries)
                break
            resp.raise_for_status()
            batch = resp.json()
            if not isinstance(batch, list) or not batch:
                break
            records.extend(batch)
            # pagination via Link header
            link = resp.headers.get("Link", "")
            next_url: str | None = None
            for part in link.split(","):
                if 'rel="next"' in part:
                    next_url = part[part.find("<") + 1 : part.find(">")]
            url = next_url
            params = {}
    finally:
        if owns_client:
            await client.aclose()
    return records
