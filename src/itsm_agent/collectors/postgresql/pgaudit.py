"""PostgreSQL pgAudit collector (Task 9).

Read-only adapter: parses pgAudit log lines, normalizes into SourceEvents,
redacts sensitive SQL. No mutations.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from itsm_agent.domain.events import SourceEvent
from itsm_agent.ports.collectors import CollectorPort
from itsm_agent.ports.repositories import SourceCheckpointRepository

# pgAudit log line example:
# (example pgAudit line omitted for line length)


def _parse_ts(line: str) -> datetime:
    # leading "YYYY-MM-DD HH:MM:SS TZ:"
    m = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(\w+)", line)
    if m:
        ts = m.group(1)
        dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
        return dt
    return datetime.now(tz=UTC)


def _redact_sql(sql: str) -> str:
    # Redact string literals and numeric params
    s = re.sub(r"'[^']*'", "'<redacted>'", sql)
    s = re.sub(r"\b\d{4,}\b", "<num>", s)
    return s


def parse_pgaudit_line(line: str) -> dict[str, Any] | None:
    """Parse a single pgAudit log line into a dict; None if not an audit record."""
    if "AUDIT:" not in line:
        return None
    # split on "AUDIT: "
    idx = line.index("AUDIT:")
    body = line[idx + len("AUDIT:") :].strip()
    # body: SESSION,1,1,READ,SELECT,TABLE,public.users,<sql>,...
    parts = body.split(",", 7)
    if len(parts) < 7:
        return None
    audit_type, stmt_id, sub_id, class_, command, obj_type, obj_name = parts[:7]
    sql = parts[7] if len(parts) > 7 else ""
    # user/db from prefix "user@db"
    user = "unknown"
    m = re.search(r":(\w+)@(\w+):", line)
    if m:
        user = m.group(1)
    return {
        "audit_type": audit_type.strip(),
        "statement_id": stmt_id.strip(),
        "substatement_id": sub_id.strip(),
        "class": class_.strip(),
        "command": command.strip(),
        "object_type": obj_type.strip(),
        "object_name": obj_name.strip(),
        "sql": sql.strip(),
        "user": user,
        "timestamp": _parse_ts(line),
    }


def normalize_record(record: dict[str, Any], tenant_id: UUID) -> SourceEvent:
    cmd = str(record.get("command", "UNKNOWN"))
    obj_name = str(record.get("object_name", ""))
    user = str(record.get("user", "unknown"))
    ts = record.get("timestamp")
    if not isinstance(ts, datetime):
        ts = datetime.now(tz=UTC)
    sql_raw = str(record.get("sql", ""))
    sql_redacted = _redact_sql(sql_raw)
    stmt = str(record.get("statement_id", ""))
    sub = str(record.get("substatement_id", ""))
    idem = f"{tenant_id}:pgaudit:{stmt}-{sub}-{ts.isoformat()}"
    payload_hash = hashlib.sha256(
        json.dumps(record, sort_keys=True, default=str).encode()
    ).hexdigest()
    return SourceEvent(
        event_id=uuid4(),
        tenant_id=tenant_id,
        source="pgaudit",
        source_event_id=record.get("statement_id"),
        idempotency_key=idem,
        source_schema_version=None,
        canonical_schema_version="1.0",
        event_type=cmd,
        event_category="data",
        event_time=ts,
        observed_at=datetime.now(tz=UTC),
        actor_id=user,
        principal_id=user,
        session_id=None,
        action=f"pg:{cmd}",
        resource_type=record.get("object_type"),
        resource_id=obj_name or None,
        outcome="success",
        permission_context={},
        payload_hash=payload_hash,
        raw_evidence_reference=None,
        correlation_metadata={"sql_redacted": sql_redacted, "audit_type": record.get("audit_type")},
    )


class PgAuditCollector(CollectorPort):
    SOURCE = "pgaudit"

    def __init__(
        self,
        tenant_id: UUID,
        lines: list[str],
        checkpoint_repo: SourceCheckpointRepository | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self._lines = lines
        self._checkpoint_repo = checkpoint_repo

    async def collect(self, since: datetime) -> list[SourceEvent]:
        events: list[SourceEvent] = []
        latest = None
        for line in self._lines:
            rec = parse_pgaudit_line(line)
            if rec is None:
                continue
            if rec["timestamp"] < since:
                continue
            ev = normalize_record(rec, self.tenant_id)
            events.append(ev)
            if latest is None or ev.event_time > latest:
                latest = ev.event_time
        if self._checkpoint_repo is not None and latest is not None:
            await self._checkpoint_repo.upsert(
                self.tenant_id, self.SOURCE, f"pgaudit:{latest.isoformat()}", latest
            )
        return events
