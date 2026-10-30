"""Unit tests for pgAudit normalization (no network)."""

from __future__ import annotations

import uuid

from itsm_agent.collectors.postgresql.pgaudit import (
    _redact_sql,
    normalize_record,
    parse_pgaudit_line,
)

TENANT = uuid.uuid4()


def test_parse_valid_line() -> None:
    line = (
        "2026-01-01 12:00:00 UTC:alice@db:LOG:  AUDIT: SESSION,1,1,READ,SELECT,"
        "TABLE,public.users,select * from users where id=12345"
    )
    rec = parse_pgaudit_line(line)
    assert rec is not None
    assert rec["user"] == "alice"
    assert rec["command"] == "SELECT"
    assert rec["object_name"] == "public.users"


def test_parse_non_audit_returns_none() -> None:
    assert parse_pgaudit_line("2026-01-01 12:00:00 UTC:alice@db:LOG:  not an audit") is None


def test_redact_sql() -> None:
    out = _redact_sql("select * from users where name='secret' and id=12345")
    assert "'<redacted>'" in out
    assert "12345" not in out


def test_normalize_basic() -> None:
    line = (
        "2026-01-01 12:00:00 UTC:alice@db:LOG:  AUDIT: SESSION,1,1,READ,SELECT,"
        "TABLE,public.users,select * from users where id=12345"
    )
    rec = parse_pgaudit_line(line)
    assert rec is not None
    ev = normalize_record(rec, TENANT)
    assert ev.tenant_id == TENANT
    assert ev.source == "pgaudit"
    assert ev.actor_id == "alice"
    assert ev.resource_id == "public.users"
    assert ev.event_category == "data"
    sqlr = str(ev.correlation_metadata.get("sql_redacted", ""))
    assert "<redacted>" in sqlr or "12345" not in sqlr


def test_normalize_idempotency_key() -> None:
    line = (
        "2026-01-01 12:00:00 UTC:alice@db:LOG:  AUDIT: SESSION,1,1,READ,SELECT,"
        "TABLE,public.users,select 1"
    )
    rec = parse_pgaudit_line(line)
    assert rec is not None
    ev = normalize_record(rec, TENANT)
    assert ev.idempotency_key.startswith(f"{TENANT}:pgaudit:")
