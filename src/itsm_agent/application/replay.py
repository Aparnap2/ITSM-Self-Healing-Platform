"""Bounded replay helpers for the event backbone (Task 7)."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID

from psycopg_pool import AsyncConnectionPool

from itsm_agent.adapters.persistence.repositories import PsycopgSourceEventRepository


async def replay_source_events(
    pool: AsyncConnectionPool[Any],
    *,
    tenant_id: UUID,
    source: str,
    start: datetime,
    end: datetime,
    limit: int = 100,
) -> list[UUID]:
    if limit <= 0 or limit > 1000:
        raise ValueError("limit must be between 1 and 1000")
    repo = PsycopgSourceEventRepository(pool)
    async with pool.connection() as conn, conn.cursor() as cur:
        await cur.execute(
            """
            SELECT id FROM source_events
            WHERE tenant_id = %s AND source = %s
              AND event_time >= %s AND event_time <= %s
            ORDER BY event_time, id
            LIMIT %s
            """,
            (tenant_id, source, start, end, limit),
        )
        rows = await cur.fetchall()
    event_ids = [r[0] for r in rows]

    requeued: list[UUID] = []
    async with pool.connection() as conn:
        for eid in event_ids:
            cur = await conn.execute(
                "SELECT 1 FROM outbox WHERE aggregate_id = %s AND event_type = %s LIMIT 1",
                (eid, "SourceEventReplayed"),
            )
            existing = await cur.fetchone()
            if existing is not None:
                continue
            ev = await repo.get(eid, conn=conn)
            if ev is None:
                continue
            await conn.execute(
                """
                INSERT INTO outbox (id, event_type, aggregate_id, payload, tenant_id, status)
                VALUES (gen_random_uuid(), %s, %s, %s, %s, 'pending')
                """,
                ("SourceEventReplayed", eid, json.dumps(ev.model_dump(mode="json")), ev.tenant_id),
            )
            requeued.append(eid)
        await conn.commit()
    return requeued


__all__ = ["replay_source_events"]
