"""Async migration applier (mirrors migrations/apply.py for test/runtime use)."""

from __future__ import annotations

from pathlib import Path

from psycopg import AsyncConnection, sql

MIGRATIONS_DIR = Path(__file__).resolve().parents[4] / "migrations"
BOOKKEEPING_TABLE = "schema_migrations"


def _migration_files() -> list[Path]:
    files = sorted(MIGRATIONS_DIR.glob("[0-9][0-9][0-9]_*.sql"))
    if not files:
        raise RuntimeError(f"no migration files found in {MIGRATIONS_DIR}")
    return files


async def apply_migrations(dsn: str) -> list[str]:
    """Apply all not-yet-applied migrations. Returns newly applied filenames."""
    applied_now: list[str] = []
    async with await AsyncConnection.connect(dsn) as conn:
        await conn.execute("SET lock_timeout = '5s'")
        # Identifier is composed with psycopg.sql.Identifier (injection-safe
        # whitelisting); nothing here is user-controlled.
        await conn.execute(
            sql.SQL(
                "CREATE TABLE IF NOT EXISTS {} ("
                "filename TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
            ).format(sql.Identifier(BOOKKEEPING_TABLE))
        )
        async with conn.cursor() as cur:
            await cur.execute(
                sql.SQL("SELECT filename FROM {}").format(sql.Identifier(BOOKKEEPING_TABLE))
            )
            already = {row[0] for row in await cur.fetchall()}
        for path in _migration_files():
            if path.name in already:
                continue
            await conn.execute(path.read_text(encoding="utf-8"))
            # Identifier composed with psycopg.sql.Identifier (see above).
            await conn.execute(
                sql.SQL("INSERT INTO {} (filename) VALUES (%s)").format(
                    sql.Identifier(BOOKKEEPING_TABLE)
                ),
                (path.name,),
            )
            await conn.commit()
            applied_now.append(path.name)
    return applied_now
