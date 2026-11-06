"""Forward-only SQL migration applier (psycopg 3, sync — used from CLI/tests).

Usage:
    uv run python -m migrations.apply --dsn postgresql://user:pass@host:5432/db
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import psycopg

MIGRATIONS_DIR = Path(__file__).resolve().parent
BOOKKEEPING_TABLE = "schema_migrations"


def _migration_files() -> list[Path]:
    files = sorted(MIGRATIONS_DIR.glob("[0-9][0-9][0-9]_*.sql"))
    if not files:
        raise RuntimeError(f"no migration files found in {MIGRATIONS_DIR}")
    return files


def _ensure_bookkeeping(conn: psycopg.Connection[bytes]) -> None:
    with conn.cursor() as cur:
        cur.execute(
            f"CREATE TABLE IF NOT EXISTS {BOOKKEEPING_TABLE} ("
            "filename TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        )


def _applied(conn: psycopg.Connection[bytes]) -> set[str]:
    with conn.cursor() as cur:
        cur.execute(f"SELECT filename FROM {BOOKKEEPING_TABLE}")
        return {row[0] for row in cur.fetchall()}


def apply_migrations_sync(dsn: str) -> list[str]:
    """Apply all not-yet-applied migrations. Returns newly applied filenames."""
    applied_now: list[str] = []
    with psycopg.connect(dsn) as conn:
        conn.execute("SET lock_timeout = '5s'")
        _ensure_bookkeeping(conn)
        already = _applied(conn)
        for path in _migration_files():
            if path.name in already:
                continue
            sql = path.read_text(encoding="utf-8")
            conn.execute(sql)
            conn.execute(
                f"INSERT INTO {BOOKKEEPING_TABLE} (filename) VALUES (%s)",
                (path.name,),
            )
            conn.commit()
            applied_now.append(path.name)
    return applied_now


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply forward-only SQL migrations.")
    parser.add_argument(
        "--dsn",
        required=True,
        help="PostgreSQL DSN, e.g. postgresql://itsm:itsm@localhost:5432/itsm_test",
    )
    args = parser.parse_args()
    applied = apply_migrations_sync(args.dsn)
    if applied:
        print("applied: " + ", ".join(applied))
    else:
        print("nothing to apply (schema up to date)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
