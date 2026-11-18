"""Capture execution evidence for the local staging demo (WP-I).

Writes two kinds of artifact, and never blurs them:

* **raw captures** — exactly what a command or endpoint returned (JSON/text);
* **screenshots** — a headless browser against a live web endpoint.

Both are timestamped and bound to the current commit. No token, key or
credential is ever written: the auth matrix records the subject and the HTTP
status, not the bearer value.

Usage:
    python tools/demo_capture.py --phase a --out-dir evals/reports/staging/evidence/<run>
    python tools/demo_capture.py --phase b --out-dir ... --run-id <id>
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx

from itsm_agent.simulators.identity.client import fetch_token

DEMO_TENANT = UUID("11111111-1111-1111-1111-111111111111")
REVIEWER_A = "reviewer-a"
INTRUDER = "reviewer-intruder"

#: Chrome flags for a reproducible capture. `--ignore-certificate-errors` is
#: used ONLY by this screenshot process against the simulator's throwaway CA;
#: the platform itself always pins the CA and never disables verification.
CHROME_FLAGS = (
    "--headless=new",
    "--disable-gpu",
    "--no-sandbox",
    "--hide-scrollbars",
    "--ignore-certificate-errors",
    "--window-size=1440,1100",
    "--virtual-time-budget=9000",
)


def _env(name: str, default: str) -> str:
    return (os.environ.get(name) or default).strip()


def _git_commit() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return "unknown"


def _chrome() -> str | None:
    for candidate in ("google-chrome", "chromium", "chromium-browser"):
        found = shutil.which(candidate)
        if found:
            return found
    return None


def _screenshot(url: str, target: Path, note: str) -> dict[str, Any]:
    chrome = _chrome()
    if chrome is None:
        return {"file": target.name, "url": url, "status": "NOT RUN", "note": "no browser"}
    result = subprocess.run(
        [chrome, *CHROME_FLAGS, f"--screenshot={target}", url],
        capture_output=True,
        text=True,
        timeout=120,
    )
    ok = target.exists() and target.stat().st_size > 0
    return {
        "file": target.name,
        "url": url,
        "status": "PASS" if ok else "FAIL",
        "bytes": target.stat().st_size if target.exists() else 0,
        "note": note,
        "stderr": "" if ok else result.stderr.strip()[:300],
    }


async def _raw_captures(out: Path) -> list[dict[str, Any]]:
    captured: list[dict[str, Any]] = []
    api = _env("ITSM_API_BASE_URL", "http://127.0.0.1:8001")
    prometheus = _env("ITSM_PROMETHEUS_URL", "http://127.0.0.1:9091")
    identity = _env("ITSM_IDENTITY_BASE_URL", "https://127.0.0.1:8444")
    ca = _env("ITSM_IDENTITY_CA_FILE", "./demo-state/identity/simulator-ca.pem")

    def write(name: str, payload: Any, source: str) -> None:
        path = out / name
        text = payload if isinstance(payload, str) else json.dumps(payload, indent=2)
        path.write_text(text + ("" if text.endswith("\n") else "\n"), encoding="utf-8")
        captured.append({"file": name, "source": source, "bytes": path.stat().st_size})

    # 1. Container state, exactly as compose reports it.
    ps = subprocess.run(
        ["docker", "compose", "ps", "--format", "json"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    write("compose-ps.json", ps.stdout.strip() or ps.stderr, "docker compose ps")

    # 2. Prometheus scrape health.
    async with httpx.AsyncClient(timeout=20.0) as client:
        targets = await client.get(f"{prometheus}/api/v1/targets")
        write("prometheus-targets.json", targets.json(), f"{prometheus}/api/v1/targets")

        # 3. OIDC surface — over TLS, pinning the simulator's CA.
        import ssl

        context = ssl.create_default_context(cafile=ca)
        async with httpx.AsyncClient(base_url=identity, verify=context, timeout=15.0) as oidc:
            write(
                "oidc-discovery.json",
                (await oidc.get("/.well-known/openid-configuration")).json(),
                f"{identity}/.well-known/openid-configuration",
            )
            write(
                "oidc-jwks.json",
                (await oidc.get("/jwks")).json(),
                f"{identity}/jwks",
            )

        # 4. Authentication matrix. The bearer value is never recorded.
        matrix: list[dict[str, Any]] = []

        async def probe(label: str, token: str | None) -> None:
            headers = {"authorization": f"Bearer {token}"} if token else {}
            response = await client.get(
                f"{api}/v1/findings",
                params={"tenant_id": str(DEMO_TENANT)},
                headers=headers,
            )
            matrix.append(
                {
                    "case": label,
                    "http_status": response.status_code,
                    "detail": response.text[:160],
                    "expected": "200" if label == "valid reviewer token" else "401/403",
                }
            )

        await probe("no authorization header", None)
        await probe("malformed bearer token", "not-a-jwt")
        await probe(
            "valid reviewer token",
            await fetch_token(base_url=identity, subject=REVIEWER_A, ca_path=ca),
        )
        await probe(
            "signed token, no directory row",
            await fetch_token(base_url=identity, subject=INTRUDER, ca_path=ca),
        )
        write(
            "auth-matrix.json", {"tenant": str(DEMO_TENANT), "probes": matrix}, "GET /v1/findings"
        )

        # 5. Live API metrics document.
        metrics = await client.get(f"{api}/metrics")
        write("api-metrics.txt", metrics.text, f"{api}/metrics")

    return captured


async def _migrations(out: Path) -> dict[str, Any]:
    import psycopg

    dsn = _env("ITSM_POSTGRES_DSN", "")
    if not dsn:
        return {"status": "NOT RUN", "reason": "ITSM_POSTGRES_DSN unset"}
    with psycopg.connect(dsn, connect_timeout=10) as conn, conn.cursor() as cur:
        cur.execute("SELECT filename, applied_at FROM schema_migrations ORDER BY filename")
        applied = [{"filename": name, "applied_at": str(at)} for name, at in cur.fetchall()]
        cur.execute(
            "SELECT subject, roles, tenant_ids, authorization_version "
            "FROM reviewer_authorizations WHERE active ORDER BY subject"
        )
        reviewers = [
            {
                "subject": subject,
                "roles": roles,
                "tenants": [str(t) for t in tenants],
                "version": version,
            }
            for subject, roles, tenants, version in cur.fetchall()
        ]
        cur.execute("SELECT count(*) FROM source_events")
        events = (cur.fetchone() or [0])[0]
        cur.execute("SELECT count(*) FROM findings")
        findings = (cur.fetchone() or [0])[0]
        cur.execute("SELECT status, count(*) FROM outbox GROUP BY status")
        outbox = {status: count for status, count in cur.fetchall()}
    payload = {
        "applied_migrations": applied,
        "reviewer_authorizations": reviewers,
        "source_events": events,
        "findings": findings,
        "outbox": outbox,
    }
    (out / "database-state.json").write_text(json.dumps(payload, indent=2) + "\n", "utf-8")
    return {"status": "PASS", "migrations": len(applied), "reviewers": len(reviewers)}


def _screenshots(out: Path, phase: str) -> list[dict[str, Any]]:
    prometheus = _env("ITSM_PROMETHEUS_URL", "http://127.0.0.1:9091")
    api = _env("ITSM_API_BASE_URL", "http://127.0.0.1:8001")
    identity = _env("ITSM_IDENTITY_BASE_URL", "https://127.0.0.1:8444")

    if phase == "a":
        return [
            _screenshot(
                f"{prometheus}/targets",
                out / "01-prometheus-targets.png",
                "live Prometheus scrape targets",
            ),
            _screenshot(
                f"{prometheus}/api/v1/query?query=itsm_ingestion_events_total",
                out / "02-prometheus-query-ingestion.png",
                "live Prometheus query response for the platform's own metric",
            ),
            _screenshot(f"{api}/metrics", out / "03-api-metrics.png", "live API /metrics"),
            _screenshot(
                f"{identity}/.well-known/openid-configuration",
                out / "04-oidc-discovery.png",
                "live OIDC discovery document over TLS (browser ignores the "
                "throwaway CA; the platform pins it)",
            ),
        ]
    return [
        _screenshot(
            f"{prometheus}/api/v1/query?query=itsm_ingestion_events_total",
            out / "10-prometheus-ingestion-after-run.png",
            "ingestion counter after the event was processed",
        ),
        _screenshot(
            f"{api}/metrics",
            out / "11-api-metrics-after-run.png",
            "live API /metrics after the run",
        ),
    ]


async def main_async(args: argparse.Namespace) -> int:
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).isoformat()

    captured = await _raw_captures(out)
    migrations = await _migrations(out)
    shots = _screenshots(out, args.phase)

    index = {
        "phase": args.phase,
        "commit": _git_commit(),
        "captured_at": stamp,
        "screenshots_ignore_certificate_errors": True,
        "raw_captures": captured,
        "database": migrations,
        "screenshots": shots,
        "not_captured": (
            [] if _chrome() else ["no browser available: all screenshot entries are NOT RUN"]
        ),
    }
    (out / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")

    print(f"evidence directory: {out}")
    for entry in shots:
        print(f"  screenshot {entry['status']:<8} {entry['file']}")
    for entry in captured:
        print(f"  capture    PASS     {entry['file']} ({entry['bytes']} bytes)")
    failed = [entry for entry in shots if entry["status"] == "FAIL"]
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("a", "b"), required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--run-id", default="")
    args = parser.parse_args(argv)
    return asyncio.run(main_async(args))


if __name__ == "__main__":  # pragma: no cover - process boundary
    sys.exit(main())
