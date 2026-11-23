"""Staging readiness gate for the local demo stack (WP-I, Execution A).

Every check here is a **live** probe against the running stack. Nothing is
inferred from unit or contract tests: a check that cannot run is reported as
``NOT RUN``, never as a pass.

Verdicts use exactly ``PASS``, ``FAIL``, ``NOT RUN`` and ``NOT APPLICABLE``.

The written artifact is the evidence: it records the commit, the timestamp,
each probe's verdict and the observable detail behind it. A human can re-run
any single check with the URL in its ``detail``.

Usage:
    python tools/demo_readiness.py --full            # every check, incl. expiry
    python tools/demo_readiness.py                   # fast path (skips the wait)
    python tools/demo_readiness.py --out evals/reports/staging/readiness-<id>.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

import httpx
import psycopg

from itsm_agent.simulators.identity.client import fetch_token

Verdict = Literal["PASS", "FAIL", "NOT RUN", "NOT APPLICABLE"]

#: Fixed demo tenant. Provisioning and the rehearsal must agree on it, so it is
#: a constant rather than something each run invents.
DEMO_TENANT = UUID("11111111-1111-1111-1111-111111111111")

#: Subjects the simulator may mint for. ``reviewer-intruder`` is deliberately
#: NOT provisioned in the reviewer directory: a token for it must be refused,
#: which is the live proof that a token is not an authorization.
REVIEWER_A = "reviewer-a"
REVIEWER_B = "reviewer-b"
INTRUDER = "reviewer-intruder"


@dataclass
class Check:
    name: str
    verdict: Verdict
    detail: str


@dataclass
class Readiness:
    commit: str
    started_at: str
    mode: str
    checks: list[Check] = field(default_factory=list)
    #: Extra context attached when a check fails and the cause is not obvious
    #: from the check text alone (e.g. the reviewer-authorization row).
    diagnostics: dict[str, Any] = field(default_factory=dict)

    def add(self, name: str, verdict: Verdict, detail: str) -> None:
        self.checks.append(Check(name=name, verdict=verdict, detail=detail))

    @property
    def gate(self) -> str:
        """Only the full mode can speak for STAGING_READY."""
        return "STAGING_READY" if self.mode == "full" else "STAGING_SMOKE"

    @property
    def verdict(self) -> Verdict:
        if any(c.verdict == "FAIL" for c in self.checks):
            return "FAIL"
        # In fast (smoke) mode a skipped time-boxed check is expected; it makes
        # no claim either way. In full mode an unrun check means the gate has
        # not been demonstrated, and must not read as a pass.
        if self.mode == "full" and any(c.verdict == "NOT RUN" for c in self.checks):
            return "FAIL"
        return "PASS"

    def evidence(self) -> dict[str, Any]:
        return {
            "gate": self.gate,
            "verdict": self.verdict,
            "commit": self.commit,
            "started_at": self.started_at,
            "mode": self.mode,
            "generated_at": datetime.now(UTC).isoformat(),
            "checks": [asdict(c) for c in self.checks],
            "diagnostics": self.diagnostics,
            "does_not_prove": [
                "production readiness",
                "throughput or latency under load",
                "multi-node failover",
                "that spans reach a real OTLP collector (metrics are asserted, traces are not)",
            ],
        }


def _git_commit() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return "unknown"


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _is_ok(status_code: int) -> bool:
    return 200 <= status_code < 300


async def check_compose_services(report: Readiness, required: list[str]) -> None:
    try:
        result = subprocess.run(
            ["docker", "compose", "ps", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(Path(__file__).resolve().parents[1]),
        )
    except (subprocess.SubprocessError, OSError) as exc:
        report.add("compose services", "FAIL", f"docker compose ps failed: {exc}")
        return
    if result.returncode != 0:
        report.add("compose services", "FAIL", result.stderr.strip()[:300])
        return

    services: dict[str, dict[str, Any]] = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        services[str(record.get("Service") or record.get("Name"))] = record

    problems: list[str] = []
    seen: list[str] = []
    for name in required:
        record = services.get(name)
        if record is None:
            problems.append(f"{name}: absent")
            continue
        state = str(record.get("State") or "")
        health = str(record.get("Health") or "")
        seen.append(f"{name}={state}{'/' + health if health else ''}")
        if state != "running":
            problems.append(f"{name}: state={state}")
        elif health and health != "healthy":
            # "starting" is not readiness: the gate runs after `up --wait`.
            problems.append(f"{name}: health={health}")

    if problems:
        report.add("compose services", "FAIL", "; ".join(problems))
    else:
        report.add("compose services", "PASS", ", ".join(seen))


def check_migrations(report: Readiness) -> None:
    dsn = _env("ITSM_POSTGRES_DSN") or _env("DATABASE_URL")
    if not dsn:
        report.add("postgres migrations", "NOT RUN", "no ITSM_POSTGRES_DSN configured")
        return
    expected = len(
        sorted((Path(__file__).resolve().parents[1] / "migrations").glob("[0-9][0-9][0-9]_*.sql"))
    )
    try:
        with psycopg.connect(dsn, connect_timeout=10) as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM schema_migrations")
            row = cur.fetchone()
            applied = int(row[0]) if row else 0
            cur.execute("SELECT count(*) FROM reviewer_authorizations")
            reviewers_row = cur.fetchone()
            reviewers = int(reviewers_row[0]) if reviewers_row else 0
    except psycopg.Error as exc:
        report.add("postgres migrations", "FAIL", f"cannot query schema: {exc}"[:300])
        return
    if applied != expected:
        report.add(
            "postgres migrations",
            "FAIL",
            f"{applied}/{expected} migrations applied (schema is not current)",
        )
        return
    report.add(
        "postgres migrations",
        "PASS",
        f"{applied}/{expected} migrations applied; {reviewers} reviewer authorization row(s)",
    )


async def check_jetstream(report: Readiness) -> None:
    url = _env("ITSM_NATS_MONITOR_URL", "http://127.0.0.1:8223") + "/jsz?consumers=true"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url)
    except httpx.HTTPError as exc:
        report.add("nats jetstream", "FAIL", f"{url}: {exc}"[:300])
        return
    if not _is_ok(response.status_code):
        report.add("nats jetstream", "FAIL", f"{url}: HTTP {response.status_code}")
        return
    body = response.json()
    streams = int(body.get("streams") or 0)
    consumers = int(body.get("consumers") or 0)
    accounts = body.get("account_details") or []
    if streams < 1:
        report.add("nats jetstream", "FAIL", f"{url}: no streams ({streams})")
        return
    # Require a durable consumer with the expected name. An ephemeral consumer
    # or a durable consumer with a different name must NOT satisfy this check.
    expected_durable = "itsm-workflow"
    durable_names: list[str] = []
    for account in accounts:
        for consumer in account.get("consumer_detail") or []:
            name = consumer.get("config", {}).get("durable_name")
            if name:
                durable_names.append(str(name))
    has_expected = expected_durable in durable_names
    report.add(
        "nats jetstream",
        "PASS" if (streams >= 1 and has_expected) else "FAIL",
        f"{url}: streams={streams} consumers={consumers} "
        f"durable={durable_names} expected={expected_durable}",
    )


async def check_oidc(report: Readiness) -> None:
    base = _env("ITSM_IDENTITY_BASE_URL", "https://127.0.0.1:8444")
    ca = _env("ITSM_IDENTITY_CA_FILE", "./demo-state/identity/simulator-ca.pem")
    expected_issuer = _env("ITSM_OIDC_ISSUER", "https://identity:8443")
    if not Path(ca).exists():
        report.add("oidc discovery", "FAIL", f"pinned CA not found at {ca}")
        report.add("oidc jwks", "NOT RUN", "discovery blocked by missing CA")
        return
    import ssl

    context = ssl.create_default_context(cafile=ca)
    try:
        async with httpx.AsyncClient(base_url=base, verify=context, timeout=10.0) as client:
            discovery = await client.get("/.well-known/openid-configuration")
            jwks = await client.get("/jwks")
    except httpx.HTTPError as exc:
        report.add("oidc discovery", "FAIL", f"{base}: {exc}"[:300])
        report.add("oidc jwks", "NOT RUN", "discovery request failed")
        return

    if _is_ok(discovery.status_code):
        body = discovery.json()
        if body.get("issuer") == expected_issuer:
            report.add(
                "oidc discovery",
                "PASS",
                f"{base}/.well-known/openid-configuration: issuer={body.get('issuer')} "
                f"jwks_uri={body.get('jwks_uri')}",
            )
        else:
            report.add(
                "oidc discovery",
                "FAIL",
                f"issuer mismatch: advertised {body.get('issuer')!r}, "
                f"platform configured {expected_issuer!r}",
            )
    else:
        report.add("oidc discovery", "FAIL", f"HTTP {discovery.status_code}")

    if _is_ok(jwks.status_code):
        keys = jwks.json().get("keys") or []
        algorithms = {key.get("alg") for key in keys}
        if keys and algorithms == {"RS256"}:
            report.add("oidc jwks", "PASS", f"{len(keys)} key(s), alg={sorted(algorithms)}")
        else:
            report.add("oidc jwks", "FAIL", f"keys={len(keys)} alg={sorted(algorithms)}")
    else:
        report.add("oidc jwks", "FAIL", f"HTTP {jwks.status_code}")


async def _token(subject: str, ttl: int = 900) -> str:
    return await fetch_token(
        base_url=_env("ITSM_IDENTITY_BASE_URL", "https://127.0.0.1:8444"),
        subject=subject,
        ca_path=_env("ITSM_IDENTITY_CA_FILE", "./demo-state/identity/simulator-ca.pem"),
        ttl_seconds=ttl,
    )


async def _findings_status(token: str | None) -> tuple[int, str]:
    api = _env("ITSM_API_BASE_URL", "http://127.0.0.1:8001")
    headers = {"authorization": f"Bearer {token}"} if token else {}
    async with httpx.AsyncClient(base_url=api, timeout=15.0) as client:
        response = await client.get(
            "/v1/findings", params={"tenant_id": str(DEMO_TENANT)}, headers=headers
        )
        return response.status_code, response.text[:200]


def directory_probe(subject: str, *, tenant: UUID = DEMO_TENANT) -> dict[str, Any]:
    """Read the reviewer's authorization row for diagnosis, best effort.

    Uses the administrative DSN the operator already has (the runtime role
    cannot read this table usefully without a tenant context). It never
    raises: a diagnostic that fails must not replace the failure it was
    meant to explain.

    The point is to separate the two explanations for a 403 "not a member of
    the requested tenant": the stored row disagrees with what the probe asked
    for, or the row agrees and the API answered out of stale state. The age
    of ``updated_at`` is what tells them apart.
    """
    dsn = _env("ITSM_POSTGRES_DSN") or _env("DATABASE_URL")
    issuer = _env("ITSM_OIDC_ISSUER")
    if not dsn:
        return {"available": False, "reason": "no administrative DSN configured"}
    try:
        with psycopg.connect(dsn, connect_timeout=10) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT tenant_ids, roles, active, authorization_version, updated_at "
                "  FROM reviewer_authorizations WHERE issuer = %s AND subject = %s",
                (issuer, subject),
            )
            row = cur.fetchone()
    except psycopg.Error as exc:
        return {"available": False, "reason": str(exc)[:200]}
    if row is None:
        return {
            "available": True,
            "row_found": False,
            "issuer": issuer,
            "subject": subject,
            "requested_tenant": str(tenant),
        }
    tenant_ids, roles, active, version, updated_at = row
    members = [str(item) for item in tenant_ids]
    return {
        "available": True,
        "row_found": True,
        "issuer": issuer,
        "subject": subject,
        "active": bool(active),
        "roles": list(roles),
        "tenant_ids": members,
        "authorization_version": str(version),
        "updated_at": updated_at.isoformat(),
        "age_seconds": round((datetime.now(UTC) - updated_at).total_seconds(), 1),
        "requested_tenant": str(tenant),
        "requested_tenant_is_member": str(tenant) in members,
    }


async def check_authentication(report: Readiness, *, full: bool) -> None:
    api = _env("ITSM_API_BASE_URL", "http://127.0.0.1:8001")
    try:
        async with httpx.AsyncClient(base_url=api, timeout=10.0) as client:
            health = await client.get("/healthz")
        report.add(
            "api health",
            "PASS" if _is_ok(health.status_code) else "FAIL",
            f"{api}/healthz: HTTP {health.status_code}",
        )
    except httpx.HTTPError as exc:
        report.add("api health", "FAIL", f"{api}/healthz: {exc}"[:300])
        report.add("oidc token accepted", "NOT RUN", "API unreachable")
        return

    try:
        token = await _token(REVIEWER_A)
    except (httpx.HTTPError, ValueError) as exc:
        report.add("oidc token accepted", "FAIL", f"token mint failed: {exc}"[:300])
        return

    try:
        status, body = await _findings_status(token)
    except (httpx.HTTPError, ValueError) as exc:
        # `/healthz` answering is not the same service answering `/v1/findings`.
        # A timeout here used to escape the check and abort the run before the
        # report was written, leaving no artifact to explain the failure.
        report.add(
            "oidc token accepted",
            "FAIL",
            f"GET /v1/findings as {REVIEWER_A}: request failed ({type(exc).__name__})",
        )
        report.diagnostics["auth_failure"] = {
            "requested_tenant": str(DEMO_TENANT),
            "http_status": None,
            "detail": f"{type(exc).__name__}: {exc}"[:300],
            "directory": directory_probe(REVIEWER_A),
        }
        return
    report.add(
        "oidc token accepted",
        "PASS" if status == 200 else "FAIL",
        f"GET /v1/findings as {REVIEWER_A}: HTTP {status} {body[:120]}",
    )
    if status != 200:
        # Attach what the directory actually holds, so the artifact explains
        # the refusal instead of leaving a bare status code. A 403 here means
        # the API found the principal but not for this tenant; the stored row
        # says whether that is true or whether the API read stale state.
        report.diagnostics["auth_failure"] = {
            "requested_tenant": str(DEMO_TENANT),
            "http_status": status,
            "detail": body[:300],
            "directory": directory_probe(REVIEWER_A),
        }

    status, body = await _findings_status("not-a-jwt")
    report.add(
        "malformed token rejected",
        "PASS" if status in {401, 403} else "FAIL",
        f"GET /v1/findings with 'Bearer not-a-jwt': HTTP {status} {body[:120]}",
    )

    status, body = await _findings_status(None)
    report.add(
        "missing token rejected",
        "PASS" if status in {401, 403} else "FAIL",
        f"GET /v1/findings with no Authorization header: HTTP {status} {body[:120]}",
    )

    try:
        intruder = await _token(INTRUDER)
    except (httpx.HTTPError, ValueError) as exc:
        report.add(
            "unauthorized principal rejected",
            "NOT RUN",
            f"simulator could not mint for {INTRUDER}: {exc}"[:200],
        )
        intruder = None
    if intruder:
        status, body = await _findings_status(intruder)
        report.add(
            "unauthorized principal rejected",
            "PASS" if status in {401, 403} else "FAIL",
            f"signed token for {INTRUDER} (no directory row): HTTP {status} {body[:120]}",
        )

    if not full:
        report.add(
            "expired token rejected",
            "NOT RUN",
            "skipped in the fast path (requires waiting out a real token TTL); run with --full",
        )
        return

    # The relying party allows a clock-skew leeway (default 30s) past `exp`, so
    # waiting TTL + 5s would still be accepted — correctly. Wait past
    # TTL + leeway + a margin, or this probe would "fail" a healthy system.
    ttl = 60
    leeway = float(_env("ITSM_OIDC_LEEWAY_SECONDS", "30") or 30)
    wait_seconds = int(ttl + leeway + 10)
    try:
        short = await _token(REVIEWER_A, ttl=ttl)
    except (httpx.HTTPError, ValueError) as exc:
        report.add("expired token rejected", "NOT RUN", f"token mint failed: {exc}"[:200])
        return
    status_before, _ = await _findings_status(short)
    print(f"      waiting {wait_seconds}s for the token to expire...", flush=True)
    await asyncio.sleep(wait_seconds)
    status_after, body = await _findings_status(short)
    report.add(
        "expired token rejected",
        "PASS" if status_before == 200 and status_after in {401, 403} else "FAIL",
        f"same token: HTTP {status_before} before expiry, {status_after} after "
        f"{wait_seconds}s {body[:100]}",
    )


async def check_observability(report: Readiness) -> None:
    prometheus = _env("ITSM_PROMETHEUS_URL", "http://127.0.0.1:9091")
    api = _env("ITSM_API_BASE_URL", "http://127.0.0.1:8001")
    try:
        async with httpx.AsyncClient(base_url=api, timeout=10.0) as client:
            metrics = await client.get("/metrics")
        text = metrics.text
        declared = [
            name
            for name in (
                "itsm_ingestion_events_total",
                "itsm_consumer_messages_total",
                "itsm_outbox_backlog",
            )
            if name in text
        ]
        report.add(
            "api metrics endpoint",
            "PASS" if _is_ok(metrics.status_code) and declared else "FAIL",
            f"{api}/metrics: HTTP {metrics.status_code}, "
            f"{len(text.splitlines())} lines, names present={declared}",
        )
    except httpx.HTTPError as exc:
        report.add("api metrics endpoint", "FAIL", f"{api}/metrics: {exc}"[:300])

    url = prometheus + "/api/v1/targets"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url)
    except httpx.HTTPError as exc:
        report.add("prometheus targets", "FAIL", f"{url}: {exc}"[:300])
        return
    if not _is_ok(response.status_code):
        report.add("prometheus targets", "FAIL", f"{url}: HTTP {response.status_code}")
        return
    active = response.json().get("data", {}).get("activeTargets") or []
    down = [
        f"{t.get('labels', {}).get('job')}={t.get('health')}"
        for t in active
        if t.get("health") != "up"
    ]
    up_jobs = sorted(
        {str(t.get("labels", {}).get("job")) for t in active if t.get("health") == "up"}
    )
    expected = {"prometheus", "otel-collector", "otel-exported-app-metrics", "api"}
    missing = expected - set(up_jobs)
    if down or missing:
        report.add(
            "prometheus targets",
            "FAIL",
            f"{url}: up={up_jobs} down={down} missing={sorted(missing)}",
        )
    else:
        report.add("prometheus targets", "PASS", f"{url}: up={up_jobs}")


async def check_pipeline_processes(report: Readiness) -> None:
    """Verify durable consumer topology and outbox state.

    NOTE: A durable consumer persisting in NATS does not prove the worker
    process is alive. This check verifies that the durable consumer exists
    with the correct name and configuration. Process liveness is verified
    separately by the container health check (H4) and by the consumer
    creating the durable consumer during startup. If the consumer is absent,
    the check fails even when the outbox is empty.
    """
    # Verify the durable consumer exists (process liveness signal).
    nats_url = _env("ITSM_NATS_MONITOR_URL", "http://127.0.0.1:8223")
    consumer_url = nats_url + "/jsz?consumers=true"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(consumer_url)
        if not _is_ok(response.status_code):
            report.add(
                "pipeline processes",
                "FAIL",
                f"{consumer_url}: HTTP {response.status_code}",
            )
            return
        try:
            body = response.json()
        except (ValueError, KeyError) as exc:
            report.add(
                "pipeline processes",
                "FAIL",
                f"{consumer_url}: unparseable response ({type(exc).__name__})",
            )
            return
        accounts = body.get("account_details") or []
        durable_names: list[str] = []
        for account in accounts:
            for consumer in account.get("consumer_detail") or []:
                name = consumer.get("config", {}).get("durable_name")
                if name:
                    durable_names.append(str(name))
        if "itsm-workflow" not in durable_names:
            report.add(
                "pipeline processes",
                "FAIL",
                f"durable consumer 'itsm-workflow' not found in NATS (found: {durable_names})",
            )
            return
    except httpx.HTTPError as exc:
        report.add("pipeline processes", "FAIL", f"{consumer_url}: {exc}"[:300])
        return

    dsn = _env("ITSM_POSTGRES_DSN") or _env("DATABASE_URL")
    if not dsn:
        report.add("pipeline processes", "NOT RUN", "no DSN configured")
        return
    try:
        with psycopg.connect(dsn, connect_timeout=10) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT count(*), "
                "count(*) FILTER (WHERE tenant_id IS NULL), "
                "count(*) FILTER (WHERE tenant_id IS NOT NULL AND status = 'pending'), "
                "coalesce(extract(epoch FROM now() - min(created_at) "
                "  FILTER (WHERE tenant_id IS NOT NULL AND status = 'pending')), 0) "
                "FROM outbox"
            )
            row = cur.fetchone()
    except psycopg.Error as exc:
        report.add("pipeline processes", "FAIL", f"cannot read outbox: {exc}"[:300])
        return

    total, system_rows, tenant_pending, oldest_pending_seconds = row if row else (0, 0, 0, 0)
    total = int(total)
    tenant_pending = int(tenant_pending)
    oldest_pending_seconds = float(oldest_pending_seconds)

    if total == 0:
        # A freshly started stack has no rows yet; publishing is asserted by
        # the rehearsal, not here. An empty table is not evidence of anything.
        report.add(
            "outbox backlog",
            "NOT APPLICABLE",
            "no outbox rows yet — publishing is asserted by the rehearsal",
        )
        return

    if tenant_pending and oldest_pending_seconds > 60:
        report.add(
            "outbox backlog",
            "FAIL",
            f"{tenant_pending} tenant-scoped row(s) still pending after "
            f"{oldest_pending_seconds:.0f}s; the relay is not draining them",
        )
        return

    detail = f"{tenant_pending} tenant-scoped row(s) pending, oldest {oldest_pending_seconds:.0f}s"
    if system_rows:
        # Pre-existing behaviour, recorded rather than hidden: the relay runs
        # one scoped pass per registered tenant, so rows with no tenant (the
        # legacy incident workflow) are outside its reach once a tenant exists.
        detail += (
            f"; {system_rows} system row(s) with tenant_id NULL are NOT drained by the "
            "tenant-scoped relay (known limitation, documented in the qualification record)"
        )
    report.add("outbox backlog", "PASS", detail)


async def main_async(args: argparse.Namespace) -> int:
    report = Readiness(
        commit=_git_commit(),
        started_at=datetime.now(UTC).isoformat(),
        mode="full" if args.full else "fast",
    )
    required = [
        "postgres",
        "nats",
        "identity",
        "mockoon",
        "otel-collector",
        "prometheus",
    ]
    # worker/relay/retention expose no port and therefore no healthcheck: the
    # gate can only prove the process is running here. That they actually
    # process events is a separate, live assertion in the rehearsal.
    required += ["api", "worker", "relay", "retention"]

    await check_compose_services(report, required)
    check_migrations(report)
    await check_jetstream(report)
    await check_oidc(report)
    await check_authentication(report, full=args.full)
    await check_observability(report)
    await check_pipeline_processes(report)

    print()
    print(f"{'CHECK':<34} {'VERDICT':<8} DETAIL")
    print("-" * 110)
    for check in report.checks:
        print(f"{check.name:<34} {check.verdict:<8} {check.detail[:64]}")
    print("-" * 110)
    print(f"{report.gate}: {report.verdict}   (commit {report.commit[:12]}, mode {report.mode})")

    target = evidence_target(args.out, report.verdict, report.started_at)
    if target is not None:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(report.evidence(), indent=2) + "\n", encoding="utf-8")
        label = "failure evidence" if report.verdict != "PASS" else "evidence"
        print(f"{label}: {target}")

    return 0 if report.verdict == "PASS" else 1


def evidence_target(out: str, verdict: Verdict, started_at: str) -> Path | None:
    """Where this run's report belongs.

    A failure always gets a file, even when the caller asked for none, because
    a gate that can fail without leaving evidence cannot be investigated. It
    is routed under ``failures/`` so that a directory of passing artifacts is
    never mistaken for a system that has never failed. A pass is written only
    where the caller asked for it.
    """
    if verdict != "PASS":
        stem = started_at.replace(":", "").replace("-", "").split(".")[0]
        return Path("evals/reports/staging/failures") / f"readiness-{stem}Z.json"
    return Path(out) if out else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--full",
        action="store_true",
        help="include the checks that cost time (the expired-token wait)",
    )
    parser.add_argument("--out", default="", help="write the JSON evidence here")
    args = parser.parse_args(argv)
    started = time.monotonic()
    code = asyncio.run(main_async(args))
    print(f"readiness gate finished in {time.monotonic() - started:.1f}s")
    return code


if __name__ == "__main__":  # pragma: no cover - process boundary
    sys.exit(main())
