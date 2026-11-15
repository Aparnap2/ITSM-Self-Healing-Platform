#!/usr/bin/env python3
"""Manual staging end-to-end rehearsal for the selective investigation stage.

**This tool is NOT part of CI.** It makes REAL, BILLED model calls when a
Groq key is present, and it is meant to be run by an operator against a
staging deployment, following ``docs/runbooks/SOP-06-staging-e2e-run.md``.

What it does, in order:

1. **Preflight** -- verifies the required environment is present. If anything
   is missing the run stops with exit code ``2`` *before any network access*.
2. Registers a tenant and seeds **one** malicious CloudTrail record
   (AssumeRole to an admin role) through the durable source-event sink.
3. Delivers the same malicious activity through the **signed HTTP webhook**
   of the running API (``POST /v1/incidents/webhook``).
4. Relays the outbox to NATS JetStream.
5. Consumes the source event (in-process by default) so the deterministic
   detection engine produces a finding.
6. Polls (bounded) for the finding to appear.
7. Runs the **advisory** investigation stage for that finding, under a hard
   cap on real model calls.
8. Fetches the evidence bundle from ``GET /v1/findings/{id}/bundle`` with a
   minted reviewer bearer token.
9. Writes a JSON run report and prints a short human summary.

What the report explicitly states: the model's proposal is **advisory**, the
model did **not** change the finding's status, how many model calls were
used, and what the run does **not** prove.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx

from itsm_agent.adapters.messaging.nats_bus import (
    JetStreamConsumer,
    JetStreamPublisher,
    MessagingConfig,
)
from itsm_agent.adapters.messaging.outbox_relay import OutboxRelay
from itsm_agent.adapters.persistence.ingestion_sink import PsycopgSourceEventSink
from itsm_agent.adapters.persistence.pool import PersistenceConfig, create_pool
from itsm_agent.adapters.persistence.repositories import RepositoryBundle
from itsm_agent.api.auth import Role, mint_token
from itsm_agent.api.security import compute_signature
from itsm_agent.application.audit_consumer import build_evidence_source
from itsm_agent.collectors.aws.cloudtrail import normalize_record
from itsm_agent.domain.events import IncidentCreated, InvestigationProposal, InvestigationRequest
from itsm_agent.domain.investigation_policy import should_investigate
from itsm_agent.domain.models import Finding
from itsm_agent.investigations.groq_model import (
    GroqInvestigationModel,
    InvestigationModelOutputInvalidError,
    InvestigationModelUnavailableError,
)
from itsm_agent.investigations.service import InvestigationService

#: Repository root (the tool lives in ``tools/``).
REPO_ROOT = Path(__file__).resolve().parents[1]

#: Default report location. The report is a run artifact, not a source file.
DEFAULT_REPORT_PATH = REPO_ROOT / "evals" / "reports" / "staging-run.json"

#: Default number of seconds to wait for a finding to appear.
DEFAULT_POLL_SECONDS = 60.0

#: Default hard cap on REAL (billed) model calls for one run.
DEFAULT_LLM_BUDGET_CALLS = 3

#: Minimum length of the reviewer HMAC secret (``TokenAuthenticator`` rejects
#: anything shorter).
MIN_SECRET_LENGTH = 16


class LlmBudgetExceeded(RuntimeError):
    """The hard cap on real model calls for this run was reached."""


class StagingRunError(RuntimeError):
    """The rehearsal could not be completed."""


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

#: Logical requirement -> accepted environment variable names (first hit wins).
REQUIRED_ENVIRONMENTS: dict[str, tuple[str, ...]] = {
    "database DSN": ("ITSM_POSTGRES_DSN", "DATABASE_URL"),
    "NATS URL": ("ITSM_NATS_URL", "NATS_URL"),
    "webhook signing secret": ("ITSM_WEBHOOK_SECRET",),
    "reviewer HMAC secret": ("ITSM_AUTH_HMAC_SECRET",),
    "Groq API key": ("ITSM_GROQ_API_KEY",),
}


def missing_requirements(env: Mapping[str, str]) -> list[str]:
    """Return the requirements that are not satisfied by ``env``.

    Pure function: it never touches the network, the database or the disk.
    """
    missing: list[str] = []
    for label, names in REQUIRED_ENVIRONMENTS.items():
        if not any((env.get(name) or "").strip() for name in names):
            missing.append(f"{label} (one of: {', '.join(names)})")
    reviewer_secret = (env.get("ITSM_AUTH_HMAC_SECRET") or "").strip()
    if reviewer_secret and len(reviewer_secret) < MIN_SECRET_LENGTH:
        missing.append(
            f"reviewer HMAC secret (ITSM_AUTH_HMAC_SECRET must be at least "
            f"{MIN_SECRET_LENGTH} characters)"
        )
    return missing


def _resolve(env: Mapping[str, str], names: Sequence[str]) -> str:
    for name in names:
        value = (env.get(name) or "").strip()
        if value:
            return value
    raise StagingRunError(f"missing required setting: {' or '.join(names)}")


# ---------------------------------------------------------------------------
# The malicious record
# ---------------------------------------------------------------------------


def malicious_cloudtrail_record(*, event_id: str | None = None) -> dict[str, Any]:
    """One AssumeRole-to-admin CloudTrail record (the staging threat)."""
    return {
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
        "requestID": "r-staging-1",
        "eventID": event_id or f"staging-{uuid.uuid4().hex}",
        "readOnly": False,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": "123",
        "eventCategory": "Management",
    }


def malicious_incident(*, external_event_id: str) -> IncidentCreated:
    """The same malicious activity expressed as an incident for the webhook."""
    return IncidentCreated(
        event_id=uuid.uuid4(),
        source_system="aws-cloudtrail",
        source_incident_id=external_event_id,
        external_event_id=external_event_id,
        occurred_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
        correlation_id=uuid.uuid4(),
        title="AssumeRole to an administrative role",
        description=(
            "Principal arn:aws:iam::123:user/alice assumed the administrative role "
            "arn:aws:iam::123:role/Admin from 203.0.113.5 without a recorded approval."
        ),
        service_name="aws-iam",
        severity="P2",
        environment="staging",
    )


# ---------------------------------------------------------------------------
# Budgeted model
# ---------------------------------------------------------------------------


@dataclass
class BudgetedInvestigationModel:
    """Enforces the hard cap on REAL model calls for one run.

    The budget is a property of the *run*, not of the model: every call --
    successful or not -- consumes one unit. A model failure is dumped to
    ``/tmp/llm_debug_<UTC timestamp>.json`` and the run stops; there is no
    retry loop.
    """

    inner: GroqInvestigationModel
    budget: int
    debug_dir: Path = Path("/tmp")
    calls_used: int = 0
    failure: Exception | None = None
    debug_path: Path | None = None

    async def investigate(
        self, request: InvestigationRequest, evidence: dict[UUID, str]
    ) -> InvestigationProposal:
        if self.calls_used >= self.budget:
            raise LlmBudgetExceeded(
                f"LLM budget exhausted: {self.calls_used} of {self.budget} calls used"
            )
        self.calls_used += 1
        try:
            return await self.inner.investigate(request, evidence)
        except (InvestigationModelUnavailableError, InvestigationModelOutputInvalidError) as exc:
            self.failure = exc
            self.debug_path = self._dump_debug(exc)
            raise

    def _dump_debug(self, exc: Exception) -> Path:
        """Write the raw model response to /tmp for offline debugging."""
        self.debug_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
        path = self.debug_dir / f"llm_debug_{stamp}.json"
        payload = {
            "captured_at": datetime.now(tz=UTC).isoformat(),
            "error_type": type(exc).__name__,
            "error": str(exc),
            "model": self.inner.model_name,
            "raw_response": self.inner.last_raw_payload,
        }
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        return path


# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StagingOptions:
    """Everything the rehearsal needs, resolved from the environment."""

    env: Mapping[str, str]
    api_base_url: str
    report_path: Path
    in_process: bool = True
    tenant_id: UUID = field(default_factory=uuid.uuid4)
    poll_seconds: float = DEFAULT_POLL_SECONDS
    llm_budget_calls: int = 3

    @property
    def dsn(self) -> str:
        return _resolve(self.env, REQUIRED_ENVIRONMENTS["database DSN"])

    @property
    def nats_url(self) -> str:
        return _resolve(self.env, REQUIRED_ENVIRONMENTS["NATS URL"])

    @property
    def webhook_secret(self) -> str:
        return _resolve(self.env, REQUIRED_ENVIRONMENTS["webhook signing secret"])

    @property
    def reviewer_secret(self) -> str:
        return _resolve(self.env, REQUIRED_ENVIRONMENTS["reviewer HMAC secret"])

    @property
    def groq_api_key(self) -> str:
        return _resolve(self.env, REQUIRED_ENVIRONMENTS["Groq API key"])

    @property
    def groq_base_url(self) -> str:
        return (self.env.get("ITSM_GROQ_BASE_URL") or "").strip() or (
            "https://api.groq.com/openai/v1"
        )

    @property
    def groq_model(self) -> str:
        return (self.env.get("ITSM_GROQ_MODEL") or "").strip() or "openai/gpt-oss-120b"


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------


@dataclass
class RunLog:
    """Ordered, human-readable record of what the rehearsal did."""

    steps: list[dict[str, str]] = field(default_factory=list)

    def add(self, name: str, outcome: str, detail: str = "") -> None:
        self.steps.append({"step": name, "outcome": outcome, "detail": detail})


async def _post_signed_webhook(
    client: httpx.AsyncClient,
    *,
    api_base_url: str,
    webhook_secret: str,
    incident: IncidentCreated,
) -> dict[str, Any]:
    """Deliver the incident to the running API over the signed webhook."""
    body = incident.model_dump(mode="json")
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = compute_signature(webhook_secret, raw)
    response = await client.post(
        f"{api_base_url.rstrip('/')}/v1/incidents/webhook",
        content=raw,
        headers={
            "content-type": "application/json",
            "x-itsm-signature": f"sha256={signature}",
        },
    )
    return {"status_code": response.status_code, "body": response.text[:500]}


async def _wait_for_finding(
    repositories: RepositoryBundle,
    tenant_id: UUID,
    *,
    timeout_seconds: float,
) -> Finding | None:
    """Poll for the finding produced by detection (bounded)."""
    deadline = datetime.now(tz=UTC).timestamp() + timeout_seconds
    while datetime.now(tz=UTC).timestamp() < deadline:
        findings = await repositories.findings.list_for_tenant(tenant_id)
        if findings:
            return findings[0]
        await asyncio.sleep(0.5)
    return None


async def run_staging(options: StagingOptions) -> tuple[dict[str, Any], int]:
    """Run the rehearsal. Returns (report, exit code)."""
    log = RunLog()
    started_at = datetime.now(tz=UTC)

    pool = create_pool(PersistenceConfig(dsn=options.dsn))
    await pool.open()
    publisher: JetStreamPublisher | None = None
    consumer: JetStreamConsumer | None = None
    model: GroqInvestigationModel | None = None
    try:
        repositories = RepositoryBundle(pool)
        await repositories.tenants.ensure(options.tenant_id, name="staging-e2e")
        log.add("tenant", "registered", str(options.tenant_id))

        # --- 1. durable source-event ingest -------------------------------
        record = malicious_cloudtrail_record()
        source_event = normalize_record(record, options.tenant_id)
        sink = PsycopgSourceEventSink(pool)
        ingest_outcome = await sink.accept_source_event(source_event)
        if ingest_outcome.value != "ACCEPTED":
            raise StagingRunError(f"source event was not durably accepted: {ingest_outcome.value}")
        log.add(
            "source_event_ingest",
            ingest_outcome.value,
            f"cloudtrail:{record['eventID']}",
        )

        # --- 2. signed HTTP webhook ingest ---------------------------------
        webhook_result: dict[str, Any] = {"status_code": None, "body": ""}
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
            try:
                webhook_result = await _post_signed_webhook(
                    client,
                    api_base_url=options.api_base_url,
                    webhook_secret=options.webhook_secret,
                    incident=malicious_incident(external_event_id=str(record["eventID"])),
                )
                log.add(
                    "signed_webhook_ingest",
                    "accepted" if webhook_result["status_code"] < 400 else "rejected",
                    f"HTTP {webhook_result['status_code']}",
                )
            except httpx.HTTPError as exc:
                log.add(
                    "signed_webhook_ingest",
                    "unavailable",
                    f"the API at {options.api_base_url} is unreachable: {type(exc).__name__}",
                )

        # --- 3. outbox -> NATS ---------------------------------------------
        messaging = MessagingConfig(servers=(options.nats_url,), connect_timeout_seconds=5.0)
        publisher = JetStreamPublisher(messaging)
        await publisher.ensure_stream()
        relay = OutboxRelay(repositories.outbox, publisher, backoff_seconds=0.0, max_attempts=5)
        # The relay must be tenant-scoped: a runtime role cannot make the
        # system-wide claim (that requires bypassing RLS).
        published = await relay.relay_once(tenant_id=options.tenant_id)
        log.add("outbox_relay", "published", f"{published} message(s)")

        # --- 4. detection (in-process, or the packaged consumer) -----------
        if options.in_process:
            consumer = JetStreamConsumer(messaging)
            await consumer.ensure_consumer()
            from itsm_agent.application.audit_consumer import consume_source_event

            outcome = await consume_source_event(
                consumer=consumer,
                pool=pool,
                findings_repo=repositories.findings,
                processing_repo=repositories.processing_records,
                covered_sources={"cloudtrail"},
                clock_now=lambda: datetime.now(tz=UTC),
                investigation_enabled=False,
                timeout_seconds=5.0,
            )
            log.add("detection", outcome, "audit consumer driven in-process")
        else:
            log.add(
                "detection",
                "delegated",
                "waiting for the packaged audit consumer "
                "(python -m itsm_agent.workers.audit_consumer)",
            )

        finding = await _wait_for_finding(
            repositories, options.tenant_id, timeout_seconds=options.poll_seconds
        )
        if finding is None:
            raise StagingRunError(
                f"no finding appeared within {options.poll_seconds:.0f}s; "
                "is the audit consumer running? start it with: "
                "python -m itsm_agent.workers.audit_consumer"
            )
        log.add(
            "finding",
            "detected",
            f"{finding.finding_type} severity={finding.severity} outcome={finding.outcome}",
        )
        status_before_investigation = finding.status

        # --- 5. advisory investigation stage --------------------------------
        model = GroqInvestigationModel(
            base_url=options.groq_base_url,
            api_key=options.groq_api_key,
            model=options.groq_model,
            max_tokens=int(options.env.get("ITSM_GROQ_MAX_TOKENS") or "2000"),
            timeout_seconds=30.0,
            # No retry loop: a failed model call ends the run.
            max_retries=0,
        )
        budgeted = BudgetedInvestigationModel(
            inner=model, budget=options.llm_budget_calls, debug_dir=Path("/tmp")
        )
        investigation_status = "SKIPPED"
        proposal: InvestigationProposal | None = None
        if should_investigate(finding, enabled=True):
            service = InvestigationService(
                repositories.investigation,
                model=budgeted,
                evidence_source=build_evidence_source(repositories.pool),
            )
            investigation_status = await service.investigate_finding(
                tenant_id=options.tenant_id,
                finding=finding,
                evidence_snapshot_ids=(source_event.event_id,),
                requested_by="staging-e2e-runner",
            )
            proposals = await repositories.investigation.list_proposals_for_finding(
                options.tenant_id, finding.id
            )
            if proposals:
                proposal = InvestigationProposal(
                    investigation_id=proposals[0].request_id,
                    hypothesis=proposals[0].hypothesis,
                    supporting_evidence=list(proposals[0].supporting_evidence),
                    contradicting_evidence=list(proposals[0].contradicting_evidence),
                    missing_evidence=list(proposals[0].missing_evidence),
                    uncertainty=proposals[0].uncertainty,
                    recommended_disposition=proposals[0].recommended_disposition,
                    model_version=options.groq_model,
                    prompt_version="investigation-v1",
                )
        else:
            log.add(
                "investigation",
                "not_selected",
                "the deterministic selection policy did not select this finding",
            )
        log.add(
            "investigation",
            investigation_status,
            f"{budgeted.calls_used} model call(s) used",
        )

        # --- 6. evidence bundle over HTTP -----------------------------------
        token = mint_token(
            options.reviewer_secret,
            principal_id="staging-e2e-runner",
            tenant_ids=[options.tenant_id],
            roles=[Role.REVIEWER],
        )
        bundle: dict[str, Any] = {}
        bundle_error = ""
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
            try:
                response = await client.get(
                    f"{options.api_base_url.rstrip('/')}/v1/findings/{finding.id}/bundle",
                    params={"tenant_id": str(options.tenant_id)},
                    headers={"authorization": f"Bearer {token}"},
                )
                if response.status_code == 200:
                    bundle = response.json()
                    log.add(
                        "evidence_bundle", "fetched", f"bundle_hash={bundle.get('bundle_hash')}"
                    )
                else:
                    bundle_error = f"HTTP {response.status_code}"
                    log.add("evidence_bundle", "failed", bundle_error)
            except httpx.HTTPError as exc:
                bundle_error = (
                    f"the API at {options.api_base_url} is unreachable: {type(exc).__name__}"
                )
                log.add("evidence_bundle", "failed", bundle_error)

        stored = await repositories.findings.get(options.tenant_id, finding.id)
        status_after_investigation = stored.status if stored is not None else "UNKNOWN"

        report = _build_report(
            options=options,
            log=log,
            started_at=started_at,
            record=record,
            source_event_id=source_event.event_id,
            ingest_outcome=ingest_outcome.value,
            webhook_result=webhook_result,
            finding=finding,
            status_before_investigation=status_before_investigation,
            status_after_investigation=status_after_investigation,
            investigation_status=investigation_status,
            proposal=proposal,
            model_calls_used=budgeted.calls_used,
            llm_budget_calls=options.llm_budget_calls,
            bundle=bundle,
            bundle_error=bundle_error,
            model_failure=budgeted.failure,
            debug_path=budgeted.debug_path,
        )
        exit_code = 0
        if budgeted.failure is not None:
            # A model failure ends the run: no retry loop, no silent continue.
            exit_code = 1
        # A missing evidence bundle is recorded, not fatal: the bundle is an
        # observation, and the API may not have the evidence-reference store
        # wired (it then answers 503). The core rehearsal result stands.
        return report, exit_code
    finally:
        if consumer is not None:
            await consumer.close()
        if publisher is not None:
            await publisher.close()
        if model is not None:
            await model.aclose()
        await pool.close()


def _build_report(
    *,
    options: StagingOptions,
    log: RunLog,
    started_at: datetime,
    record: dict[str, Any],
    source_event_id: UUID,
    ingest_outcome: str,
    webhook_result: dict[str, Any],
    finding: Finding,
    status_before_investigation: str,
    status_after_investigation: str,
    investigation_status: str,
    proposal: InvestigationProposal | None,
    model_calls_used: int,
    llm_budget_calls: int,
    bundle: dict[str, Any],
    bundle_error: str,
    model_failure: Exception | None,
    debug_path: Path | None,
) -> dict[str, Any]:
    """Assemble the run report. It states what the run does and does not prove."""
    proposal_json = (
        {
            "hypothesis": proposal.hypothesis,
            "supporting_evidence": [str(x) for x in proposal.supporting_evidence],
            "contradicting_evidence": [str(x) for x in proposal.contradicting_evidence],
            "missing_evidence": list(proposal.missing_evidence),
            "uncertainty": proposal.uncertainty,
            "recommended_disposition": proposal.recommended_disposition,
        }
        if proposal is not None
        else None
    )
    notes: list[str] = []
    if bundle_error:
        notes.append(
            "the evidence bundle could not be fetched: "
            f"{bundle_error}. The API answers 503 when the evidence-reference "
            "store is not wired into the process; the rehearsal records this "
            "and continues."
        )
    if investigation_status == "SKIPPED":
        notes.append(
            "the deterministic selection policy did not select this finding for "
            "an investigation, so no model call was made"
        )
    return {
        "run": {
            "started_at": started_at.isoformat(),
            "finished_at": datetime.now(tz=UTC).isoformat(),
            "mode": "in-process" if options.in_process else "external-consumer",
            "tenant_id": str(options.tenant_id),
            "api_base_url": options.api_base_url,
            "model": options.groq_model,
            "llm_budget_calls": llm_budget_calls,
        },
        "steps": log.steps,
        "source_event": {
            "event_id": str(source_event_id),
            "source": "cloudtrail",
            "event_type": record.get("eventName"),
            "ingest_outcome": ingest_outcome,
        },
        "webhook_ingest": webhook_result,
        "detection": {
            "finding_id": str(finding.id),
            "finding_type": finding.finding_type,
            "severity": str(finding.severity),
            "outcome": finding.outcome,
            "risk_score": finding.risk_score,
            "status_before_investigation": status_before_investigation,
            "status_after_investigation": status_after_investigation,
        },
        "investigation": {
            "status": investigation_status,
            "model_calls_used": model_calls_used,
            "llm_budget_calls": llm_budget_calls,
            "proposal": proposal_json,
            "model_failure": None if model_failure is None else str(model_failure),
            "debug_dump": None if debug_path is None else str(debug_path),
        },
        "evidence_bundle": bundle,
        "evidence_bundle_error": bundle_error,
        "notes": notes,
        "statements": {
            "proposal_is_advisory": (
                "The model's proposal is ADVISORY. It is stored verbatim in the "
                "investigation ledger and is never applied to the finding lifecycle; "
                "deterministic policy and a human reviewer remain authoritative."
            ),
            "finding_status_unchanged_by_model": (
                status_before_investigation == status_after_investigation
            ),
            "finding_status_before": status_before_investigation,
            "finding_status_after": status_after_investigation,
            "model_calls_used": model_calls_used,
            "what_this_run_does_not_prove": [
                "The source event is a simulated CloudTrail record, not a real "
                "AWS API call; no cloud account was involved.",
                "The model PROPOSES. It cannot authorize an action, cannot change "
                "a finding status, and cannot run a command.",
                "No independent verification of a real finding was performed: the "
                "rehearsal stops at the proposal and the evidence bundle.",
                "No production credentials were used; every secret came from the "
                "operator's environment.",
                "The finding carries no evidence references yet, so the model was "
                "given the question only and no evidence ids to reference.",
                "The LLM budget bounds the number of real, billed model calls; it "
                "is not a quality or accuracy guarantee.",
            ],
        },
    }


def _print_summary(report: dict[str, Any]) -> None:
    """Print a short human summary of the run."""
    detection = report["detection"]
    investigation = report["investigation"]
    statements = report["statements"]
    print("")
    print("=== staging end-to-end rehearsal ===")
    print(f"tenant            : {report['run']['tenant_id']}")
    print(f"mode              : {report['run']['mode']}")
    print(f"finding           : {detection['finding_id']} ({detection['finding_type']})")
    print(
        f"finding status    : {detection['status_before_investigation']} -> "
        f"{detection['status_after_investigation']}"
    )
    print(f"investigation     : {investigation['status']}")
    print(
        f"model calls used  : {investigation['model_calls_used']} "
        f"(budget {investigation['llm_budget_calls']})"
    )
    if investigation.get("proposal"):
        print("proposal          : ADVISORY -- not applied to the finding lifecycle")
    else:
        print("proposal          : none recorded (the stage did not complete)")
    if report.get("evidence_bundle_error"):
        print(f"evidence bundle   : NOT FETCHED -- {report['evidence_bundle_error']}")
    else:
        print("evidence bundle   : fetched")
    if investigation.get("debug_dump"):
        print(f"model debug dump  : {investigation['debug_dump']}")
    print("")
    print("This run does NOT prove:")
    for item in statements["what_this_run_does_not_prove"]:
        print(f"  - {item}")
    print("")
    print(f"report: {report.get('report_path', 'see --report-path')}")


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=("Manual staging rehearsal. Makes REAL (billed) model calls. Not part of CI.")
    )
    parser.add_argument(
        "--api-base-url",
        default=os.environ.get("ITSM_API_BASE_URL", "http://127.0.0.1:8000"),
        help="Base URL of the running API (default: %(default)s).",
    )
    parser.add_argument(
        "--report-path",
        default=str(DEFAULT_REPORT_PATH),
        help="Where to write the JSON run report (default: %(default)s).",
    )
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=DEFAULT_POLL_SECONDS,
        help="How long to wait for the finding to appear (default: %(default)s).",
    )
    parser.add_argument(
        "--llm-budget-calls",
        type=int,
        default=None,
        help="Hard cap on real model calls (default: ITSM_INVESTIGATION_LLM_BUDGET_CALLS or 3).",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--in-process",
        dest="in_process",
        action="store_true",
        default=True,
        help="Drive the audit consumer in-process (default).",
    )
    mode.add_argument(
        "--external-consumer",
        dest="in_process",
        action="store_false",
        help="Wait for a separately running 'python -m itsm_agent.workers.audit_consumer'.",
    )
    return parser.parse_args(list(argv))


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns the process exit code."""
    args = _parse_args(list(argv) if argv is not None else sys.argv[1:])
    env = os.environ

    missing = missing_requirements(env)
    if missing:
        print("staging rehearsal preflight FAILED. Missing configuration:", file=sys.stderr)
        for item in missing:
            print(f"  - {item}", file=sys.stderr)
        print(
            "No network call was made. See docs/runbooks/SOP-06-staging-e2e-run.md.",
            file=sys.stderr,
        )
        return 2

    budget = args.llm_budget_calls
    if budget is None:
        raw_budget = (
            env.get("ITSM_INVESTIGATION_LLM_BUDGET_CALLS") or str(DEFAULT_LLM_BUDGET_CALLS)
        ).strip()
        try:
            budget = int(raw_budget)
        except ValueError:
            budget = DEFAULT_LLM_BUDGET_CALLS
    if budget < 1:
        print("staging rehearsal preflight FAILED: the LLM budget must be >= 1", file=sys.stderr)
        return 2

    options = StagingOptions(
        env=env,
        api_base_url=args.api_base_url,
        report_path=Path(args.report_path),
        in_process=args.in_process,
        tenant_id=uuid.uuid4(),
        poll_seconds=args.poll_seconds,
        llm_budget_calls=budget,
    )

    try:
        report, exit_code = asyncio.run(run_staging(options))
    except StagingRunError as exc:
        print(f"staging rehearsal FAILED: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - operator tool boundary
        print(f"staging rehearsal crashed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    report["report_path"] = str(options.report_path)
    options.report_path.parent.mkdir(parents=True, exist_ok=True)
    options.report_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    _print_summary(report)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
