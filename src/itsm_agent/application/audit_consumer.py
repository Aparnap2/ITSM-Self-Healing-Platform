"""Security-audit consumer: durable detection over source events.

Consumes SourceEvent messages from NATS JetStream, runs deterministic
detection (including approval evidence) and persists findings. Idempotent on
(tenant, source, event, processing_version) via PostgreSQL.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from itsm_agent.adapters.messaging.nats_bus import JetStreamConsumer
from itsm_agent.adapters.persistence.repositories import (
    PsycopgEvidenceReferenceRepository,
    PsycopgFindingRepository,
    PsycopgProcessingRecordRepository,
    PsycopgSourceEventRepository,
)
from itsm_agent.adapters.persistence.tenant import tenant_transaction
from itsm_agent.domain.events import InvestigationRequest, SourceEvent
from itsm_agent.domain.investigation_policy import should_investigate
from itsm_agent.domain.models import EvidenceReference, Finding
from itsm_agent.investigations.service import EvidenceFetcher
from itsm_agent.privacy.redaction import redact_secrets

logger = logging.getLogger(__name__)

PROCESSING_VERSION = "detection-v1"

#: Trust level recorded on evidence produced by the detection pipeline. The
#: sources are simulators and collectors, so the evidence is an observation,
#: never an independent verification.
DEFAULT_EVIDENCE_TRUST_LEVEL = "SIMULATOR_OBSERVATION"

#: Actor recorded on investigation requests raised by the detection pipeline.
INVESTIGATION_REQUESTER = "detection-pipeline"


def build_evidence_source(pool: Any) -> EvidenceFetcher:
    """Request-scoped evidence resolver for the investigation stage.

    The model must reason about the evidence that produced the finding, not
    about a bare question. For every id in the request's snapshot this returns
    a bounded summary: the finding's evidence reference when one exists, and
    otherwise the canonical source event itself (id, type, actor, resource,
    outcome and payload hash). Nothing else is exposed, and the caller
    (the service) redacts and truncates every summary.
    """
    evidence_repo = PsycopgEvidenceReferenceRepository(pool)
    source_repo = PsycopgSourceEventRepository(pool)

    async def fetch(request: InvestigationRequest, ids: Sequence[UUID]) -> dict[UUID, str]:
        summaries: dict[UUID, str] = {}
        if not ids:
            return summaries
        references = await evidence_repo.list_for_tenant_finding(
            request.tenant_id, request.finding_id
        )
        by_id = {ref.id: ref for ref in references}
        for evidence_id in ids:
            reference = by_id.get(evidence_id)
            if reference is not None:
                summaries[evidence_id] = (
                    f"evidence_reference:{reference.trust_level}:"
                    f"{reference.excerpt or reference.content_hash}"
                )
                continue
            event = await source_repo.get_for_tenant(request.tenant_id, evidence_id)
            if event is None:
                continue
            summaries[evidence_id] = (
                f"source_event:{event.source}:{event.event_type}:"
                f"actor={event.actor_id or event.principal_id}:"
                f"resource={event.resource_id}:outcome={event.outcome}:"
                f"hash={event.payload_hash}"
            )
        return summaries

    return fetch


#: Maximum length of the stored evidence excerpt. The excerpt is a summary of
#: the source event, not the event itself: raw payloads stay in the immutable
#: source store and are referenced by hash.
MAX_EVIDENCE_EXCERPT_CHARS = 500


def _evidence_reference(event: SourceEvent, finding: Finding) -> EvidenceReference:
    """Build the evidence reference that anchors a finding to its source event.

    The content hash is the canonical event's payload hash, so the reference
    is verifiable against the immutable source record. The excerpt is a
    bounded, redacted summary: it describes what happened without carrying
    secret material into a reviewer-visible surface.
    """
    summary = (
        f"source={event.source}; type={event.event_type}; "
        f"actor={event.actor_id or event.principal_id}; "
        f"resource={event.resource_id}; outcome={event.outcome}; "
        f"hash={event.payload_hash}"
    )
    return EvidenceReference(
        id=uuid4(),
        finding_id=finding.id,
        source_event_id=event.event_id,
        access_fact_id=None,
        content_hash=event.payload_hash,
        excerpt=redact_secrets(summary)[:MAX_EVIDENCE_EXCERPT_CHARS],
        trust_level=DEFAULT_EVIDENCE_TRUST_LEVEL,
        collected_at=event.event_time,
    )


async def _run_investigation_stage(
    *,
    tenant_id: UUID,
    findings: list[Finding],
    service: Any | None,
    enabled: bool,
    source_event: SourceEvent | None = None,
) -> None:
    """Run the optional agentic investigation stage for selected findings.

    The stage is advisory and optional. Detection is the source of truth, so a
    failure here is logged and swallowed: it must never undo or hide the
    deterministic detection result. Each request is written in its own
    tenant-scoped transaction (inside the ledger repository), after the
    detection transaction has committed.

    The evidence snapshot is the canonical source event that produced the
    finding, so the model has real context to reason about and the
    orchestrator's evidence-reference validation is exercised (a proposal may
    only cite ids that are in the snapshot).
    """
    if service is None:
        logger.warning("investigation stage enabled but no service configured; skipping")
        return
    snapshot_ids: tuple[UUID, ...] = ()
    if source_event is not None:
        snapshot_ids = (source_event.event_id,)
    for finding in findings:
        if not should_investigate(finding, enabled=enabled):
            continue
        try:
            await service.investigate_finding(
                tenant_id=tenant_id,
                finding=finding,
                evidence_snapshot_ids=snapshot_ids,
                requested_by=INVESTIGATION_REQUESTER,
            )
        except Exception as exc:  # noqa: BLE001 - detection stays authoritative
            logger.warning("investigation stage failed for finding %s: %s", finding.id, exc)


async def process_source_event(
    *,
    event: SourceEvent,
    pool: Any,
    findings_repo: PsycopgFindingRepository,
    processing_repo: PsycopgProcessingRecordRepository,
    approvals: list[object] | None = None,
    covered_sources: object = None,
    source_coverage: object = None,
    processing_version: str = PROCESSING_VERSION,
    clock_now: Callable[[], datetime],
    investigation_enabled: bool = False,
    investigation_service: Any | None = None,
) -> tuple[bool, list[UUID]]:
    """Process one source event into findings. Returns (already_processed, finding_ids).

    Idempotent: a COMPLETED processing record short-circuits. All writes happen
    in a single PostgreSQL transaction.

    The optional investigation stage (``investigation_enabled``) runs AFTER that
    transaction commits, in its own tenant-scoped transaction, so a failed
    investigation can never roll back detection.
    """
    from itsm_agent.detection.engine import run_detection

    # Tenant validation + all writes run inside one transaction-local tenant
    # context, so every tenant-scoped read/write is covered by RLS. The
    # canonical event is re-read under the SENDER's tenant; the message cannot
    # override canonical tenant identity.
    src_repo = PsycopgSourceEventRepository(pool)
    evidence_repo = PsycopgEvidenceReferenceRepository(pool)
    failure: Exception | None = None
    result: tuple[bool, list[UUID]] = (False, [])
    persisted_findings: list[Finding] = []
    async with tenant_transaction(pool, event.tenant_id) as conn:
        canonical = await src_repo.get_for_tenant(
            event.tenant_id,
            event.event_id,
            conn=conn,
        )
        if canonical is None:
            raise ValueError(f"unknown source event for tenant: {event.event_id}")
        # Defense in depth: a row read under the sender's tenant can no longer
        # disagree, but keep the explicit check in case the read path changes.
        if canonical.tenant_id != event.tenant_id:
            raise ValueError(
                f"tenant mismatch for event {event.event_id}: "
                f"message={event.tenant_id} canonical={canonical.tenant_id}"
            )
        tenant_id = canonical.tenant_id
        source = canonical.source

        status, record_id = await processing_repo.claim(
            tenant_id=tenant_id,
            source=source,
            event_id=canonical.event_id,
            processing_version=processing_version,
            conn=conn,
        )
        if status == "COMPLETED":
            # Already processed; do not re-run detection or create findings.
            result = (True, [])
        elif status == "PROCESSING":
            # Another worker holds the slot; let the caller retry.
            raise RuntimeError("processing in progress; retry later")
        else:
            # status NEW or FAILED -> proceed.
            assert record_id is not None
            try:
                findings = run_detection(
                    [canonical],
                    approvals=approvals,
                    covered_sources=covered_sources,
                    source_coverage=source_coverage,
                    now=clock_now(),
                )
                finding_ids: list[UUID] = []
                for f in findings:
                    persisted = await findings_repo.upsert(f, conn=conn)
                    finding_ids.append(persisted.id)
                    # The persisted finding is authoritative: ``upsert`` may
                    # return a different id when the finding already exists.
                    persisted_findings.append(persisted)
                    # The evidence that justifies the finding is persisted in
                    # the SAME transaction: a finding never lands without the
                    # reference that anchors it to the source event.
                    await evidence_repo.insert(
                        _evidence_reference(canonical, persisted),
                        tenant_id=tenant_id,
                        conn=conn,
                    )
                await processing_repo.complete(
                    record_id,
                    finding_ids,
                    tenant_id=tenant_id,
                    conn=conn,
                )
                result = (False, finding_ids)
            except Exception as exc:  # noqa: BLE001
                # Persist the FAILED record in the same tenant transaction, then
                # re-raise AFTER the transaction commits (raising here would roll
                # the failure record back).
                failure = exc
                await processing_repo.fail(
                    record_id,
                    str(exc),
                    tenant_id=tenant_id,
                    conn=conn,
                )
    if failure is not None:
        raise failure
    if investigation_enabled and not result[0]:
        # Runs AFTER the detection transaction committed, in its own
        # tenant-scoped transaction.
        await _run_investigation_stage(
            tenant_id=tenant_id,
            findings=persisted_findings,
            service=investigation_service,
            enabled=investigation_enabled,
            source_event=canonical,
        )
    return result


async def consume_source_event(
    *,
    consumer: JetStreamConsumer,
    pool: Any,
    findings_repo: PsycopgFindingRepository,
    processing_repo: PsycopgProcessingRecordRepository,
    approvals: list[object] | None = None,
    covered_sources: object = None,
    source_coverage: object = None,
    processing_version: str = PROCESSING_VERSION,
    clock_now: Callable[[], datetime],
    investigation_enabled: bool = False,
    investigation_service: Any | None = None,
    max_deliver: int = 5,
    timeout_seconds: float = 1.0,
) -> str:
    """Fetch and process one source-event message. Returns outcome string."""
    msgs = await consumer.fetch(timeout_seconds=timeout_seconds, batch=1)
    if not msgs:
        return "none"
    message = msgs[0]
    # --- validate envelope --------------------------------------------------
    try:
        raw = json.loads(message.payload.decode("utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("envelope must be a JSON object")
        payload = raw.get("payload", raw)
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        event = SourceEvent.model_validate(payload)
    except Exception as exc:  # noqa: BLE001
        logger.warning("poison message on %s: %s", message.subject, exc)
        await consumer.dead_letter(message, error=f"invalid envelope: {exc}")
        return "poison"

    # --- durable processing -------------------------------------------------
    try:
        already, _ = await process_source_event(
            event=event,
            pool=pool,
            findings_repo=findings_repo,
            processing_repo=processing_repo,
            approvals=approvals,
            covered_sources=covered_sources,
            source_coverage=source_coverage,
            processing_version=processing_version,
            clock_now=clock_now,
            investigation_enabled=investigation_enabled,
            investigation_service=investigation_service,
        )
    except RuntimeError as exc:
        # Retryable (processing in progress / transient).
        if message.delivery_attempt >= max_deliver:
            await consumer.dead_letter(message, error=str(exc))
            return "dead_lettered"
        await consumer.nak(message, delay_seconds=0.5)
        return "retry"
    except Exception as exc:  # noqa: BLE001
        if message.delivery_attempt >= max_deliver:
            await consumer.dead_letter(message, error=str(exc))
            return "dead_lettered"
        await consumer.nak(message, delay_seconds=0.5)
        return "retry"

    await consumer.ack(message)
    return "duplicate" if already else "processed"


__all__ = ["PROCESSING_VERSION", "consume_source_event", "process_source_event"]
