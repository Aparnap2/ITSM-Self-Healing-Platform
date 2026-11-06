#!/usr/bin/env python3
"""Deterministic DAST target for the API security surface.

This is **not** a production server. It composes the real ``create_app``
factory, the real HMAC ingestion boundary, the real authenticator, and the
real security-headers middleware with in-memory fake persistence. It exists so
an isolated OWASP ZAP baseline scan can exercise HTTP behaviour that unit tests
cannot see (missing headers, error handling, method handling).

Secrets are generated per process; nothing sensitive is checked in. The server
binds 127.0.0.1 only.
"""

from __future__ import annotations

import os
import secrets
import uuid

import uvicorn
from fastapi import FastAPI

from itsm_agent.api.app import create_app
from itsm_agent.api.auth import TokenAuthenticator
from itsm_agent.api.routes.ingestion import SinkOutcome
from itsm_agent.config import Settings
from itsm_agent.domain.models import Finding, ReviewDecision

HOST = "127.0.0.1"
PORT = int(os.environ.get("DAST_PORT", "8010"))
TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")


class InMemorySink:
    async def accept_incident(self, event: object) -> SinkOutcome:
        return SinkOutcome.ACCEPTED


class InMemoryFindings:
    def __init__(self) -> None:
        self._items: dict[uuid.UUID, Finding] = {}

    async def get(self, tenant_id: uuid.UUID, finding_id: uuid.UUID) -> Finding | None:
        finding = self._items.get(finding_id)
        if finding is None or finding.tenant_id != tenant_id:
            return None
        return finding

    async def list_for_tenant(self, tenant_id: uuid.UUID) -> list[Finding]:
        return [item for item in self._items.values() if item.tenant_id == tenant_id]


class InMemoryDecisions:
    async def record(self, decision: ReviewDecision) -> ReviewDecision:
        return decision

    async def list_for_finding(
        self, tenant_id: uuid.UUID, finding_id: uuid.UUID
    ) -> list[ReviewDecision]:
        return []


def _settings() -> Settings:
    return Settings.model_validate(
        {
            "env": "test",
            "api_host": HOST,
            "api_port": PORT,
            "webhook_secret": secrets.token_hex(32),
            "webhook_max_body_bytes": 4096,
            "rate_limit_requests": 120,
            "rate_limit_window_seconds": 60.0,
            "mockoon_itsm_base_url": "http://127.0.0.1:3001",
            "mockoon_identity_base_url": "http://127.0.0.1:3001",
            "mockoon_infrastructure_base_url": "http://127.0.0.1:3001",
        }
    )


def build_app() -> FastAPI:
    return create_app(
        settings=_settings(),
        sink=InMemorySink(),
        findings_repo=InMemoryFindings(),
        review_decisions_repo=InMemoryDecisions(),
        authenticator=TokenAuthenticator(secret=secrets.token_hex(32)),
    )


def main() -> None:
    uvicorn.run(build_app(), host=HOST, port=PORT, log_level="warning", access_log=False)


if __name__ == "__main__":
    main()
