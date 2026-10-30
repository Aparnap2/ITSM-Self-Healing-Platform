"""Unit tests for redaction (no I/O)."""

from __future__ import annotations

import pytest

from itsm_agent.privacy.redaction import redact_secrets


def test_redact_aws_key() -> None:
    out = redact_secrets("key AKIAIOSFODNN7EXAMPLE here")
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "[REDACTED_AWS_KEY]" in out


def test_redact_email() -> None:
    out = redact_secrets("user alice@example.com logged in")
    assert "alice@example.com" not in out
    assert "[REDACTED_EMAIL]" in out


def test_redact_password() -> None:
    out = redact_secrets("password=hunter2")
    assert "hunter2" not in out


def test_redact_token() -> None:
    out = redact_secrets("Bearer abc.def.ghi")
    assert "abc.def.ghi" not in out


pytestmark = pytest.mark.unit
