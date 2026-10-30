"""Redaction helpers (Task 15). Pure, deterministic."""

from __future__ import annotations

import re


def redact_secrets(text: str) -> str:
    # AWS keys
    text = re.sub(r"AKIA[0-9A-Z]{16}", "[REDACTED_AWS_KEY]", text)
    # Bearer tokens
    text = re.sub(r"Bearer\s+[A-Za-z0-9._-]+", "Bearer [REDACTED]", text)
    # Generic password=/secret=/token= assignments
    text = re.sub(r"(?i)(password|secret|token|api[_-]?key)\s*=\s*\S+", r"\1=[REDACTED]", text)
    # Email addresses
    text = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[REDACTED_EMAIL]", text)
    return text


__all__ = ["redact_secrets"]
