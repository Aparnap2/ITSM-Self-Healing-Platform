"""Ingestion boundary security primitives (FR-01).

- HMAC-SHA256 webhook signature verification over the raw request body
  (constant-time compare).
- Replay detection: a signature is bound to the body; a seen
  (signature, body-hash) pair within the replay window is rejected.
- Payload size enforcement before parsing.
- In-process sliding-window rate limiter keyed by client identity.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from collections import deque
from dataclasses import dataclass, field


class SecurityRejection(Exception):
    """Base for security rejections; maps to an HTTP status at the route."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class MissingSignatureError(SecurityRejection):
    def __init__(self) -> None:
        super().__init__("MISSING_SIGNATURE", "Signature header missing")


class InvalidSignatureError(SecurityRejection):
    def __init__(self) -> None:
        super().__init__("INVALID_SIGNATURE", "Signature verification failed")


class ReplayedSignatureError(SecurityRejection):
    def __init__(self) -> None:
        super().__init__("REPLAYED_SIGNATURE", "Signature already used")


class PayloadTooLargeError(SecurityRejection):
    def __init__(self, max_bytes: int) -> None:
        super().__init__("PAYLOAD_TOO_LARGE", f"Body exceeds {max_bytes} bytes")
        self.max_bytes = max_bytes


class RateLimitExceededError(SecurityRejection):
    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("RATE_LIMITED", "Rate limit exceeded")
        self.retry_after_seconds = retry_after_seconds


def compute_signature(secret: str, body: bytes) -> str:
    """Hex HMAC-SHA256 of the raw body with the shared secret."""
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def verify_signature(
    *, secret: str, body: bytes, provided: str | None, max_body_bytes: int
) -> None:
    """Verify size + signature; raise typed SecurityRejection on failure.

    Accepts the signature with or without a ``sha256=`` prefix.
    """
    if len(body) > max_body_bytes:
        raise PayloadTooLargeError(max_body_bytes)
    if not provided:
        raise MissingSignatureError()
    expected = compute_signature(secret, body)
    candidate = provided.strip().lower()
    if candidate.startswith("sha256="):
        candidate = candidate[len("sha256=") :]
    if not hmac.compare_digest(expected, candidate):
        raise InvalidSignatureError()


@dataclass
class ReplayCache:
    """Bounded cache of recently seen signature digests."""

    max_entries: int = 4096
    _seen: deque[str] = field(default_factory=deque)
    _seen_set: set[str] = field(default_factory=set)

    def check_and_record(self, signature: str) -> bool:
        """Return True if the signature is new; record it either way."""
        if signature in self._seen_set:
            return False
        self._seen.append(signature)
        self._seen_set.add(signature)
        while len(self._seen) > self.max_entries:
            old = self._seen.popleft()
            self._seen_set.discard(old)
        return True


class SlidingWindowRateLimiter:
    """In-process sliding-window limiter keyed by client identity."""

    def __init__(self, max_requests: int, window_seconds: float) -> None:
        self._max = max_requests
        self._window = window_seconds
        self._hits: dict[str, deque[float]] = {}

    def check(self, client_key: str, *, now: float | None = None) -> None:
        """Raise RateLimitExceededError if the client is over budget."""
        current = time.monotonic() if now is None else now
        bucket = self._hits.setdefault(client_key, deque())
        cutoff = current - self._window
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= self._max:
            retry_after = int(max(1, bucket[0] + self._window - current)) + 1
            raise RateLimitExceededError(retry_after)
        bucket.append(current)


__all__ = [
    "InvalidSignatureError",
    "MissingSignatureError",
    "PayloadTooLargeError",
    "RateLimitExceededError",
    "ReplayCache",
    "ReplayedSignatureError",
    "SecurityRejection",
    "SlidingWindowRateLimiter",
    "compute_signature",
    "verify_signature",
]
