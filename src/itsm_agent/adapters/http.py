"""Shared HTTP client base for outbound adapters.

Enforces the adapter boundary rules:

- Only allowlisted URL origins (from Settings) may be called.
- Every request has a bounded timeout.
- Retries are bounded (tenacity, max ``adapter_max_retries``) and only
  for transient conditions (connection errors, 5xx, 429).
- Every response body is returned as parsed JSON for the caller to
  validate with Pydantic — adapters never return raw dicts to domain
  code.

Note: this shared helper sits inside the adapters boundary owned by this
task (itsm/identity/infrastructure/llm adapters all use it).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

import httpx
from tenacity import (
    AsyncRetrying,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)


class AdapterError(Exception):
    """Base error for adapter failures (fail-closed callers)."""


class AdapterUnavailableError(AdapterError):
    """Target endpoint unreachable, timed out, or returned 5xx after retries."""


class EndpointNotAllowedError(AdapterError):
    """Attempted call to a non-allowlisted origin or path."""


class UnexpectedResponseError(AdapterError):
    """Response could not be parsed/validated as the expected contract."""


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _split_template(template: str) -> list[str]:
    # Split keeping brace groups as single tokens.
    import re as _re

    return _re.findall(r"\{[^}]*\}|[^{]+", template)


class AllowlistedHttpClient:
    """httpx.AsyncClient wrapper with origin allowlist + bounded retries."""

    def __init__(
        self,
        *,
        base_url: str,
        allowed_paths: tuple[str, ...],
        timeout_seconds: float,
        max_retries: int,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self._base_origin = _origin(base_url)
        self._base_url = base_url.rstrip("/")
        self._allowed_paths = frozenset(allowed_paths)
        self._timeout = timeout_seconds
        self._max_retries = max_retries
        self._headers = {"accept": "application/json", **(extra_headers or {})}
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=httpx.Timeout(timeout_seconds),
            headers=self._headers,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    def _check_url(self, path: str) -> str:
        if not path.startswith("/"):
            raise EndpointNotAllowedError(f"Relative path required, got: {path!r}")
        for template in self._allowed_paths:
            regex = (
                "^"
                + "".join(
                    r"[^/]+" if part.startswith("{") and part.endswith("}") else re.escape(part)
                    for part in _split_template(template)
                )
                + "$"
            )
            if re.fullmatch(regex, path):
                return path
        raise EndpointNotAllowedError(f"Endpoint not allowlisted: {path}")

    def _is_transient(self, exc: BaseException) -> bool:
        if isinstance(exc, (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteError)):
            return True
        if isinstance(exc, httpx.HTTPStatusError):
            status = exc.response.status_code
            return status == 429 or status >= 500
        return False

    async def request_json(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Perform an allowlisted request, return parsed JSON object."""
        checked = self._check_url(path)
        # Verify final origin matches the allowlisted base origin.
        if _origin(str(self._client.base_url)) != self._base_origin:
            raise EndpointNotAllowedError("Base URL origin mismatch")

        async def _attempt() -> dict[str, Any]:
            response = await self._client.request(method, checked, json=json_body, params=params)
            response.raise_for_status()
            try:
                parsed: Any = response.json()
            except ValueError as exc:
                raise UnexpectedResponseError(f"Non-JSON response from {checked}") from exc
            if not isinstance(parsed, dict):
                raise UnexpectedResponseError(
                    f"Expected JSON object from {checked}, got {type(parsed).__name__}"
                )
            return parsed

        try:
            result: dict[str, Any] | None = None
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(max(1, self._max_retries + 1)),
                wait=wait_exponential(multiplier=0.1, max=1.0),
                retry=retry_if_exception(self._is_transient),
                reraise=True,
            ):
                with attempt:
                    result = await _attempt()
            if result is None:
                raise AdapterUnavailableError(f"{method} {checked} produced no result")
            return result
        except httpx.HTTPStatusError as exc:
            raise AdapterUnavailableError(
                f"{method} {checked} failed with HTTP {exc.response.status_code}"
            ) from exc
        except (httpx.HTTPError, OSError) as exc:
            raise AdapterUnavailableError(
                f"{method} {checked} unreachable: {type(exc).__name__}"
            ) from exc


__all__ = [
    "AdapterError",
    "AdapterUnavailableError",
    "AllowlistedHttpClient",
    "EndpointNotAllowedError",
    "UnexpectedResponseError",
]
