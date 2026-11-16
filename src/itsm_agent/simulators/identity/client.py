"""Client helper for the LOCAL identity simulator.

The rehearsal runner needs a token from the simulator to authenticate against
the OIDC-configured API. This helper fetches one over TLS, pinning the
simulator's CA — verification is never disabled.
"""

from __future__ import annotations

import ssl

import httpx

#: Bounded token request: a simulator credential must not become a slow
#: dependency of a test run.
TOKEN_REQUEST_TIMEOUT_SECONDS = 10.0


def ca_context(ca_path: str) -> ssl.SSLContext:
    """An SSL context that trusts exactly the simulator's CA."""
    return ssl.create_default_context(cafile=ca_path)


async def fetch_token(
    *,
    base_url: str,
    subject: str,
    ca_path: str,
    ttl_seconds: int = 900,
) -> str:
    """Mint a token for ``subject`` from the simulator.

    Raises ``httpx.HTTPStatusError`` for an unknown subject and
    ``httpx.HTTPError`` when the simulator is unreachable.
    """
    async with httpx.AsyncClient(
        base_url=base_url,
        verify=ca_context(ca_path),
        timeout=httpx.Timeout(TOKEN_REQUEST_TIMEOUT_SECONDS),
        follow_redirects=False,
    ) as client:
        response = await client.post(
            "/token",
            json={"subject": subject, "ttl_seconds": ttl_seconds},
        )
        response.raise_for_status()
        payload = response.json()
    token = payload.get("access_token")
    if not isinstance(token, str) or not token:
        raise ValueError("the simulator returned no access token")
    return token


__all__ = ["TOKEN_REQUEST_TIMEOUT_SECONDS", "ca_context", "fetch_token"]
