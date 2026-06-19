"""Keycloak OAuth2 token exchange (RFC 8693) for crawling as the caller.

The caller authenticates to this API with a Keycloak access token whose audience
is *this* service (``KEYCLOAK_AUDIENCE``). To let the crawler act as the caller
against a scan's ``start_url`` we must not replay that token to the target: its
audience is wrong, and a long crawl outlives its short TTL. Instead we exchange
it for a token whose audience is the target app, then refresh that token for the
duration of the (detached, background) crawl.

Configuration (all required to enable exchange; if any is unset, crawls run
unauthenticated and no Authorization header is injected):

* ``KEYCLOAK_ISSUER``               - realm issuer (already used by api.security)
* ``KEYCLOAK_CRAWLER_CLIENT_ID``    - confidential client the crawler authenticates as
* ``KEYCLOAK_CRAWLER_CLIENT_SECRET``- its secret
* ``KEYCLOAK_TARGET_AUDIENCE``      - requested audience for the exchanged token

The crawler client must be permitted (in Keycloak) to exchange to
``KEYCLOAK_TARGET_AUDIENCE``, and the realm must have token exchange enabled.
"""
import asyncio
import logging
import os
import time
from dataclasses import dataclass
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

_ISSUER = os.environ.get("KEYCLOAK_ISSUER", "").rstrip("/")
_TOKEN_URL = f"{_ISSUER}/protocol/openid-connect/token" if _ISSUER else ""
_CLIENT_ID = os.environ.get("KEYCLOAK_CRAWLER_CLIENT_ID", "")
_CLIENT_SECRET = os.environ.get("KEYCLOAK_CRAWLER_CLIENT_SECRET", "")
_TARGET_AUDIENCE = os.environ.get("KEYCLOAK_TARGET_AUDIENCE", "")

_GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
_TOKEN_TYPE_ACCESS = "urn:ietf:params:oauth:token-type:access_token"

# Refresh once the current token is within this many seconds of expiry.
_EXPIRY_SKEW_SECONDS = 30
# Floor applied if the IdP omits expires_in, so we still refresh proactively.
_DEFAULT_EXPIRES_IN = 60


class TokenExchangeError(RuntimeError):
    """Raised when the IdP refuses the exchange/refresh or is unreachable."""


def token_exchange_configured() -> bool:
    """True iff every env var needed to perform an exchange is set."""
    return bool(_TOKEN_URL and _CLIENT_ID and _CLIENT_SECRET and _TARGET_AUDIENCE)


@dataclass
class _Token:
    access_token: str
    expires_at: float  # time.monotonic() deadline
    refresh_token: Optional[str]


async def _post_token(data: dict) -> _Token:
    body = {**data, "client_id": _CLIENT_ID, "client_secret": _CLIENT_SECRET}
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                _TOKEN_URL, data=body, headers={"Accept": "application/json"}
            )
    except httpx.HTTPError as exc:
        raise TokenExchangeError(f"token endpoint unreachable: {exc}") from exc

    if resp.status_code != 200:
        # error_description may name the misconfiguration (e.g. exchange not
        # permitted to this audience); the body carries no usable token.
        raise TokenExchangeError(
            f"token endpoint returned {resp.status_code}: {resp.text[:300]}"
        )

    payload = resp.json()
    access = payload.get("access_token")
    if not access:
        raise TokenExchangeError("token response missing access_token")
    expires_in = int(payload.get("expires_in") or _DEFAULT_EXPIRES_IN)
    return _Token(
        access_token=access,
        expires_at=time.monotonic() + expires_in,
        refresh_token=payload.get("refresh_token"),
    )


async def _exchange(subject_token: str, audience: str) -> _Token:
    return await _post_token(
        {
            "grant_type": _GRANT_TOKEN_EXCHANGE,
            "subject_token": subject_token,
            "subject_token_type": _TOKEN_TYPE_ACCESS,
            "requested_token_type": _TOKEN_TYPE_ACCESS,
            "audience": audience,
        }
    )


async def _refresh(refresh_token: str) -> _Token:
    return await _post_token(
        {"grant_type": "refresh_token", "refresh_token": refresh_token}
    )


class CrawlTokenProvider:
    """A target-audience token for one crawl, renewed on demand.

    Built by exchanging the caller's inbound token once, synchronously, so an
    exchange failure surfaces to the API caller rather than silently breaking
    the background job. The crawl then outlives the request, so ``get_token``
    refreshes (via the refresh token, when the IdP issued one) as expiry nears.
    If it cannot refresh once expired it returns the stale token and lets the
    target reject it, rather than crashing the crawl.
    """

    def __init__(self, token: _Token, audience: str) -> None:
        self._token = token
        self._audience = audience
        self._lock = asyncio.Lock()
        self._warned_no_refresh = False

    @classmethod
    async def create(
        cls, subject_token: str, *, audience: str = ""
    ) -> "CrawlTokenProvider":
        if not token_exchange_configured():
            raise TokenExchangeError("token exchange is not configured")
        aud = audience or _TARGET_AUDIENCE
        token = await _exchange(subject_token, aud)
        return cls(token, aud)

    async def get_token(self) -> str:
        async with self._lock:
            if time.monotonic() < self._token.expires_at - _EXPIRY_SKEW_SECONDS:
                return self._token.access_token
            if self._token.refresh_token:
                try:
                    self._token = await _refresh(self._token.refresh_token)
                    return self._token.access_token
                except TokenExchangeError as exc:
                    logger.warning("crawl token refresh failed: %s", exc)
            elif not self._warned_no_refresh:
                self._warned_no_refresh = True
                logger.warning(
                    "exchanged token expiring and no refresh token was issued; "
                    "target requests may start failing with 401"
                )
            return self._token.access_token
