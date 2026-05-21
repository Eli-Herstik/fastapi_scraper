import asyncio
import logging
import os
import time
from dataclasses import dataclass
from typing import Any

import httpx
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JOSEError, JWTError

from .models import CurrentUser

logger = logging.getLogger(__name__)

_KEYCLOAK_ISSUER = os.environ.get("KEYCLOAK_ISSUER", "").rstrip("/")
_oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{_KEYCLOAK_ISSUER}/protocol/openid-connect/auth",
    tokenUrl=f"{_KEYCLOAK_ISSUER}/protocol/openid-connect/token",
    refreshUrl=f"{_KEYCLOAK_ISSUER}/protocol/openid-connect/token",
    scopes={
        "openid": "OpenID Connect scope",
        "profile": "User profile",
        "email": "User email",
    },
)
_UNAUTHENTICATED_HEADERS = {"WWW-Authenticate": "Bearer"}

# Admin authorization is delegated to the AD Groups API: a caller is an admin
# iff they are a direct member of the configured gatekeeper-admin group. The
# token itself carries no group/role claim, so membership is checked live.
_AD_GROUPS_API_URL = os.environ.get("AD_GROUPS_API_URL", "http://localhost:8001").rstrip("/")
_GATEKEEPER_ADMIN_GROUP = os.environ.get("GATEKEEPER_ADMIN_GROUP", "Gatekeeper-Admins")
# AD group lookups are cached briefly to avoid hitting the AD Groups API on every
# guarded request. Sliding window since last read, capped by an absolute window
# since fetch (mirrors the C# claims-transformation cache).
_AD_GROUPS_CACHE_SLIDING_SECONDS = int(os.environ.get("AD_GROUPS_CACHE_SLIDING_SECONDS", "600"))
_AD_GROUPS_CACHE_ABSOLUTE_SECONDS = int(os.environ.get("AD_GROUPS_CACHE_ABSOLUTE_SECONDS", "3600"))


class AuthSettings:
    def __init__(self) -> None:
        issuer = os.environ.get("KEYCLOAK_ISSUER")
        audience = os.environ.get("KEYCLOAK_AUDIENCE")
        if not issuer or not audience:
            raise RuntimeError(
                "KEYCLOAK_ISSUER and KEYCLOAK_AUDIENCE must be set "
                "(see .env). They must match the frontend Keycloak config."
            )
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.jwks_url = f"{self.issuer}/protocol/openid-connect/certs"
        self.jwks_ttl_seconds = int(os.environ.get("KEYCLOAK_JWKS_TTL_SECONDS", "3600"))


class JwksCache:
    def __init__(self, settings: AuthSettings) -> None:
        self._settings = settings
        self._lock = asyncio.Lock()
        self._keys_by_kid: dict[str, dict[str, Any]] = {}
        self._fetched_at: float = 0.0

    async def get_key(self, kid: str) -> dict[str, Any]:
        key = self._keys_by_kid.get(kid)
        if key and not self._is_stale():
            return key
        await self._refresh()
        key = self._keys_by_kid.get(kid)
        if not key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unknown signing key",
                headers=_UNAUTHENTICATED_HEADERS,
            )
        return key

    def _is_stale(self) -> bool:
        return (time.monotonic() - self._fetched_at) > self._settings.jwks_ttl_seconds

    async def _refresh(self) -> None:
        async with self._lock:
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get(self._settings.jwks_url)
                    resp.raise_for_status()
                    payload = resp.json()
            except (httpx.HTTPError, ValueError) as exc:
                logger.warning("JWKS fetch failed: %s", exc)
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Identity provider unreachable",
                ) from exc

            self._keys_by_kid = {k["kid"]: k for k in payload.get("keys", []) if "kid" in k}
            self._fetched_at = time.monotonic()


@dataclass
class _GroupsCacheEntry:
    groups: list[str]
    fetched_at: float
    last_access: float


class AdGroupsCache:
    """Short-TTL cache of AD group memberships, keyed by username.

    Mirrors the cache used by the equivalent C# claims transformation: an entry
    stays valid for ``sliding_seconds`` since it was last read, but never longer
    than ``absolute_seconds`` since it was fetched. Trades a little staleness for
    far fewer calls to the AD Groups API on back-to-back requests.

    Accessors are plain synchronous methods: under asyncio they run to
    completion without yielding, so no lock is needed.
    """

    def __init__(
        self,
        sliding_seconds: int = _AD_GROUPS_CACHE_SLIDING_SECONDS,
        absolute_seconds: int = _AD_GROUPS_CACHE_ABSOLUTE_SECONDS,
    ) -> None:
        self._sliding = sliding_seconds
        self._absolute = absolute_seconds
        self._entries: dict[str, _GroupsCacheEntry] = {}

    def get(self, username: str) -> list[str] | None:
        """Return cached groups (a copy) or None if absent/expired."""
        entry = self._entries.get(username)
        if entry is None:
            return None
        now = time.monotonic()
        if now - entry.fetched_at > self._absolute or now - entry.last_access > self._sliding:
            del self._entries[username]
            return None
        entry.last_access = now
        return list(entry.groups)

    def set(self, username: str, groups: list[str]) -> None:
        now = time.monotonic()
        self._entries[username] = _GroupsCacheEntry(
            groups=list(groups), fetched_at=now, last_access=now
        )


async def get_current_user(
    request: Request,
    token: str = Depends(_oauth2_scheme),
) -> CurrentUser:
    settings: AuthSettings = request.app.state.auth_settings
    jwks: JwksCache = request.app.state.jwks_cache

    try:
        header = jwt.get_unverified_header(token)
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token",
            headers=_UNAUTHENTICATED_HEADERS,
        ) from exc

    kid = header.get("kid")
    if not kid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing kid",
            headers=_UNAUTHENTICATED_HEADERS,
        )

    key = await jwks.get_key(kid)

    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=[header.get("alg", "RS256")],
            audience=settings.audience,
            issuer=settings.issuer,
            options={"verify_at_hash": False},
        )
    except ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers=_UNAUTHENTICATED_HEADERS,
        ) from exc
    except JOSEError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers=_UNAUTHENTICATED_HEADERS,
        ) from exc

    username = claims.get("preferred_username") or claims.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has no subject",
            headers=_UNAUTHENTICATED_HEADERS,
        )

    return CurrentUser(
        username=username,
        display_name=claims.get("name") or username,
        email=claims.get("email") or "",
    )


async def _fetch_user_groups(username: str) -> list[str]:
    """Call the AD Groups API for a user's direct group memberships.

    Fails closed: if the AD service is unreachable or errors we deny with 503;
    if the user is unknown to the directory (404) we treat them as having no
    groups (empty list) rather than erroring, so list endpoints can return an
    empty result.
    """
    url = f"{_AD_GROUPS_API_URL}/users/{username}/groups"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        logger.warning("AD Groups API unreachable (%s): %s", url, exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authorization service unreachable",
        ) from exc

    if resp.status_code == status.HTTP_404_NOT_FOUND:
        # Unknown to the directory -> no groups. Fail closed.
        return []
    if resp.status_code != 200:
        logger.warning("AD Groups API returned %s for %s", resp.status_code, url)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authorization service error",
        )

    return resp.json().get("groups", [])


async def get_user_groups(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> list[str]:
    """Caller's direct AD groups, served from a short-TTL per-username cache.

    On a cache miss we hit the AD Groups API via ``_fetch_user_groups`` and
    cache the result (including the empty list for unknown users). A 503 from
    the AD service is *not* cached, so the next request retries.
    """
    cache: AdGroupsCache = request.app.state.ad_groups_cache
    cached = cache.get(user.username)
    if cached is not None:
        return cached
    groups = await _fetch_user_groups(user.username)
    cache.set(user.username, groups)
    return groups


def is_admin(groups: list[str]) -> bool:
    """True if the caller's AD groups include the gatekeeper-admin group."""
    return _GATEKEEPER_ADMIN_GROUP in groups


async def require_admin(
    groups: list[str] = Depends(get_user_groups),
    user: CurrentUser = Depends(get_current_user),
) -> CurrentUser:
    """Authorize an admin-only action via the caller's AD group membership.

    Requires the configured gatekeeper-admin group. Denies with 403 if the user
    is not a member (including users unknown to the directory); a 503 from the
    AD service propagates from ``get_user_groups``.
    """
    if not is_admin(groups):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to perform this action",
        )
    return user
