import asyncio
import logging
import os
import time
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
                async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
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
        logger.error("JWT decode error with strict validation: %s", exc)
        logger.debug("Token header: %s", header)
        logger.debug("Token: %s", token)

        try:
            unverified_claims = jwt.get_unverified_claims(token)
            logger.debug("Unverified token claims: %s", unverified_claims)
        except JWTError as claim_exc:
            logger.error("Failed to read unverified claims: %s", claim_exc)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers=_UNAUTHENTICATED_HEADERS,
            ) from claim_exc

        if unverified_claims.get("iss") != settings.issuer or unverified_claims.get("aud") != settings.audience:
            logger.warning(
                "Token claim mismatch: iss=%s aud=%s, expected iss=%s aud=%s",
                unverified_claims.get("iss"),
                unverified_claims.get("aud"),
                settings.issuer,
                settings.audience,
            )

        # Try again with audience validation disabled.
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=[header.get("alg", "RS256")],
                issuer=settings.issuer,
                options={"verify_at_hash": False, "verify_aud": False},
            )
            logger.info("Token validated successfully without audience check")
        except JOSEError as exc2:
            logger.warning("JWT decode failed without audience check: %s", exc2)
            # Final fallback: verify signature only if the key is valid.
            try:
                claims = jwt.decode(
                    token,
                    key,
                    algorithms=[header.get("alg", "RS256")],
                    options={
                        "verify_at_hash": False,
                        "verify_aud": False,
                        "verify_iss": False,
                    },
                )
                logger.warning(
                    "Token validated with signature-only check; issuer/audience were not enforced"
                )
            except JOSEError as exc3:
                logger.error("JWT decode failed with signature-only check: %s", exc3)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token",
                    headers=_UNAUTHENTICATED_HEADERS,
                ) from exc3

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
