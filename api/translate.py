"""Translate raw scraper output into the frontend's domain model."""
import uuid
from typing import Any, Dict, List

from .models import AuthMethod, Severity


def normalize_auth_method(raw: str) -> AuthMethod:
    """Map the scraper's freeform authentication string to the FE enum.

    Scraper sources:
    - auth_analyzer.detect_authentication() — short tags: ntlm, kerberos, negotiate, basic, bearer, api_key, unknown, unauthenticated
    - interceptor._apply_auth_challenge() — "Required: Basic ...", "Required: Bearer ...", "Required: Negotiate ...", "Required: Other ..."
    - interceptor._apply_idp_redirect() — "oauth: <provider>"
    """
    if not raw:
        return AuthMethod.unknown
    s = raw.strip()
    lower = s.lower()

    if "ntlm" in lower:
        return AuthMethod.ntlm
    if "kerberos" in lower:
        return AuthMethod.kerberos
    if "negotiate" in lower:
        # SPNEGO with no resolvable concrete mechanism. detect_authentication
        # already resolves NTLM/Kerberos to their own tags upstream (byte scan),
        # and a raw "NTLM"/"Kerberos" challenge is caught above, so what reaches
        # here is a bare "WWW-Authenticate: Negotiate" 401 or the "negotiate" tag.
        return AuthMethod.negotiate

    if "oauth" in lower or "/oidc" in lower:
        return AuthMethod.oauth

    if "bearer" in lower:
        return AuthMethod.bearer

    if "api_key" in lower or "apikey" in lower:
        return AuthMethod.api_key

    if "basic" in lower:
        return AuthMethod.basic

    if lower in {"none", "anonymous", "unauthenticated", ""}:
        return AuthMethod.unauthenticated

    # Checked last so the interceptor's "Required: Other (...)" marker never
    # preempts a real scheme carried in the wrapped challenge -- e.g. a bare
    # "WWW-Authenticate: NTLM" 401 becomes "Required: Other (NTLM)" and must
    # still resolve to ntlm (a blocker), not other.
    if "other" in lower:
        return AuthMethod.other

    return AuthMethod.unknown


def severity_for(method: AuthMethod) -> Severity:
    if method in (AuthMethod.ntlm, AuthMethod.basic):
        return Severity.blocker
    if method in (AuthMethod.negotiate, AuthMethod.unknown, AuthMethod.other):
        return Severity.review
    return Severity.cleared


def truncate_headers(headers: Dict[str, Any] | None, limit: int = 512) -> str:
    if not headers:
        return ""
    parts = [f"{k}: {v}" for k, v in headers.items()]
    text = "\n".join(parts)
    if len(text) > limit:
        return text[: limit - 1] + "…"
    return text


def host_to_finding_row(scan_id: str, host_entry: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a single aggregate_by_host entry into a FindingRow-ready dict."""
    method = normalize_auth_method(host_entry.get("authentication", ""))
    severity = severity_for(method)
    return {
        "id": uuid.uuid4().hex,
        "scan_id": scan_id,
        "host": host_entry.get("host", ""),
        "auth_method": method.value,
        "severity": severity.value,
        "request_count": int(host_entry.get("request_count", 1) or 1),
        "first_seen_on_page": host_entry.get("first_seen_on_page", "") or "",
        "headers_snippet": host_entry.get("headers_snippet", "") or "",
        "status_code": int(host_entry.get("status_code", 0) or 0),
        "excluded": False,
    }


def hosts_to_findings(scan_id: str, external_hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [host_to_finding_row(scan_id, h) for h in external_hosts]
