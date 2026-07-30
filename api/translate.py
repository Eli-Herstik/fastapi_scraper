"""Translate raw scraper output into the frontend's domain model."""
import uuid
from typing import Any, Dict, List

from .models import AuthMethod, Severity


def normalize_auth_method(raw: str) -> AuthMethod:
    """Map the scraper's authentication tag to the FE enum.

    Every tag the scraper emits is verbatim an AuthMethod value, so the enum
    constructor is the whole mapping. Sources:
    - auth_analyzer.detect_authentication() — ntlm, kerberos, negotiate, basic, bearer, api_key, other, unauthenticated
    - auth_analyzer.detect_auth_challenge() — the same short tags for a 401's demanded scheme: basic, bearer, ntlm, negotiate, other (raw challenge kept separately in 'auth_challenge')
    - interceptor._apply_idp_redirect() — "oauth" (the IdP host kept separately in 'idp_redirect')

    "negotiate" means SPNEGO whose concrete mechanism was unresolvable: NTLM and
    Kerberos are already resolved to their own tags upstream, so it is not a
    shortfall of this mapping.

    Matching is exact. A string outside that set means a producer drifted from the
    FE vocabulary, and unknown (severity_for -> review) puts it in front of a human
    instead of guessing a scheme from a coincidental substring.
    """
    try:
        return AuthMethod((raw or "").strip().lower())
    except ValueError:
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
