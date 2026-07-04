"""Authentication detection: request headers, API keys, IdP redirects, auth challenges."""
import base64
import binascii
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse


# Authentication values that represent "no auth observed". Shared with the
# interceptor's 401-challenge handling and the aggregation priority logic so the
# definition of "no auth" stays in one place. "None"/"anonymous" are tolerated
# for robustness against externally-supplied request dicts.
NO_AUTH_VALUES = {"unauthenticated", "None", "anonymous"}

# Mechanism signatures for classifying a "Negotiate" (SPNEGO) token by scanning
# its decoded bytes, instead of a full ASN.1 parse. NTLM messages always begin
# with the literal "NTLMSSP\0" magic (also present when NTLM rides inside a
# SPNEGO mechToken); Kerberos shows up as its mech OID in DER form.
_NTLM_SIGNATURE = b"NTLMSSP\x00"
_KERBEROS_MECH_OIDS = (
    bytes((0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02)),  # 1.2.840.113554.1.2.2  (KRB5)
    bytes((0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02)),  # 1.2.840.48018.1.2.2    (MS KRB5)
)


def _classify_negotiate_token(token: str) -> str:
    """Classify a SPNEGO/"Negotiate" token by scanning its bytes (no ASN.1 parse).

    An embedded NTLM magic means NTLM is actively being exchanged (raw or as a
    SPNEGO mechToken) and wins over a merely-offered Kerberos OID, since NTLM is
    the only mechanism that changes severity. A Kerberos mech OID -> "kerberos".
    Anything else -- including a token that isn't valid base64 -- stays in the
    "negotiate" bucket, because the scheme is still unambiguously SPNEGO.
    """
    try:
        raw = base64.b64decode(token, validate=False)
    except (binascii.Error, ValueError):
        return "negotiate"
    if _NTLM_SIGNATURE in raw:
        return "ntlm"
    if any(oid in raw for oid in _KERBEROS_MECH_OIDS):
        return "kerberos"
    return "negotiate"


def detect_authentication(headers: Dict[str, str], url: str) -> str:
    """Detect the authentication method used in the request.

    Returns a canonical short tag aligned with the FE's AuthMethod vocabulary:
    "bearer", "basic", "ntlm", "kerberos", "negotiate" (SPNEGO whose underlying
    mechanism couldn't be resolved), "api_key", "unknown" (an
    unrecognized/ambiguous scheme), or "unauthenticated" (no auth observed).
    """
    auth_header = None
    for k, v in headers.items():
        if k.lower() == 'authorization':
            auth_header = v
            break

    if auth_header:
        if auth_header.startswith('Bearer '):
            return "bearer"
        if auth_header.startswith('Basic '):
            return "basic"
        if auth_header.startswith('Negotiate '):
            token = auth_header[10:].strip()
            # Fast path: base64 of the NTLM "NTLMSSP\0" magic. Otherwise fall to
            # a byte-signature scan that also catches NTLM/Kerberos wrapped in a
            # SPNEGO blob, settling on "negotiate" when no mechanism is resolvable.
            if token.startswith('TlR'):
                return "ntlm"
            return _classify_negotiate_token(token)
        if auth_header.startswith('NTLM '):
            return "ntlm"
        if auth_header.startswith('Kerberos '):
            return "kerberos"
        return "unknown"

    api_key_headers = [
        'x-api-key', 'x-auth-token', 'x-auth', 'api-key', 'apikey', 'auth-token'
    ]
    for k in headers:
        if k.lower() in api_key_headers:
            return "api_key"

    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    api_key_params = ['api_key', 'apikey', 'key', 'auth_token', 'token']
    for param in api_key_params:
        if param in query_params:
            return "api_key"

    return "unauthenticated"


def detect_idp_redirect(location: str) -> Optional[str]:
    """Detect if a Location URL points to a known Identity Provider."""
    try:
        parsed = urlparse(location)
        domain = parsed.netloc.lower()

        if 'auth0.com' in domain:
            return "Auth0"
        if 'okta.com' in domain or 'oktapreview.com' in domain:
            return "Okta"
        if 'login.microsoftonline.com' in domain:
            return "Azure AD"
        if 'accounts.google.com' in domain:
            return "Google"
        if 'cognito-idp' in domain or 'amazoncognito.com' in domain:
            return "AWS Cognito"
        if 'onelogin.com' in domain:
            return "OneLogin"
        if 'pingidentity.com' in domain:
            return "Ping Identity"

        if '/oauth' in parsed.path or '/oidc' in parsed.path:
            return "Generic OAuth2/OIDC Endpoint"

        return None
    except Exception:
        return None


def _format_headers_snippet(headers: Dict[str, Any] | None, limit: int = 512) -> str:
    if not headers:
        return ""
    parts = [f"{k}: {v}" for k, v in headers.items()]
    text = "\n".join(parts)
    if len(text) > limit:
        return text[: limit - 1] + "…"
    return text


def _evidence_from(req: Dict[str, Any]) -> Dict[str, Any]:
    response = req.get('response') or {}
    return {
        'headers_snippet': _format_headers_snippet(req.get('headers')),
        'status_code': int(response.get('status', 0) or 0),
        'first_seen_on_page': req.get('source_url', '') or '',
    }


# Host-level ranking for aggregate_by_host: when a host is seen with more than
# one authentication scheme across its requests, the highest-ranked scheme
# becomes the host's label. Ordered so the weakest/most-notable schemes (Basic,
# NTLM) rank highest and "no auth observed" ranks lowest; a "Required: <scheme>"
# 401 challenge ranks as that scheme, so a demanded Basic/NTLM is never masked by
# an accepted credential on another endpoint of the same host.
_AUTH_RANK = {
    "basic": 8,
    "ntlm": 8,
    "negotiate": 7,
    "other": 6,
    "unknown": 5,
    "kerberos": 4,
    "bearer": 3,
    "oauth": 2,
    "api_key": 1,
    "unauthenticated": 0,
}


def _auth_rank(value: str) -> int:
    """Rank an authentication string by its scheme for host aggregation.

    Classifies the raw scraper value -- a short detect_authentication tag, a
    "Required: <scheme> ..." 401 challenge, or an "oauth: <provider>" redirect --
    to a single scheme by substring, mirroring translate.normalize_auth_method so
    the rank agrees with the scheme the FE will ultimately show. A scheme the
    server merely demanded therefore counts the same as one actually observed.
    An unresolved challenge surfaces on the FE as "other" and ranks just above
    "unknown": when a host carries both, the "Required: Other (...)" 401 -- whose
    evidence is the literal WWW-Authenticate demand -- represents the host over an
    unclassifiable sent header. "other" still sits below negotiate and the
    blockers, so it never masks a more-notable demanded scheme, and (like every
    named scheme) outranks unauthenticated.
    """
    lower = (value or "").lower()
    if not lower or value in NO_AUTH_VALUES or lower in {"none", "anonymous", "unauthenticated"}:
        return _AUTH_RANK["unauthenticated"]
    if "ntlm" in lower:
        return _AUTH_RANK["ntlm"]
    if "kerberos" in lower:
        return _AUTH_RANK["kerberos"]
    if "negotiate" in lower:
        return _AUTH_RANK["negotiate"]
    if "oauth" in lower or "/oidc" in lower:
        return _AUTH_RANK["oauth"]
    if "bearer" in lower:
        return _AUTH_RANK["bearer"]
    if "basic" in lower:
        return _AUTH_RANK["basic"]
    if "api_key" in lower or "apikey" in lower or "api-key" in lower:
        return _AUTH_RANK["api_key"]
    # Last, mirroring normalize_auth_method: the "Required: Other (...)" marker
    # must not preempt a real scheme wrapped inside it.
    if "other" in lower:
        return _AUTH_RANK["other"]
    return _AUTH_RANK["unknown"]


def aggregate_by_host(requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group requests by host and pick the most specific authentication seen.

    Retains a representative evidence sample (request headers, response status,
    first source page) for the request whose authentication classification "wins"
    so the FE can render its `evidence` block.
    """
    result_map: Dict[str, Dict[str, Any]] = {}
    for req in requests:
        parsed_url = urlparse(req['url'])
        host = parsed_url.netloc
        if not host:
            continue

        current_auth = req.get('authentication', 'unauthenticated')

        if host not in result_map:
            entry = {
                'host': host,
                'authentication': current_auth,
                'request_count': 1,
            }
            entry.update(_evidence_from(req))
            result_map[host] = entry
            continue

        entry = result_map[host]
        entry['request_count'] = int(entry.get('request_count', 1)) + 1

        existing_auth = entry['authentication']
        # Rank by scheme (_auth_rank): the most notable auth seen on any of the
        # host's requests wins as its label. A strictly higher rank also brings
        # its evidence sample along; equal ranks keep the first request seen.
        if _auth_rank(current_auth) > _auth_rank(existing_auth):
            entry['authentication'] = current_auth
            entry.update(_evidence_from(req))

    return list(result_map.values())
