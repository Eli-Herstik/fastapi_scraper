"""Authentication detection: request headers, API keys, IdP redirects, auth challenges."""
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse


def detect_authentication(headers: Dict[str, str], url: str) -> str:
    """Detect the authentication method used in the request."""
    auth_header = None
    for k, v in headers.items():
        if k.lower() == 'authorization':
            auth_header = v
            break

    if auth_header:
        if auth_header.startswith('Bearer '):
            return "OAuth (Bearer)"
        if auth_header.startswith('Basic '):
            return "Basic Auth"
        if auth_header.startswith('Negotiate '):
            token = auth_header[10:].strip()
            if token.startswith('TlR'):
                return "NTLM (Negotiate)"
            if token.startswith('YII'):
                return "Kerberos (Negotiate)"
            return "Negotiate (Unknown)"
        if auth_header.startswith('NTLM '):
            return "NTLM"
        if auth_header.startswith('Kerberos '):
            return "Kerberos"
        return f"Unknown Authorization ({auth_header.split(' ')[0]})"

    api_key_headers = [
        'x-api-key', 'x-auth-token', 'x-auth', 'api-key', 'apikey', 'auth-token'
    ]
    for k in headers:
        if k.lower() in api_key_headers:
            return f"API Key ({k})"

    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    api_key_params = ['api_key', 'apikey', 'key', 'auth_token', 'token']
    for param in api_key_params:
        if param in query_params:
            return f"API Key (Query Param: {param})"

    if 'cookie' in headers or 'Cookie' in headers:
        return "Cookie / Session"

    return "None"


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


def aggregate_by_host(requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group requests by host and pick the most specific authentication seen."""
    result_map: Dict[str, Dict[str, Any]] = {}
    for req in requests:
        parsed_url = urlparse(req['url'])
        host = parsed_url.netloc
        if not host:
            continue

        current_auth = req.get('authentication', 'None')

        if host not in result_map:
            result_map[host] = {'host': host, 'authentication': current_auth}
            continue

        existing_auth = result_map[host]['authentication']
        # Priority: Actual Auth > Required Auth > None
        if existing_auth in ['None', 'anonymous'] and current_auth not in ['None', 'anonymous']:
            result_map[host]['authentication'] = current_auth
        elif "Required" in existing_auth and "OAuth" in current_auth:
            result_map[host]['authentication'] = current_auth

    return list(result_map.values())
