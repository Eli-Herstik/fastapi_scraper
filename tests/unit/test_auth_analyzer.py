"""Tests for crawler.network.auth_analyzer."""
import base64

import pytest
from crawler.network.auth_analyzer import (
    detect_authentication,
    detect_idp_redirect,
    aggregate_by_host,
)


# Mechanism signatures used to craft realistic SPNEGO tokens for the tests.
_NTLM_MAGIC = b"NTLMSSP\x00"
_KRB5_OID = bytes((0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02))
_MS_KRB5_OID = bytes((0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02))


def _negotiate(raw: bytes) -> dict:
    """Build an Authorization header carrying a base64 'Negotiate' token."""
    return {"authorization": "Negotiate " + base64.b64encode(raw).decode("ascii")}


class TestDetectAuthentication:
    def test_bearer(self):
        assert detect_authentication({"authorization": "Bearer abc"}, "http://x") == "bearer"

    def test_bearer_empty_token(self):
        assert detect_authentication({"authorization": "Bearer "}, "http://x") == "bearer"

    def test_basic(self):
        assert detect_authentication({"authorization": "Basic dXNlcg=="}, "http://x") == "basic"

    def test_negotiate_ntlm_prefix_fast_path(self):
        # base64 of "NTLMSSP\0\x01..." starts with "TlR" -- the cheap fast path.
        assert detect_authentication({"authorization": "Negotiate TlRMTVNTUAAB"}, "http://x") == "ntlm"

    def test_negotiate_ntlm_inside_spnego(self):
        # NTLM mechToken wrapped in a SPNEGO blob (token starts 0x60, not "TlR")
        # must still be caught by the byte-signature scan.
        raw = b"\x60\x28\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x1e" + _NTLM_MAGIC + b"\x01\x00\x00\x00"
        assert detect_authentication(_negotiate(raw), "http://x") == "ntlm"

    def test_negotiate_kerberos_oid(self):
        raw = b"\x60\x1e\x06\x09" + _KRB5_OID + b"\xa0\x11\x30\x0f"
        assert detect_authentication(_negotiate(raw), "http://x") == "kerberos"

    def test_negotiate_ms_kerberos_oid(self):
        raw = b"\x60\x1e\x06\x09" + _MS_KRB5_OID + b"\xa0\x11\x30\x0f"
        assert detect_authentication(_negotiate(raw), "http://x") == "kerberos"

    def test_negotiate_ntlm_wins_over_offered_kerberos(self):
        # SPNEGO that lists the Kerberos OID but actually carries an NTLM
        # mechToken -> NTLM is in use, and NTLM is the severity-relevant call.
        raw = b"\x60\x30\x06\x09" + _KRB5_OID + b"\xa2\x12" + _NTLM_MAGIC + b"\x03\x00\x00\x00"
        assert detect_authentication(_negotiate(raw), "http://x") == "ntlm"

    def test_negotiate_unresolved_token(self):
        # Valid base64 but no recognizable mechanism signature -> negotiate bucket.
        raw = b"\x60\x06\x06\x04\x01\x02\x03\x04"
        assert detect_authentication(_negotiate(raw), "http://x") == "negotiate"

    def test_negotiate_invalid_base64(self):
        # Scheme is certainly SPNEGO even if the token is junk.
        assert detect_authentication({"authorization": "Negotiate xyz123"}, "http://x") == "negotiate"

    def test_ntlm_direct(self):
        assert detect_authentication({"authorization": "NTLM abc"}, "http://x") == "ntlm"

    def test_kerberos_direct(self):
        assert detect_authentication({"authorization": "Kerberos abc"}, "http://x") == "kerberos"

    def test_unnamed_scheme_is_other(self):
        # A present-but-unrecognized scheme (Digest) is a real, unnamed mechanism,
        # classified as "other" -- not "unknown" -- mirroring the interceptor's
        # "Required: Other (...)" challenge handling.
        assert detect_authentication({"authorization": "Digest abc"}, "http://x") == "other"

    def test_case_insensitive_header_key(self):
        assert detect_authentication({"Authorization": "Bearer abc"}, "http://x") == "bearer"

    @pytest.mark.parametrize("header", [
        "x-api-key", "x-auth-token", "x-auth", "api-key", "apikey", "auth-token"
    ])
    def test_api_key_headers(self, header):
        result = detect_authentication({header: "k"}, "http://x")
        assert result == "api_key"

    @pytest.mark.parametrize("param", ["api_key", "apikey", "key", "auth_token", "token"])
    def test_api_key_query_params(self, param):
        url = f"http://api.example.com/v1?{param}=abc"
        assert detect_authentication({}, url) == "api_key"

    def test_cookie_lowercase_ignored(self):
        assert detect_authentication({"cookie": "sid=abc"}, "http://x") == "unauthenticated"

    def test_cookie_capital_ignored(self):
        assert detect_authentication({"Cookie": "sid=abc"}, "http://x") == "unauthenticated"

    def test_no_auth(self):
        assert detect_authentication({}, "http://x") == "unauthenticated"

    def test_auth_header_priority_over_api_key(self):
        assert detect_authentication(
            {"authorization": "Bearer abc", "x-api-key": "k"}, "http://x"
        ) == "bearer"

    def test_api_key_priority_over_cookie(self):
        assert detect_authentication(
            {"x-api-key": "k", "cookie": "sid=abc"}, "http://x"
        ) == "api_key"

    def test_api_key_header_priority_over_query_param(self):
        assert detect_authentication(
            {"x-api-key": "k"}, "http://x?api_key=abc"
        ) == "api_key"

    def test_non_matching_query_params(self):
        assert detect_authentication({}, "http://x?user=a&page=1") == "unauthenticated"


class TestDetectIdpRedirect:
    @pytest.mark.parametrize("url,expected", [
        ("https://myapp.auth0.com/authorize", "Auth0"),
        ("https://dev-123.okta.com/oauth2/default", "Okta"),
        ("https://dev-123.oktapreview.com/app", "Okta"),
        ("https://login.microsoftonline.com/t/oauth2", "Azure AD"),
        ("https://accounts.google.com/o/oauth2/auth", "Google"),
        ("https://cognito-idp.us-east-1.amazonaws.com/p", "AWS Cognito"),
        ("https://mypool.amazoncognito.com/login", "AWS Cognito"),
        ("https://app.onelogin.com/trust/saml2", "OneLogin"),
        ("https://sso.pingidentity.com/sso", "Ping Identity"),
        ("https://mysite.com/oauth/authorize", "Generic OAuth2/OIDC Endpoint"),
        ("https://mysite.com/oidc/auth", "Generic OAuth2/OIDC Endpoint"),
    ])
    def test_idp_matches(self, url, expected):
        assert detect_idp_redirect(url) == expected

    def test_no_match(self):
        assert detect_idp_redirect("https://www.example.com/dashboard") is None

    def test_empty_string(self):
        assert detect_idp_redirect("") is None

    def test_oauth_in_query_not_path(self):
        assert detect_idp_redirect("https://example.com/login?r=/oauth/cb") is None

    def test_case_insensitive_domain(self):
        assert detect_idp_redirect("https://MyApp.Auth0.COM/authorize") == "Auth0"


class TestAggregateByHost:
    def test_single_host(self):
        reqs = [{"url": "http://a.com/x", "authentication": "bearer"}]
        result = aggregate_by_host(reqs)
        assert len(result) == 1
        assert result[0]["host"] == "a.com"
        assert result[0]["authentication"] == "bearer"

    def test_groups_by_host(self):
        reqs = [
            {"url": "http://a.com/1", "authentication": "unauthenticated"},
            {"url": "http://a.com/2", "authentication": "unauthenticated"},
            {"url": "http://b.com/1", "authentication": "bearer"},
        ]
        result = aggregate_by_host(reqs)
        hosts = {e["host"] for e in result}
        assert hosts == {"a.com", "b.com"}

    def test_upgrades_from_none_to_actual(self):
        reqs = [
            {"url": "http://a.com/1", "authentication": "unauthenticated"},
            {"url": "http://a.com/2", "authentication": "bearer"},
        ]
        result = aggregate_by_host(reqs)
        assert result[0]["authentication"] == "bearer"

    def test_basic_challenge_outranks_accepted_bearer(self):
        # A demanded Basic scheme (blocker-tier) is the host's most notable auth
        # and must not be masked by an accepted bearer token on another endpoint.
        reqs = [
            {"url": "http://a.com/1", "authentication": "Required: Basic (...)"},
            {"url": "http://a.com/2", "authentication": "bearer"},
        ]
        result = aggregate_by_host(reqs)
        assert result[0]["authentication"] == "Required: Basic (...)"

    def test_keeps_better_auth(self):
        reqs = [
            {"url": "http://a.com/1", "authentication": "bearer"},
            {"url": "http://a.com/2", "authentication": "unauthenticated"},
        ]
        result = aggregate_by_host(reqs)
        assert result[0]["authentication"] == "bearer"

    def test_basic_outranks_negotiate_challenge(self):
        # Ranking is purely by scheme: Basic (blocker-tier) outranks a Negotiate
        # challenge (review-tier) regardless of which was actually accepted.
        reqs = [
            {"url": "http://a.com/admin", "authentication": "Required: Negotiate (...)"},
            {"url": "http://a.com/login", "authentication": "basic"},
        ]
        result = aggregate_by_host(reqs)
        assert result[0]["authentication"] == "basic"

    def test_challenge_stands_without_accepted_credential(self):
        # A host seen only via a rejected-and-challenged request keeps the
        # challenge as its label -- the rejected credential does not resurface.
        reqs = [
            {"url": "http://a.com/admin", "authentication": "Required: Negotiate (...)"},
        ]
        result = aggregate_by_host(reqs)
        assert result[0]["authentication"] == "Required: Negotiate (...)"

    def test_challenge_not_overwritten_by_later_unauthenticated(self):
        # A real 401 challenge outranks "no auth", so a later unauthenticated
        # request on the same host must not overwrite it (regression guard for
        # the removed NO_AUTH-only upgrade path).
        reqs = [
            {"url": "http://a.com/admin", "authentication": "Required: Negotiate (...)"},
            {"url": "http://a.com/health", "authentication": "unauthenticated"},
        ]
        result = aggregate_by_host(reqs)
        assert result[0]["authentication"] == "Required: Negotiate (...)"

    def test_ntlm_outranks_negotiate(self):
        # NTLM (blocker-tier) is the host's most notable auth over a plain
        # Negotiate/SPNEGO handshake (review-tier).
        reqs = [
            {"url": "http://a.com/1", "authentication": "negotiate"},
            {"url": "http://a.com/2", "authentication": "ntlm"},
        ]
        result = aggregate_by_host(reqs)
        assert result[0]["authentication"] == "ntlm"

    def test_other_challenge_outranks_unknown(self):
        # Same review-tier severity, but the "Required: Other (...)" 401 carries
        # the concrete WWW-Authenticate demand as evidence, so it wins the host
        # label over an unclassifiable header. Deterministic tiebreak: the unknown
        # is seen first here, yet "other" still represents the host.
        reqs = [
            {"url": "http://a.com/1", "authentication": "unknown"},
            {"url": "http://a.com/2", "authentication": "Required: Other (Digest ...)"},
        ]
        result = aggregate_by_host(reqs)
        assert result[0]["authentication"] == "Required: Other (Digest ...)"

    def test_oauth_redirect_outranks_unauthenticated(self):
        # The "oauth: <provider>" redirect form is classified by substring and
        # outranks unauthenticated.
        reqs = [
            {"url": "http://a.com/1", "authentication": "unauthenticated"},
            {"url": "http://a.com/2", "authentication": "oauth: Okta"},
        ]
        result = aggregate_by_host(reqs)
        assert result[0]["authentication"] == "oauth: Okta"

    def test_skips_requests_without_host(self):
        reqs = [{"url": "not-a-url", "authentication": "unauthenticated"}]
        assert aggregate_by_host(reqs) == []

    def test_missing_authentication_defaults_to_unauthenticated(self):
        reqs = [{"url": "http://a.com/x"}]
        result = aggregate_by_host(reqs)
        assert result[0]["authentication"] == "unauthenticated"

    def test_empty_input(self):
        assert aggregate_by_host([]) == []
