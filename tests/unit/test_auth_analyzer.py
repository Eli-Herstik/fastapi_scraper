"""Tests for crawler.network.auth_analyzer."""
import pytest
from crawler.network.auth_analyzer import (
    detect_authentication,
    detect_idp_redirect,
    aggregate_by_host,
)


class TestDetectAuthentication:
    def test_bearer(self):
        assert detect_authentication({"authorization": "Bearer abc"}, "http://x") == "bearer"

    def test_bearer_empty_token(self):
        assert detect_authentication({"authorization": "Bearer "}, "http://x") == "bearer"

    def test_basic(self):
        assert detect_authentication({"authorization": "Basic dXNlcg=="}, "http://x") == "basic"

    def test_negotiate_ntlm(self):
        assert detect_authentication({"authorization": "Negotiate TlRMTVNTUAAB"}, "http://x") == "ntlm"

    def test_negotiate_kerberos(self):
        assert detect_authentication({"authorization": "Negotiate YIIGfAY"}, "http://x") == "kerberos"

    def test_negotiate_unknown(self):
        assert detect_authentication({"authorization": "Negotiate xyz123"}, "http://x") == "unknown"

    def test_ntlm_direct(self):
        assert detect_authentication({"authorization": "NTLM abc"}, "http://x") == "ntlm"

    def test_kerberos_direct(self):
        assert detect_authentication({"authorization": "Kerberos abc"}, "http://x") == "kerberos"

    def test_unknown_scheme(self):
        assert detect_authentication({"authorization": "Digest abc"}, "http://x") == "unknown"

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

    def test_cookie_lowercase(self):
        assert detect_authentication({"cookie": "sid=abc"}, "http://x") == "session"

    def test_cookie_capital(self):
        assert detect_authentication({"Cookie": "sid=abc"}, "http://x") == "session"

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

    def test_upgrades_from_required_to_oauth(self):
        reqs = [
            {"url": "http://a.com/1", "authentication": "Required: Basic (...)"},
            {"url": "http://a.com/2", "authentication": "bearer"},
        ]
        result = aggregate_by_host(reqs)
        assert result[0]["authentication"] == "bearer"

    def test_keeps_better_auth(self):
        reqs = [
            {"url": "http://a.com/1", "authentication": "bearer"},
            {"url": "http://a.com/2", "authentication": "unauthenticated"},
        ]
        result = aggregate_by_host(reqs)
        assert result[0]["authentication"] == "bearer"

    def test_skips_requests_without_host(self):
        reqs = [{"url": "not-a-url", "authentication": "unauthenticated"}]
        assert aggregate_by_host(reqs) == []

    def test_missing_authentication_defaults_to_unauthenticated(self):
        reqs = [{"url": "http://a.com/x"}]
        result = aggregate_by_host(reqs)
        assert result[0]["authentication"] == "unauthenticated"

    def test_empty_input(self):
        assert aggregate_by_host([]) == []
