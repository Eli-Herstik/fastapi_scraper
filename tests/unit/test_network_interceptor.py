"""Tests for scraper.network.NetworkInterceptor."""
import pytest
from unittest.mock import MagicMock

from scraper.network import NetworkInterceptor


@pytest.fixture
def interceptor():
    return NetworkInterceptor()


class TestGetPostData:
    async def test_json_body(self, interceptor, mock_request):
        req = mock_request("POST", post_data='{"k": "v"}', headers={"content-type": "application/json"})
        assert await interceptor._get_post_data(req) == {"k": "v"}

    async def test_form_urlencoded(self, interceptor, mock_request):
        req = mock_request("POST", post_data="u=a&p=b",
                           headers={"content-type": "application/x-www-form-urlencoded"})
        result = await interceptor._get_post_data(req)
        assert "u" in result and "p" in result

    async def test_form_multiple_values(self, interceptor, mock_request):
        req = mock_request("POST", post_data="t=a&t=b&t=c",
                           headers={"content-type": "application/x-www-form-urlencoded"})
        result = await interceptor._get_post_data(req)
        assert len(result["t"]) == 3

    async def test_raw_fallback(self, interceptor, mock_request):
        req = mock_request("POST", post_data="plain",
                           headers={"content-type": "text/plain"})
        assert await interceptor._get_post_data(req) == {"raw": "plain"}

    async def test_malformed_json_falls_to_raw(self, interceptor, mock_request):
        req = mock_request("POST", post_data="{bad", headers={"content-type": "application/json"})
        assert await interceptor._get_post_data(req) == {"raw": "{bad"}

    async def test_get_returns_none(self, interceptor, mock_request):
        assert await interceptor._get_post_data(mock_request("GET")) is None

    async def test_delete_returns_none(self, interceptor, mock_request):
        assert await interceptor._get_post_data(mock_request("DELETE", post_data='{"x":1}')) is None

    async def test_none_post_data(self, interceptor, mock_request):
        assert await interceptor._get_post_data(mock_request("POST", post_data=None)) is None

    async def test_empty_post_data(self, interceptor, mock_request):
        assert await interceptor._get_post_data(mock_request("POST", post_data="")) is None

    async def test_put_json(self, interceptor, mock_request):
        req = mock_request("PUT", post_data='{"u": true}', headers={"content-type": "application/json"})
        assert await interceptor._get_post_data(req) == {"u": True}

    async def test_patch_json(self, interceptor, mock_request):
        req = mock_request("PATCH", post_data='{"f": "n"}', headers={"content-type": "application/json"})
        assert await interceptor._get_post_data(req) == {"f": "n"}


class TestHandleRequest:
    async def test_returns_expected_keys(self, interceptor, mock_request):
        req = mock_request("GET", headers={"authorization": "Bearer abc"})
        interceptor.set_context("http://example.com", 1)
        result = await interceptor.handle_request(req)
        assert result["url"] == "http://api.example.com/v1/test"
        assert result["method"] == "GET"
        assert result["authentication"] == "OAuth (Bearer)"
        assert result["source_url"] == "http://example.com"
        assert result["navigation_depth"] == 1
        assert "timestamp" in result
        assert result["resource_type"] == "fetch"


class TestHandleResponse:
    async def test_200(self, interceptor, mock_response):
        req_data = {"url": "http://a.com", "authentication": "None"}
        result = await interceptor.handle_response(req_data, mock_response(200))
        assert result["response"]["status"] == 200
        assert len(interceptor.requests) == 1

    async def test_401_basic(self, interceptor, mock_response):
        req_data = {"url": "http://a.com", "authentication": "None"}
        result = await interceptor.handle_response(
            req_data, mock_response(401, {"www-authenticate": 'Basic realm="test"'})
        )
        assert "Required: Basic" in result["authentication"]

    async def test_401_bearer(self, interceptor, mock_response):
        req_data = {"url": "http://a.com", "authentication": "None"}
        result = await interceptor.handle_response(
            req_data, mock_response(401, {"www-authenticate": 'Bearer realm="api"'})
        )
        assert "Required: OAuth/Bearer" in result["authentication"]

    async def test_401_negotiate(self, interceptor, mock_response):
        req_data = {"url": "http://a.com", "authentication": "None"}
        result = await interceptor.handle_response(
            req_data, mock_response(401, {"www-authenticate": "Negotiate"})
        )
        assert "Required: Negotiate" in result["authentication"]

    async def test_401_unknown_scheme(self, interceptor, mock_response):
        req_data = {"url": "http://a.com", "authentication": "None"}
        result = await interceptor.handle_response(
            req_data, mock_response(401, {"www-authenticate": 'Digest realm="t"'})
        )
        assert "Required: Digest" in result["authentication"]

    async def test_401_without_header(self, interceptor, mock_response):
        req_data = {"url": "http://a.com", "authentication": "None"}
        result = await interceptor.handle_response(req_data, mock_response(401, {}))
        assert result["authentication"] == "None"

    async def test_401_does_not_overwrite_existing_auth(self, interceptor, mock_response):
        req_data = {"url": "http://a.com", "authentication": "OAuth (Bearer)"}
        result = await interceptor.handle_response(
            req_data, mock_response(401, {"www-authenticate": "Basic"})
        )
        assert result["authentication"] == "OAuth (Bearer)"

    async def test_302_idp(self, interceptor, mock_response):
        req_data = {"url": "http://a.com", "authentication": "None"}
        result = await interceptor.handle_response(
            req_data, mock_response(302, {"location": "https://x.auth0.com/authorize"})
        )
        assert result["authentication"] == "IdP Redirect: Auth0"

    async def test_307_idp(self, interceptor, mock_response):
        req_data = {"url": "http://a.com", "authentication": "None"}
        result = await interceptor.handle_response(
            req_data, mock_response(307, {"location": "https://login.microsoftonline.com/t/oauth2"})
        )
        assert result["authentication"] == "IdP Redirect: Azure AD"

    async def test_301_non_idp(self, interceptor, mock_response):
        req_data = {"url": "http://a.com", "authentication": "None"}
        result = await interceptor.handle_response(
            req_data, mock_response(301, {"location": "https://example.com/new"})
        )
        assert result["authentication"] == "None"

    async def test_none_response(self, interceptor):
        req_data = {"url": "http://a.com", "authentication": "None"}
        result = await interceptor.handle_response(req_data, None)
        assert result["response"]["status"] == 0
        assert "error" in result["response"]

    async def test_none_response_not_duplicated(self, interceptor):
        req_data = {"url": "http://a.com", "authentication": "None"}
        await interceptor.handle_response(req_data, None)
        await interceptor.handle_response(req_data, None)
        assert interceptor.requests.count(req_data) == 1

    async def test_appended_to_list(self, interceptor, mock_response):
        for i in range(3):
            req_data = {"url": f"http://a.com/{i}", "authentication": "None"}
            await interceptor.handle_response(req_data, mock_response(200))
        assert len(interceptor.requests) == 3


class TestGetHeaderValue:
    def test_case_insensitive(self, interceptor):
        headers = {"Content-Type": "application/json", "X-Custom": "v"}
        assert interceptor._get_header_value(headers, "content-type") == "application/json"
        assert interceptor._get_header_value(headers, "x-custom") == "v"
        assert interceptor._get_header_value(headers, "missing") is None

    def test_empty(self, interceptor):
        assert interceptor._get_header_value({}, "x") is None


class TestInterceptorState:
    def test_set_context(self, interceptor):
        interceptor.set_context("http://x/p", 2)
        assert interceptor.source_url == "http://x/p"
        assert interceptor.navigation_depth == 2

    def test_set_context_default_depth(self, interceptor):
        interceptor.set_context("http://x")
        assert interceptor.navigation_depth == 0

    def test_get_requests_returns_copy(self, interceptor):
        interceptor.requests.append({"url": "http://a"})
        copy = interceptor.get_requests()
        copy.append({"url": "http://b"})
        assert len(interceptor.requests) == 1

    def test_clear(self, interceptor):
        interceptor.requests.extend([{"url": "a"}, {"url": "b"}])
        interceptor.clear()
        assert interceptor.requests == []

    def test_initial_state(self, interceptor):
        assert interceptor.requests == []
        assert interceptor.source_url == ""
        assert interceptor.navigation_depth == 0
