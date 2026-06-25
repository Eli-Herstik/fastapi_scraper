"""Tests for crawler.auth.login."""
import json
import time

import pytest
from unittest.mock import AsyncMock, MagicMock

from config_loader import LoginConfig
from crawler.auth.login import is_on_login_page, storage_state_valid, perform_login


def _make_login_cfg(**overrides):
    defaults = dict(
        login_url="http://x/login",
        username="u",
        password="p",
        post_login_wait_ms=100,
    )
    defaults.update(overrides)
    return LoginConfig(**defaults)


class TestIsOnLoginPage:
    def test_matches_exact(self):
        cfg = _make_login_cfg()
        page = MagicMock()
        page.url = "http://x/login"
        assert is_on_login_page(page, cfg) is True

    def test_matches_prefix(self):
        cfg = _make_login_cfg()
        page = MagicMock()
        page.url = "http://x/login?next=/dash"
        assert is_on_login_page(page, cfg) is True

    def test_no_match(self):
        cfg = _make_login_cfg()
        page = MagicMock()
        page.url = "http://x/home"
        assert is_on_login_page(page, cfg) is False

    def test_matches_extra_login_url(self):
        cfg = _make_login_cfg(
            login_url="https://psso/auth/realms",
            extra_login_urls=["https://psso.corp/auth/realms"],
        )
        page = MagicMock()
        page.url = "https://psso.corp/auth/realms/myrealm?foo=bar"
        assert is_on_login_page(page, cfg) is True

    def test_extra_login_url_host_must_match(self):
        cfg = _make_login_cfg(
            login_url="https://psso/auth/realms",
            extra_login_urls=["https://psso.corp/auth/realms"],
        )
        page = MagicMock()
        page.url = "https://other/auth/realms"
        assert is_on_login_page(page, cfg) is False

    def test_no_match_on_lookalike_path(self):
        cfg = _make_login_cfg()
        page = MagicMock()
        page.url = "http://x/login-help"
        assert is_on_login_page(page, cfg) is False

    def test_matches_subpath(self):
        cfg = _make_login_cfg()
        page = MagicMock()
        page.url = "http://x/login/step2"
        assert is_on_login_page(page, cfg) is True


class TestStorageStateValid:
    def test_missing_file(self, tmp_path):
        cfg = _make_login_cfg(storage_state_path=str(tmp_path / "absent.json"))
        assert storage_state_valid(cfg) is False

    def test_empty_file(self, tmp_path):
        p = tmp_path / "s.json"
        p.write_text("")
        cfg = _make_login_cfg(storage_state_path=str(p))
        assert storage_state_valid(cfg) is False

    def test_invalid_json(self, tmp_path):
        p = tmp_path / "s.json"
        p.write_text("not json{{{")
        cfg = _make_login_cfg(storage_state_path=str(p))
        assert storage_state_valid(cfg) is False

    def test_wrong_shape(self, tmp_path):
        p = tmp_path / "s.json"
        p.write_text(json.dumps(["not", "a", "state"]))
        cfg = _make_login_cfg(storage_state_path=str(p))
        assert storage_state_valid(cfg) is False

    def test_empty_state(self, tmp_path):
        p = tmp_path / "s.json"
        p.write_text(json.dumps({"cookies": [], "origins": []}))
        cfg = _make_login_cfg(storage_state_path=str(p))
        assert storage_state_valid(cfg) is False

    def test_all_cookies_expired(self, tmp_path):
        p = tmp_path / "s.json"
        p.write_text(json.dumps({
            "cookies": [{"name": "sid", "value": "v", "expires": time.time() - 60}],
            "origins": [],
        }))
        cfg = _make_login_cfg(storage_state_path=str(p))
        assert storage_state_valid(cfg) is False

    def test_unexpired_cookie(self, tmp_path):
        p = tmp_path / "s.json"
        p.write_text(json.dumps({
            "cookies": [{"name": "sid", "value": "v", "expires": time.time() + 3600}],
            "origins": [],
        }))
        cfg = _make_login_cfg(storage_state_path=str(p))
        assert storage_state_valid(cfg) is True

    def test_session_cookie(self, tmp_path):
        p = tmp_path / "s.json"
        p.write_text(json.dumps({
            "cookies": [{"name": "sid", "value": "v", "expires": -1}],
            "origins": [],
        }))
        cfg = _make_login_cfg(storage_state_path=str(p))
        assert storage_state_valid(cfg) is True

    def test_local_storage_only(self, tmp_path):
        p = tmp_path / "s.json"
        p.write_text(json.dumps({
            "cookies": [],
            "origins": [{
                "origin": "http://x",
                "localStorage": [{"name": "token", "value": "jwt"}],
            }],
        }))
        cfg = _make_login_cfg(storage_state_path=str(p))
        assert storage_state_valid(cfg) is True


class TestPerformLogin:
    async def test_fills_and_submits_and_saves_state(self, tmp_path):
        storage_path = str(tmp_path / "s.json")
        cfg = _make_login_cfg(
            storage_state_path=storage_path,
            username_selector="#u",
            password_selector="#p",
            submit_selector="#go",
        )
        page = AsyncMock()
        page.url = "http://x/login"
        page.goto.return_value = MagicMock(status=200)
        page.query_selector = AsyncMock(return_value=None)
        ctx = AsyncMock()
        page.context = ctx

        await perform_login(page, cfg, "http://x/home")

        page.wait_for_selector.assert_called_with("#u", timeout=10000)
        page.fill.assert_any_call("#u", "u")
        page.fill.assert_any_call("#p", "p")
        page.click.assert_called_with("#go")
        page.wait_for_url.assert_called_once()
        page.goto.assert_called_once_with("http://x/home")
        ctx.storage_state.assert_called_with(path=storage_path)

        predicate = page.wait_for_url.call_args[0][0]
        assert predicate("http://x/dashboard") is True
        assert predicate("http://x/login") is False
        assert predicate("http://x/login?error=1") is False
        # Off-origin IdP hop must keep the wait pending
        assert predicate("https://idp.example.com/oauth/authorize?client_id=1") is False

    async def test_raises_when_redirect_does_not_happen(self, tmp_path):
        from playwright.async_api import TimeoutError as PWTimeoutError
        cfg = _make_login_cfg(storage_state_path=str(tmp_path / "s.json"))
        page = AsyncMock()
        page.url = "http://x/login"
        page.context = AsyncMock()
        page.wait_for_url.side_effect = PWTimeoutError("no redirect")

        with pytest.raises(RuntimeError, match="did not land back"):
            await perform_login(page, cfg, "http://x/home")

    async def test_raises_when_unauthorized(self, tmp_path):
        cfg = _make_login_cfg(storage_state_path=str(tmp_path / "s.json"))
        page = AsyncMock()
        page.url = "http://x/login"
        page.goto.return_value = MagicMock(status=403)
        ctx = AsyncMock()
        page.context = ctx

        with pytest.raises(RuntimeError, match="HTTP 403"):
            await perform_login(page, cfg, "http://x/home")
        ctx.storage_state.assert_not_called()

    async def test_tolerates_missing_goto_response(self, tmp_path):
        storage_path = str(tmp_path / "s.json")
        cfg = _make_login_cfg(storage_state_path=storage_path)
        page = AsyncMock()
        page.url = "http://x/login"
        page.goto.return_value = None
        page.query_selector = AsyncMock(return_value=None)
        ctx = AsyncMock()
        page.context = ctx

        await perform_login(page, cfg, "http://x/home")
        ctx.storage_state.assert_called_with(path=storage_path)

    async def test_raises_when_session_cookie_absent(self, tmp_path):
        storage_path = str(tmp_path / "s.json")
        cfg = _make_login_cfg(
            storage_state_path=storage_path,
            session_cookie_names=["sessionid"],
        )
        page = AsyncMock()
        page.url = "http://x/login"
        page.goto.return_value = MagicMock(status=200)
        page.query_selector = AsyncMock(return_value=None)
        ctx = AsyncMock()
        ctx.cookies = AsyncMock(return_value=[{"name": "other", "value": "x"}])
        page.context = ctx

        with pytest.raises(RuntimeError, match="session cookies"):
            await perform_login(page, cfg, "http://x/home")
        ctx.cookies.assert_called_once_with("http://x/home")
        ctx.storage_state.assert_not_called()

    async def test_succeeds_when_session_cookie_present(self, tmp_path):
        storage_path = str(tmp_path / "s.json")
        cfg = _make_login_cfg(
            storage_state_path=storage_path,
            session_cookie_names=["sessionid"],
        )
        page = AsyncMock()
        page.url = "http://x/login"
        page.goto.return_value = MagicMock(status=200)
        page.query_selector = AsyncMock(return_value=None)
        ctx = AsyncMock()
        ctx.cookies = AsyncMock(return_value=[{"name": "sessionid", "value": "abc123"}])
        page.context = ctx

        await perform_login(page, cfg, "http://x/home")
        ctx.cookies.assert_called_once_with("http://x/home")
        ctx.storage_state.assert_called_with(path=storage_path)

    async def test_raises_when_session_cookie_value_empty(self, tmp_path):
        storage_path = str(tmp_path / "s.json")
        cfg = _make_login_cfg(
            storage_state_path=storage_path,
            session_cookie_names=["sessionid"],
        )
        page = AsyncMock()
        page.url = "http://x/login"
        page.goto.return_value = MagicMock(status=200)
        page.query_selector = AsyncMock(return_value=None)
        ctx = AsyncMock()
        ctx.cookies = AsyncMock(return_value=[{"name": "sessionid", "value": ""}])
        page.context = ctx

        with pytest.raises(RuntimeError, match="session cookies"):
            await perform_login(page, cfg, "http://x/home")
        ctx.storage_state.assert_not_called()

    async def test_succeeds_when_any_configured_cookie_present(self, tmp_path):
        storage_path = str(tmp_path / "s.json")
        cfg = _make_login_cfg(
            storage_state_path=storage_path,
            session_cookie_names=["sid", "JSESSIONID"],
        )
        page = AsyncMock()
        page.url = "http://x/login"
        page.goto.return_value = MagicMock(status=200)
        page.query_selector = AsyncMock(return_value=None)
        ctx = AsyncMock()
        ctx.cookies = AsyncMock(return_value=[{"name": "JSESSIONID", "value": "v"}])
        page.context = ctx

        await perform_login(page, cfg, "http://x/home")
        ctx.storage_state.assert_called_with(path=storage_path)

    async def test_session_cookie_probe_error_is_lenient(self, tmp_path):
        from playwright.async_api import Error as PWError
        storage_path = str(tmp_path / "s.json")
        cfg = _make_login_cfg(
            storage_state_path=storage_path,
            session_cookie_names=["sessionid"],
        )
        page = AsyncMock()
        page.url = "http://x/login"
        page.goto.return_value = MagicMock(status=200)
        page.query_selector = AsyncMock(return_value=None)
        ctx = AsyncMock()
        ctx.cookies = AsyncMock(side_effect=PWError("cookie jar unavailable"))
        page.context = ctx

        await perform_login(page, cfg, "http://x/home")
        ctx.storage_state.assert_called_with(path=storage_path)

    async def test_session_cookie_check_skipped_when_unconfigured(self, tmp_path):
        storage_path = str(tmp_path / "s.json")
        cfg = _make_login_cfg(storage_state_path=storage_path)
        page = AsyncMock()
        page.url = "http://x/login"
        page.goto.return_value = MagicMock(status=200)
        page.query_selector = AsyncMock(return_value=None)
        ctx = AsyncMock()
        ctx.cookies = AsyncMock(return_value=[])
        page.context = ctx

        await perform_login(page, cfg, "http://x/home")
        ctx.cookies.assert_not_called()
        ctx.storage_state.assert_called_with(path=storage_path)

    async def test_raises_when_login_form_still_visible(self, tmp_path):
        storage_path = str(tmp_path / "s.json")
        cfg = _make_login_cfg(storage_state_path=storage_path)
        page = AsyncMock()
        page.url = "http://x/login"
        page.goto.return_value = MagicMock(status=200)
        field = AsyncMock()
        field.is_visible = AsyncMock(return_value=True)
        page.query_selector = AsyncMock(return_value=field)
        ctx = AsyncMock()
        page.context = ctx

        with pytest.raises(RuntimeError, match="still presents a login form"):
            await perform_login(page, cfg, "http://x/home")
        ctx.storage_state.assert_not_called()

    async def test_succeeds_when_login_field_present_but_hidden(self, tmp_path):
        storage_path = str(tmp_path / "s.json")
        cfg = _make_login_cfg(storage_state_path=storage_path)
        page = AsyncMock()
        page.url = "http://x/login"
        page.goto.return_value = MagicMock(status=200)
        field = AsyncMock()
        field.is_visible = AsyncMock(return_value=False)
        page.query_selector = AsyncMock(return_value=field)
        ctx = AsyncMock()
        page.context = ctx

        await perform_login(page, cfg, "http://x/home")
        ctx.storage_state.assert_called_with(path=storage_path)
