"""Tests for scraper.auth.login."""
import json
import pytest
from unittest.mock import AsyncMock, MagicMock

from config_loader import LoginConfig
from scraper.auth.login import is_on_login_page, storage_state_valid, perform_login


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

    def test_valid_json(self, tmp_path):
        p = tmp_path / "s.json"
        p.write_text(json.dumps({"cookies": []}))
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
        ctx = AsyncMock()
        page.context = ctx

        await perform_login(page, cfg)

        page.wait_for_selector.assert_called_with("#u", timeout=10000)
        page.fill.assert_any_call("#u", "u")
        page.fill.assert_any_call("#p", "p")
        page.click.assert_called_with("#go")
        page.wait_for_url.assert_called_once()
        ctx.storage_state.assert_called_with(path=storage_path)

    async def test_raises_when_redirect_does_not_happen(self, tmp_path):
        from playwright.async_api import TimeoutError as PWTimeoutError
        cfg = _make_login_cfg(storage_state_path=str(tmp_path / "s.json"))
        page = AsyncMock()
        page.url = "http://x/login"
        page.context = AsyncMock()
        page.wait_for_url.side_effect = PWTimeoutError("no redirect")

        with pytest.raises(RuntimeError, match="did not redirect"):
            await perform_login(page, cfg)
