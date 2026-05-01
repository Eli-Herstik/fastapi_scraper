"""Tests for scraper.Mapper (orchestrator, without launching a real browser)."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from scraper import Mapper
from scraper.navigation import NavigationHandler
from scraper.navigation.dom_hasher import DOMHasher
from scraper.network import NetworkInterceptor


class TestInit:
    def test_wires_components(self, make_config):
        cfg = make_config()
        m = Mapper(cfg)
        assert m.config is cfg
        assert isinstance(m.interceptor, NetworkInterceptor)
        assert isinstance(m.dom_hasher, DOMHasher)
        assert isinstance(m.navigator, NavigationHandler)
        assert m.navigator.dom_hasher is m.dom_hasher
        assert m.playwright is None
        assert m.browser is None
        assert m.page is None


class TestMapWebsite:
    async def test_returns_empty_when_navigation_fails(self, make_config):
        m = Mapper(make_config())
        m.page = MagicMock()
        m.navigator.navigate_to = AsyncMock(return_value=False)
        result = await m.map_website()
        assert result == {"external_hosts": []}

    async def test_aggregates_interceptor_requests(self, make_config):
        m = Mapper(make_config())
        m.page = MagicMock()
        m.navigator.navigate_to = AsyncMock(return_value=True)
        m._ensure_authenticated = AsyncMock()
        m._explore_page = AsyncMock()
        m.interceptor.requests = [
            {"url": "http://api.example.com/x", "authentication": "OAuth (Bearer)"},
            {"url": "http://other.com/y", "authentication": "None"},
        ]
        result = await m.map_website()
        hosts = {e["host"] for e in result["external_hosts"]}
        assert hosts == {"api.example.com", "other.com"}


class TestEnsureAuthenticated:
    async def test_noop_when_no_login_config(self, make_config):
        m = Mapper(make_config())
        page = MagicMock()
        page.url = "http://x/home"
        # Should not raise; config.login is None
        await m._ensure_authenticated(page)

    async def test_noop_when_not_on_login_page(self, make_config):
        from config_loader import LoginConfig
        cfg = make_config()
        cfg.login = LoginConfig(login_url="http://x/login", username="u", password="p")
        m = Mapper(cfg)
        page = MagicMock()
        page.url = "http://x/dashboard"
        with patch("scraper.mapper.perform_login", AsyncMock()) as pl:
            await m._ensure_authenticated(page)
            pl.assert_not_called()

    async def test_performs_login_when_on_login_page(self, make_config):
        from config_loader import LoginConfig
        cfg = make_config()
        cfg.login = LoginConfig(login_url="http://x/login", username="u", password="p")
        m = Mapper(cfg)
        page = MagicMock()
        page.url = "http://x/login"
        with patch("scraper.mapper.perform_login", AsyncMock()) as pl:
            await m._ensure_authenticated(page)
            pl.assert_called_once_with(page, cfg.login)


class TestCleanup:
    async def test_closes_all_components(self, make_config):
        m = Mapper(make_config())
        m.page = AsyncMock()
        m.context = AsyncMock()
        m.browser = AsyncMock()
        m.playwright = AsyncMock()
        await m.cleanup()
        m.page.close.assert_called_once()
        m.context.close.assert_called_once()
        m.browser.close.assert_called_once()
        m.playwright.stop.assert_called_once()

    async def test_tolerates_none_attributes(self, make_config):
        m = Mapper(make_config())
        await m.cleanup()  # should not raise

    async def test_partial_cleanup(self, make_config):
        m = Mapper(make_config())
        m.page = AsyncMock()
        m.browser = AsyncMock()
        await m.cleanup()
        m.page.close.assert_called_once()
        m.browser.close.assert_called_once()
