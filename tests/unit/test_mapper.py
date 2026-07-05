"""Tests for crawler.Mapper (orchestrator, without launching a real browser)."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from crawler import Mapper
from crawler.navigation import NavigationHandler
from crawler.navigation.dom_hasher import DOMHasher
from crawler.network import NetworkInterceptor


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
        assert result["external_hosts"] == []

    async def test_aggregates_interceptor_requests(self, make_config):
        m = Mapper(make_config())
        m.page = MagicMock()
        m.navigator.navigate_to = AsyncMock(return_value=True)
        m._ensure_authenticated = AsyncMock()
        m._explore_page = AsyncMock()
        m.interceptor.requests = [
            {"url": "http://api.example.com/x", "authentication": "bearer"},
            {"url": "http://other.com/y", "authentication": "unauthenticated"},
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
        with patch("crawler.mapper.perform_login", AsyncMock()) as pl:
            await m._ensure_authenticated(page)
            pl.assert_not_called()

    async def test_performs_login_when_on_login_page(self, make_config):
        from config_loader import LoginConfig
        cfg = make_config()
        cfg.login = LoginConfig(login_url="http://x/login", username="u", password="p")
        m = Mapper(cfg)
        page = MagicMock()
        page.url = "http://x/login"
        with patch("crawler.mapper.perform_login", AsyncMock()) as pl:
            await m._ensure_authenticated(page)
            pl.assert_called_once_with(page, cfg.login, cfg.start_url)


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


class TestCloseExtraPages:
    async def test_closes_popups_but_not_active_page(self, make_config):
        m = Mapper(make_config())
        active, popup1, popup2 = AsyncMock(), AsyncMock(), AsyncMock()
        m.page = active
        m.context = MagicMock()
        m.context.pages = [active, popup1, popup2]
        await m._close_extra_pages()
        active.close.assert_not_called()
        popup1.close.assert_called_once()
        popup2.close.assert_called_once()

    async def test_tolerates_no_context(self, make_config):
        m = Mapper(make_config())
        m.context = None
        await m._close_extra_pages()  # should not raise

    async def test_swallows_close_errors(self, make_config):
        m = Mapper(make_config())
        active, bad = AsyncMock(), AsyncMock()
        bad.close = AsyncMock(side_effect=Exception("already closed"))
        m.page = active
        m.context = MagicMock()
        m.context.pages = [active, bad]
        await m._close_extra_pages()  # must not propagate
        bad.close.assert_called_once()


class TestShouldRecycle:
    def test_true_when_threshold_reached(self, make_config):
        m = Mapper(make_config(recycle_after_pages=5))
        m._pages_since_recycle = 5
        assert m._should_recycle() is True

    def test_false_below_threshold(self, make_config):
        m = Mapper(make_config(recycle_after_pages=5))
        m._pages_since_recycle = 4
        assert m._should_recycle() is False

    def test_disabled_when_zero(self, make_config):
        m = Mapper(make_config(recycle_after_pages=0))
        m._pages_since_recycle = 999
        assert m._should_recycle() is False


class TestProcessElement:
    async def test_returns_early_when_click_fails(self, make_config, mock_page, mock_element):
        m = Mapper(make_config())
        page = mock_page(url="http://x/base")
        m.navigator.click_element = AsyncMock(return_value=False)
        m._interact_with_new_elements = AsyncMock()
        m._maybe_explore_new_url = AsyncMock()
        await m._process_element(page, mock_element(text="Foo"), 0, 1, "http://x/base", 0)
        m._interact_with_new_elements.assert_not_called()
        m._maybe_explore_new_url.assert_not_called()
