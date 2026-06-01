"""Reactive login handling: triggered when the crawler lands on the configured login URL."""
import json
import logging
import os

from playwright.async_api import Page, TimeoutError as PlaywrightTimeoutError

from config_loader import LoginConfig

logger = logging.getLogger(__name__)


def is_on_login_page(page: Page, cfg: LoginConfig) -> bool:
    return page.url.startswith(cfg.login_url)


def storage_state_valid(cfg: LoginConfig) -> bool:
    path = cfg.storage_state_path
    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        return False
    try:
        with open(path, 'r', encoding='utf-8') as f:
            json.load(f)
        return True
    except (json.JSONDecodeError, OSError):
        return False


async def perform_login(page: Page, cfg: LoginConfig) -> None:
    """Drive the login flow on `page`, which is already sitting on the login URL.

    Waits for the URL to leave `cfg.login_url` (covering SSO round-trips), then
    persists the resulting session to `cfg.storage_state_path`.
    """
    logger.info("Performing login at %s", page.url)

    await _fill_and_submit(page, cfg)

    try:
        await page.wait_for_url(
            lambda url: not url.startswith(cfg.login_url),
            timeout=cfg.post_login_wait_ms + 30000,
        )
    except PlaywrightTimeoutError as e:
        raise RuntimeError(f"Login did not redirect away from {cfg.login_url}") from e

    try:
        await page.wait_for_load_state("networkidle", timeout=cfg.post_login_wait_ms + 5000)
    except PlaywrightTimeoutError:
        logger.debug("networkidle wait timed out after login; continuing")

    await page.context.storage_state(path=cfg.storage_state_path)
    logger.info("Login successful; storage_state saved to %s", cfg.storage_state_path)


async def _fill_and_submit(page: Page, cfg: LoginConfig) -> None:
    await page.wait_for_selector(cfg.username_selector, timeout=10000)
    await page.fill(cfg.username_selector, cfg.username)
    await page.fill(cfg.password_selector, cfg.password)

    for event in ("input", "change", "blur"):
        try:
            await page.dispatch_event(cfg.password_selector, event)
        except Exception:
            pass

    await page.click(cfg.submit_selector)
