"""Reactive login handling: triggered when the crawler lands on the configured login URL."""
import json
import logging
import os
import time
from urllib.parse import urlparse

from playwright.async_api import Error as PlaywrightError, Page, TimeoutError as PlaywrightTimeoutError

from config_loader import LoginConfig

logger = logging.getLogger(__name__)


def _origin(url: str) -> tuple:
    parsed = urlparse(url)
    return (parsed.scheme.lower(), parsed.netloc.lower())


def _matches_login_url(url: str, login_url: str) -> bool:
    if _origin(url) != _origin(login_url):
        return False
    path = urlparse(url).path.rstrip('/')
    login_path = urlparse(login_url).path.rstrip('/')
    return path == login_path or path.startswith(login_path + '/')


def _is_login_url(url: str, cfg: LoginConfig) -> bool:
    return any(_matches_login_url(url, candidate) for candidate in cfg.login_urls)


def is_on_login_page(page: Page, cfg: LoginConfig) -> bool:
    return _is_login_url(page.url, cfg)


def storage_state_valid(cfg: LoginConfig) -> bool:
    """Cheap local check that the stored state could plausibly hold a session.

    Rejects files that are structurally not a Playwright storage state or that
    contain no usable session material (no unexpired cookies and no localStorage
    entries). Whether the session actually still works is left to the reactive
    login flow, which recovers if a reused state lands on the login page.
    """
    path = cfg.storage_state_path
    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        return False
    try:
        with open(path, 'r', encoding='utf-8') as f:
            state = json.load(f)
    except (json.JSONDecodeError, OSError):
        return False

    if not isinstance(state, dict):
        return False
    cookies = state.get('cookies')
    origins = state.get('origins')
    if not isinstance(cookies, list) or not isinstance(origins, list):
        return False

    now = time.time()
    has_live_cookie = any(
        isinstance(c, dict) and (c.get('expires', -1) == -1 or c.get('expires', -1) > now)
        for c in cookies
    )
    has_local_storage = any(
        isinstance(o, dict) and o.get('localStorage')
        for o in origins
    )
    return has_live_cookie or has_local_storage


async def perform_login(page: Page, cfg: LoginConfig, app_url: str) -> None:
    """Drive the login flow on `page`, which is already sitting on the login URL.

    Waits until the URL is back on `app_url`'s origin and off the login URL —
    an off-origin SSO/IdP hop keeps the wait pending until the redirect back —
    then re-navigates to `app_url` to verify the session is authorized — the
    document response must not be an error status, the app must no longer be
    presenting a login form, and the login must have established a session: either
    one of `cfg.session_cookie_names` is present, or (when none are configured) a
    generic check that authenticating introduced new app-origin session material —
    a new/changed cookie or localStorage. The generic check only warns by default;
    `cfg.require_session_material` promotes it to a hard failure. Only then is the
    state persisted to `cfg.storage_state_path`.
    This also normalizes where the crawl resumes:
    on `app_url` itself rather than wherever the login redirect chain landed.
    """
    logger.info("Performing login at %s", page.url)

    app_origin = _origin(app_url)
    use_generic_material_check = not cfg.session_cookie_names
    before_cookies = (
        await _app_cookie_snapshot(page, app_url) if use_generic_material_check else {}
    )
    await _fill_and_submit(page, cfg)

    try:
        await page.wait_for_url(
            lambda url: _origin(url) == app_origin and not _is_login_url(url, cfg),
            timeout=cfg.post_login_wait_ms + 30000,
        )
    except PlaywrightTimeoutError as e:
        raise RuntimeError(
            f"Login did not land back on {app_url} away from {cfg.login_urls}"
        ) from e

    try:
        await page.wait_for_load_state("networkidle", timeout=cfg.post_login_wait_ms + 5000)
    except PlaywrightTimeoutError:
        logger.debug("networkidle wait timed out after login; continuing")

    response = await page.goto(app_url)
    if response is not None and response.status >= 400:
        raise RuntimeError(
            f"Login completed but {app_url} returned HTTP {response.status}"
        )

    try:
        await page.wait_for_load_state("networkidle", timeout=cfg.post_login_wait_ms + 5000)
    except PlaywrightTimeoutError:
        logger.debug("networkidle wait on %s timed out; continuing", app_url)

    if await _login_form_visible(page, cfg):
        raise RuntimeError(
            f"Login completed but {app_url} still presents a login form; "
            "credentials were likely rejected"
        )

    if cfg.session_cookie_names:
        if not await _app_session_cookie_present(page, cfg, app_url):
            raise RuntimeError(
                f"Login completed but {app_url} set none of the expected session "
                f"cookies {cfg.session_cookie_names}; credentials were likely rejected"
            )
    else:
        after_cookies = await _app_cookie_snapshot(page, app_url)
        after_localstorage = await _app_local_storage_keys(page, app_url)
        if not _login_added_session_material(before_cookies, after_cookies, after_localstorage):
            message = (
                f"Login on {app_url} added no new session material: no new or "
                "changed app-origin cookie and no localStorage entry; the session "
                "may not have been established"
            )
            if cfg.require_session_material:
                raise RuntimeError(message)
            logger.warning(message)

    await page.context.storage_state(path=cfg.storage_state_path)
    logger.info("Login successful; storage_state saved to %s", cfg.storage_state_path)


async def _login_form_visible(page: Page, cfg: LoginConfig) -> bool:
    """Whether a login field is still visible — a positive "not authenticated" signal.

    The URL and HTTP-status checks in `perform_login` both pass for a failed login
    that ends on an app-origin page returning HTTP 200: a common SPA pattern, or a
    silent bounce back to the identity provider. A still-visible password or username
    field on `app_url` is the content-level tell that we are being asked to log in
    again, so the submitted credentials never took.

    Best-effort: a selector that fails to evaluate is treated as not-visible rather
    than aborting the check, matching the leniency elsewhere in this module.
    """
    for selector in (cfg.password_selector, cfg.username_selector):
        try:
            element = await page.query_selector(selector)
            if element is not None and await element.is_visible():
                return True
        except PlaywrightError as e:
            logger.debug("login-form probe for %r failed: %s", selector, e)
    return False


async def _app_session_cookie_present(page: Page, cfg: LoginConfig, app_url: str) -> bool:
    """Whether the app has set one of its configured session cookies on `app_url`.

    A positive "authenticated" signal that complements `_login_form_visible`'s
    negative one: a genuine login makes the app mint its OWN session cookie on the
    app origin, whereas a failed login that merely bounces through the IdP leaves
    only IdP-origin cookies behind. `context.cookies(app_url)` returns just the
    cookies the app origin would receive, so identity-provider (`login_url`)
    cookies are excluded from the check.

    Opt-in: with no `cfg.session_cookie_names` to look for this returns True, so
    apps that authenticate via localStorage / bearer tokens and set no cookie are
    unaffected. A cookie probe that fails to evaluate is treated as "present"
    rather than aborting the login, matching the leniency elsewhere in this module.
    """
    wanted = cfg.session_cookie_names
    if not wanted:
        return True
    try:
        cookies = await page.context.cookies(app_url)
    except PlaywrightError as e:
        logger.debug("session-cookie probe failed: %s", e)
        return True
    wanted_set = set(wanted)
    return any(c.get("name") in wanted_set and c.get("value") for c in cookies)


async def _app_cookie_snapshot(page: Page, app_url: str) -> dict:
    """Best-effort ``{name: value}`` of the cookies the app origin would receive.

    Uses ``context.cookies(app_url)``, so identity-provider cookies on other
    origins are excluded. A probe failure yields an empty snapshot rather than
    aborting the login.
    """
    snapshot: dict = {}
    try:
        cookies = await page.context.cookies(app_url)
    except PlaywrightError as e:
        logger.debug("cookie snapshot for %s failed: %s", app_url, e)
        return snapshot
    for c in cookies:
        name = c.get("name")
        if name:
            snapshot[name] = c.get("value")
    return snapshot


async def _app_local_storage_keys(page: Page, app_url: str) -> set:
    """Best-effort set of localStorage keys for the app origin.

    Only meaningful while the page is on the app origin (e.g. right after the
    post-login ``goto(app_url)``); returns an empty set when the page is elsewhere
    or the probe fails. Covers token/SPA apps that persist a session in
    localStorage rather than a cookie.
    """
    if _origin(page.url) != _origin(app_url):
        return set()
    try:
        keys = await page.evaluate("() => Object.keys(window.localStorage)")
    except PlaywrightError as e:
        logger.debug("localStorage probe on %s failed: %s", app_url, e)
        return set()
    return set(keys) if isinstance(keys, list) else set()


def _login_added_session_material(
    before_cookies: dict, after_cookies: dict, after_localstorage: set
) -> bool:
    """Whether logging in introduced new session material on the app origin.

    Differential, so material present regardless of authentication — analytics,
    consent, load-balancer affinity, and the pre-auth OIDC ``state`` cookie — is
    subtracted: it sits in ``before_cookies`` unchanged. A genuine login adds a
    new cookie name or rotates an existing cookie's value (session-fixation
    defence). localStorage is consulted only for cookieless apps, where any key on
    the authenticated page is the token/SPA equivalent of a session cookie.
    """
    for name, value in after_cookies.items():
        if value and (name not in before_cookies or before_cookies[name] != value):
            return True
    if not after_cookies and after_localstorage:
        return True
    return False


async def _dispatch_form_events(page: Page, selector: str) -> None:
    """Fire synthetic input/change/blur so framework-driven forms register the typed value.

    Best-effort: a field that doesn't handle a given event is not fatal. We swallow only
    Playwright-level failures (and log them) rather than masking arbitrary Python errors.
    """
    for event in ("input", "change", "blur"):
        try:
            await page.dispatch_event(selector, event)
        except PlaywrightError as e:
            logger.debug("dispatch_event(%r, %r) failed: %s", selector, event, e)


async def _fill_and_submit(page: Page, cfg: LoginConfig) -> None:
    await page.wait_for_selector(cfg.username_selector, timeout=10000)
    await page.fill(cfg.username_selector, cfg.username)
    await page.fill(cfg.password_selector, cfg.password)

    await _dispatch_form_events(page, cfg.username_selector)
    await _dispatch_form_events(page, cfg.password_selector)

    await page.click(cfg.submit_selector)
