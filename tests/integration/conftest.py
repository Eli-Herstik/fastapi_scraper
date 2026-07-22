"""Integration test fixtures."""
import asyncio
import os
import threading
import socket
from pathlib import Path

import pytest
import pytest_asyncio
from aiohttp import web
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from config_loader import Config, FormConfig, LoginConfig
from tests.integration.test_server import create_web_app, create_api_app

# --------------------------------------------------------------------------------
# Database fixtures
#
# These run against Postgres, because that is what production runs on and because the
# schema is now owned by alembic rather than create_all(). Set TEST_DATABASE_URL to a
# database the suite may freely TRUNCATE; without it the DB-backed tests skip, so
# `pytest tests/unit` stays instant and dependency-free.
# --------------------------------------------------------------------------------

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL")

_REPO_ROOT = Path(__file__).resolve().parents[2]

# Every table the suite touches. TRUNCATE ... CASCADE handles the apps <-> scans cycle.
_ALL_TABLES = "apps, scans, findings, submissions, scan_events"


@pytest.fixture(scope="session")
def migrated_database_url() -> str:
    """Bring the test database up to head once per session, and hand back its URL.

    Runs the real migration chain rather than create_all() — that is what catches a
    broken migration before it reaches a deploy.
    """
    if not TEST_DATABASE_URL:
        pytest.skip(
            "TEST_DATABASE_URL is not set; skipping database tests. "
            "Example: postgresql+asyncpg://postgres:postgres@localhost:5432/gatekeeper_test"
        )

    from alembic import command
    from alembic.config import Config as AlembicConfig

    # alembic/env.py resolves the URL through api.db._database_url(), which reads
    # DATABASE_URL — so point that at the test database for the duration of the run.
    previous = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = TEST_DATABASE_URL
    try:
        cfg = AlembicConfig(str(_REPO_ROOT / "alembic.ini"))
        cfg.set_main_option("script_location", str(_REPO_ROOT / "alembic"))
        command.upgrade(cfg, "head")
    finally:
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous

    return TEST_DATABASE_URL


@pytest_asyncio.fixture
async def session_factory(migrated_database_url):
    """A session factory against a truncated-clean test database."""
    from api.db import make_session_factory

    engine = create_async_engine(migrated_database_url, future=True)
    async with engine.begin() as conn:
        await conn.execute(text(f"TRUNCATE {_ALL_TABLES} RESTART IDENTITY CASCADE"))

    yield make_session_factory(engine)

    await engine.dispose()


@pytest_asyncio.fixture
async def client(session_factory):
    """(AsyncClient, session_factory) against the real app, lifespan bypassed.

    Lifespan loads config, builds an EventBus and semaphores, and asserts the schema is
    migrated — none of which route-level tests need. State is seeded directly instead.
    """
    from api.main import app as fastapi_app

    fastapi_app.state.session_factory = session_factory
    fastapi_app.state.scan_tasks = {}
    fastapi_app.state.background_tasks = set()

    transport = ASGITransport(app=fastapi_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac, session_factory


def _get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("localhost", 0))
        return s.getsockname()[1]


def _run_server(app, port, ready_event, loop_holder):
    """Run an aiohttp app in a background thread with its own event loop."""
    loop = asyncio.new_event_loop()
    loop_holder.append(loop)
    runner = web.AppRunner(app)
    loop.run_until_complete(runner.setup())
    site = web.TCPSite(runner, "localhost", port)
    loop.run_until_complete(site.start())
    ready_event.set()
    loop.run_forever()
    loop.run_until_complete(runner.cleanup())
    loop.close()


@pytest.fixture(scope="session")
def test_servers():
    """Start both web and API servers in background threads, yield ports, then shut down."""
    api_port = _get_free_port()
    web_port = _get_free_port()

    # Start API server
    api_ready = threading.Event()
    api_loop_holder = []
    api_app = create_api_app()
    api_thread = threading.Thread(
        target=_run_server, args=(api_app, api_port, api_ready, api_loop_holder), daemon=True
    )
    api_thread.start()
    api_ready.wait(timeout=10)

    # Start web server (needs api_port for HTML templates)
    web_ready = threading.Event()
    web_loop_holder = []
    web_app = create_web_app(api_port)
    web_thread = threading.Thread(
        target=_run_server, args=(web_app, web_port, web_ready, web_loop_holder), daemon=True
    )
    web_thread.start()
    web_ready.wait(timeout=10)

    yield {"web_port": web_port, "api_port": api_port}

    # Shut down servers
    for holder in [api_loop_holder, web_loop_holder]:
        if holder:
            holder[0].call_soon_threadsafe(holder[0].stop)


@pytest.fixture
def web_url(test_servers):
    return f"http://localhost:{test_servers['web_port']}"


@pytest.fixture
def api_url(test_servers):
    return f"http://localhost:{test_servers['api_port']}"


@pytest.fixture
def integration_config(test_servers):
    """Config pointing at the local test server with short timeouts."""
    return Config(
        start_url=f"http://localhost:{test_servers['web_port']}",
        max_depth=2,
        max_clicks_per_page=10,
        wait_timeout=15000,
        network_idle_timeout=1000,
        form_filling=FormConfig(),
        exclude_patterns=["logout", "delete", "remove"],
    )


@pytest.fixture
def login_config(test_servers, tmp_path):
    """Config pointing at a protected page with a login block."""
    web_port = test_servers["web_port"]
    return Config(
        start_url=f"http://localhost:{web_port}/protected",
        max_depth=1,
        max_clicks_per_page=5,
        wait_timeout=15000,
        network_idle_timeout=1000,
        form_filling=FormConfig(),
        exclude_patterns=["logout", "delete", "remove"],
        login=LoginConfig(
            login_url=f"http://localhost:{web_port}/login",
            username="test@example.com",
            password="hunter2",
            username_selector="#username",
            password_selector="input[type='password']",
            submit_selector="button[type='submit']",
            post_login_wait_ms=2000,
            storage_state_path=str(tmp_path / "storage_state.json"),
            reuse_storage_state=True,
        ),
    )
