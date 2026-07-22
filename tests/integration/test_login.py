"""Login flow + storage-state reuse integration tests."""
import json
import os

import pytest

import crawler.mapper as mapper_mod
from crawler import Mapper

pytestmark = pytest.mark.integration


async def _run(cfg):
    m = Mapper(cfg)
    try:
        await m.initialize()
        result = await m.map_website()
        return m, result
    finally:
        await m.cleanup()


class TestLogin:
    async def test_login_flow_persists_storage_state(self, login_config, test_servers):
        _, result = await _run(login_config)

        path = login_config.login.storage_state_path
        assert os.path.isfile(path) and os.path.getsize(path) > 0
        with open(path, "r", encoding="utf-8") as f:
            state = json.load(f)
        cookie_names = {c["name"] for c in state.get("cookies", [])}
        assert "session" in cookie_names

        api_host = f"localhost:{test_servers['api_port']}"
        hosts = [e["host"] for e in result["external_hosts"]]
        assert api_host in hosts

    async def test_storage_state_reuse_skips_login(self, login_config, monkeypatch):
        # First run: real login populates storage_state.
        await _run(login_config)
        assert os.path.isfile(login_config.login.storage_state_path)

        called = {"n": 0}

        async def spy(page, cfg):
            called["n"] += 1

        monkeypatch.setattr(mapper_mod, "perform_login", spy)

        await _run(login_config)
        assert called["n"] == 0

    async def test_invalid_storage_state_falls_back_to_login(self, login_config):
        path = login_config.login.storage_state_path
        with open(path, "w", encoding="utf-8"):
            pass  # zero-byte
        assert os.path.getsize(path) == 0

        await _run(login_config)

        assert os.path.getsize(path) > 0
        with open(path, "r", encoding="utf-8") as f:
            state = json.load(f)
        assert any(c["name"] == "session" for c in state.get("cookies", []))
