"""401 WWW-Authenticate and IdP-redirect capture tests."""
import pytest

from config_loader import Config, FormConfig
from crawler import Mapper

pytestmark = pytest.mark.integration


def _cfg(test_servers, path: str) -> Config:
    return Config(
        start_url=f"http://localhost:{test_servers['web_port']}{path}",
        max_depth=1,
        max_clicks_per_page=3,
        wait_timeout=15000,
        network_idle_timeout=1500,
        form_filling=FormConfig(enabled=False),
        exclude_patterns=["logout", "delete", "remove"],
    )


class TestAuthCapture:
    async def test_401_bearer_challenge_captured(self, test_servers):
        mapper = Mapper(_cfg(test_servers, "/unauth"))
        api_host = f"localhost:{test_servers['api_port']}"
        try:
            await mapper.initialize()
            result = await mapper.map_website()
            entry = next((e for e in result["external_hosts"] if e["host"] == api_host), None)
            assert entry is not None, f"API host {api_host} not captured"
            assert entry["authentication"].startswith("Required: Bearer"), (
                f"got {entry['authentication']!r}"
            )
        finally:
            await mapper.cleanup()

    async def test_idp_redirect_propagates(self, test_servers):
        mapper = Mapper(_cfg(test_servers, "/idp-trigger"))
        api_host = f"localhost:{test_servers['api_port']}"
        try:
            await mapper.initialize()
            result = await mapper.map_website()
            entry = next((e for e in result["external_hosts"] if e["host"] == api_host), None)
            assert entry is not None, f"API host {api_host} not captured"
            assert entry["authentication"] == "oauth: Auth0", (
                f"got {entry['authentication']!r}"
            )
        finally:
            await mapper.cleanup()
