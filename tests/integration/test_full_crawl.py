"""End-to-end crawl tests against the local test server."""
import pytest
from crawler import Mapper

pytestmark = pytest.mark.integration


class TestFullCrawl:
    async def test_crawl_output_structure(self, integration_config):
        mapper = Mapper(integration_config)
        try:
            await mapper.initialize()
            result = await mapper.map_website()

            assert "external_hosts" in result
            for entry in result["external_hosts"]:
                assert "host" in entry
                assert "authentication" in entry
        finally:
            await mapper.cleanup()

    async def test_crawl_discovers_api_hosts(self, integration_config, test_servers):
        api_host = f"localhost:{test_servers['api_port']}"
        mapper = Mapper(integration_config)
        try:
            await mapper.initialize()
            result = await mapper.map_website()

            hosts = [entry["host"] for entry in result["external_hosts"]]
            assert api_host in hosts
        finally:
            await mapper.cleanup()

    async def test_crawl_detects_bearer_auth(self, integration_config, test_servers):
        api_host = f"localhost:{test_servers['api_port']}"
        mapper = Mapper(integration_config)
        try:
            await mapper.initialize()
            result = await mapper.map_website()

            api_entry = next(
                (e for e in result["external_hosts"] if e["host"] == api_host), None
            )
            assert api_entry is not None
            assert api_entry["authentication"] != "None"
        finally:
            await mapper.cleanup()

    async def test_crawl_skips_destructive_urls(self, integration_config):
        mapper = Mapper(integration_config)
        try:
            await mapper.initialize()
            await mapper.map_website()

            visited = mapper.navigator.visited_urls
            assert not any("/logout" in url for url in visited)
        finally:
            await mapper.cleanup()

    async def test_crawl_respects_max_depth(self, integration_config):
        integration_config.max_depth = 1
        mapper = Mapper(integration_config)
        try:
            await mapper.initialize()
            await mapper.map_website()

            assert len(mapper.navigator.visited_urls) >= 1
        finally:
            await mapper.cleanup()
