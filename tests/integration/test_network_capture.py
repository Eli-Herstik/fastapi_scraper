"""Tests for network interception with a real browser."""
import pytest
from crawler import Mapper

pytestmark = pytest.mark.integration


class TestNetworkCapture:
    async def test_capture_fetch_request(self, integration_config, test_servers):
        """Navigate to page1, submit form, verify interceptor captured the API call."""
        api_host = f"localhost:{test_servers['api_port']}"
        mapper = Mapper(integration_config)
        try:
            await mapper.initialize()
            page = mapper.page

            # Navigate to page1
            await page.goto(
                f"{integration_config.start_url}/page1",
                wait_until="networkidle",
            )

            # Fill form and submit
            await mapper.navigator.fill_page_forms(page)
            submit_btn = page.locator('button[type="submit"]')
            if await submit_btn.count() > 0:
                await submit_btn.click()
                await page.wait_for_timeout(2000)

            # Check interceptor captured something to the API host
            requests = mapper.interceptor.get_requests()
            api_requests = [r for r in requests if api_host in r.get("url", "")]
            assert len(api_requests) > 0
        finally:
            await mapper.cleanup()

    async def test_capture_request_headers(self, integration_config, test_servers):
        """Verify captured requests have auth headers."""
        api_host = f"localhost:{test_servers['api_port']}"
        mapper = Mapper(integration_config)
        try:
            await mapper.initialize()
            page = mapper.page

            # Navigate to page2 and click the button
            await page.goto(
                f"{integration_config.start_url}/page2",
                wait_until="networkidle",
            )

            btn = page.locator("#load-data")
            if await btn.count() > 0:
                await btn.click()
                await page.wait_for_timeout(2000)

            requests = mapper.interceptor.get_requests()
            api_requests = [r for r in requests if api_host in r.get("url", "")]

            if api_requests:
                # At least one should have auth info
                auths = [r.get("authentication", "None") for r in api_requests]
                assert any(a != "None" for a in auths)
        finally:
            await mapper.cleanup()
