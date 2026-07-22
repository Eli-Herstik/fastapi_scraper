"""Tests for form filling with a real browser."""
import pytest
from crawler import Mapper

pytestmark = pytest.mark.integration


class TestFormFilling:
    async def test_fill_text_inputs(self, integration_config):
        """Navigate to page1, fill forms, verify inputs have values."""
        mapper = Mapper(integration_config)
        try:
            await mapper.initialize()
            page = mapper.page

            await page.goto(
                f"{integration_config.start_url}/page1",
                wait_until="networkidle",
            )

            await mapper.navigator.fill_page_forms(page)

            # Check email field has a value
            email_val = await page.locator('[name="email"]').input_value()
            assert email_val != ""

            # Check password field has a value
            password_val = await page.locator('[name="password"]').input_value()
            assert password_val != ""
        finally:
            await mapper.cleanup()

    async def test_fill_email_field(self, integration_config):
        """Verify email field gets an email-like value."""
        mapper = Mapper(integration_config)
        try:
            await mapper.initialize()
            page = mapper.page

            await page.goto(
                f"{integration_config.start_url}/page1",
                wait_until="networkidle",
            )

            await mapper.navigator.fill_page_forms(page)

            email_val = await page.locator('[name="email"]').input_value()
            assert "@" in email_val
        finally:
            await mapper.cleanup()
