"""Fill visible form fields (inputs, selects, click-dropdowns) on a page or container."""
import logging
import re

from playwright.async_api import Page

from config_loader import Config
from .selectors import DROPDOWN_OPTION_SELECTORS

logger = logging.getLogger(__name__)


class FormFiller:
    """Fill forms to enable submit buttons and trigger validation."""

    def __init__(self, config: Config):
        self.config = config

    async def fill(self, page: Page, root=None) -> None:
        """Fill forms on the page (or within a specific container)."""
        if not self.config.form_filling or not self.config.form_filling.enabled:
            return

        max_passes = 3
        for pass_idx in range(max_passes):
            fields_filled = await self._fill_pass(page, pass_idx, root=root)
            if fields_filled == 0:
                break
            await page.wait_for_timeout(500)

    async def _fill_pass(self, page: Page, pass_idx: int = 0, root=None) -> int:
        fields_filled = 0
        query_root = root or page
        try:
            inputs = await query_root.query_selector_all(
                'input:not([type="hidden"]):not([disabled]), '
                'textarea:not([disabled]):not([readonly]), '
                'select:not([disabled])'
            )

            for input_el in inputs:
                try:
                    if not await input_el.is_visible():
                        continue

                    tag_name = await input_el.evaluate('el => el.tagName.toLowerCase()')

                    if tag_name == 'select':
                        if await self._fill_select(input_el, page, pass_idx):
                            fields_filled += 1
                        continue

                    if pass_idx > 0:
                        current_value = await input_el.evaluate('el => el.value')
                    else:
                        current_value = await input_el.get_attribute('value')
                    if current_value:
                        continue

                    min_length = await self._get_minimum_length(input_el)
                    fill_value = await self._determine_fill_value(input_el)
                    if min_length > 0:
                        fill_value = self._pad_value(fill_value, min_length)
                        logger.debug("Adjusted value to meet minimum length %d", min_length)

                    try:
                        await input_el.clear(timeout=2000)
                    except Exception:
                        pass

                    dropdown_handled = await self._try_click_dropdown(input_el, page)

                    if not dropdown_handled:
                        try:
                            await input_el.type(fill_value, delay=50)
                        except Exception:
                            pass
                        await page.wait_for_timeout(300)

                        dropdown_handled = await self._try_dropdown_options(page)

                        if not dropdown_handled:
                            try:
                                await input_el.fill("", timeout=1000)
                                await page.wait_for_timeout(300)
                                dropdown_handled = await self._try_dropdown_options(page)
                                if not dropdown_handled:
                                    await input_el.type(fill_value, delay=50)
                                    await page.wait_for_timeout(300)
                            except Exception:
                                pass

                    try:
                        await input_el.dispatch_event('input')
                        await input_el.dispatch_event('change')
                        await input_el.dispatch_event('blur')
                    except Exception:
                        pass

                    await page.wait_for_timeout(300)

                    el_label = await self._get_element_label(input_el)
                    if dropdown_handled:
                        logger.debug("Filled form field via dropdown selection%s", el_label)
                    else:
                        logger.debug("Filled form field with: %s%s", fill_value, el_label)

                    fields_filled += 1
                    await page.wait_for_timeout(self.config.form_filling.fill_delay)

                except Exception:
                    continue

            await page.wait_for_timeout(500)

        except Exception as e:
            logger.error("Error filling forms: %s", e)

        return fields_filled

    async def _fill_select(self, input_el, page: Page, pass_idx: int) -> bool:
        current_val = await input_el.evaluate('el => el.value')
        if pass_idx > 0 and current_val and current_val.strip() != '':
            return False

        options_data = await input_el.evaluate('''el => {
            return Array.from(el.options).map((o, idx) => ({
                index: idx,
                value: o.value,
                disabled: o.disabled
            }));
        }''')

        if not options_data:
            return False

        valid_options = [o for o in options_data if not o.get('disabled') and o.get('value', '').strip() != '']

        if current_val and current_val.strip() != '' and any(o.get('value') == current_val for o in valid_options):
            return False

        el_label = await self._get_element_label(input_el)
        if valid_options:
            selected_val = valid_options[0]['value']
            await input_el.select_option(value=selected_val)
            logger.debug("Selected select option: %s%s", selected_val, el_label)
        elif len(options_data) > 1:
            await input_el.select_option(index=1)
            logger.debug("Selected select option by index 1%s", el_label)
        else:
            await input_el.select_option(index=0)
            logger.debug("Selected select option by index 0%s", el_label)

        await input_el.dispatch_event('change')
        await page.wait_for_timeout(self.config.form_filling.fill_delay)
        return True

    async def _determine_fill_value(self, input_el) -> str:
        fill_value = "Test Value"

        if self.config.form_filling.defaults:
            for selector, value in self.config.form_filling.defaults.items():
                is_match = await input_el.evaluate(f'(el) => el.matches("{selector}")')
                if is_match:
                    return value

        input_type = await input_el.get_attribute('type') or 'text'
        input_name = await input_el.get_attribute('name') or ''
        input_id = await input_el.get_attribute('id') or ''
        lower_name = (input_name + input_id).lower()

        if input_type == 'email' or 'email' in lower_name:
            return "test@example.com"
        if input_type == 'password' or 'password' in lower_name:
            return "Password123!"
        if input_type == 'tel' or 'phone' in lower_name:
            return "555-012345"
        if input_type == 'number':
            return "1"
        if input_type == 'url':
            return "https://example.com"
        if input_type == 'date':
            return "2024-01-01"

        return fill_value

    async def _try_click_dropdown(self, input_el, page: Page) -> bool:
        try:
            await input_el.click(timeout=2000)
            await page.wait_for_timeout(500)
            return await self._try_dropdown_options(page, log_label="click-triggered")
        except Exception as e:
            logger.warning("Error checking click dropdown: %s", e)
            return False

    async def _try_dropdown_options(self, page: Page, log_label: str = "typing-triggered") -> bool:
        try:
            for opt_selector in DROPDOWN_OPTION_SELECTORS:
                options = await page.query_selector_all(opt_selector)
                for opt in options:
                    if await opt.is_visible():
                        try:
                            await opt.scroll_into_view_if_needed(timeout=2000)
                        except Exception:
                            pass
                        await opt.click(timeout=2000)
                        logger.debug("Selected %s dropdown option: %s", log_label, opt_selector)
                        await page.wait_for_timeout(300)
                        return True
        except Exception:
            pass
        return False

    async def _get_element_label(self, input_el) -> str:
        try:
            text = (await input_el.evaluate('el => el.textContent') or "").strip()
            if not text:
                text = (await input_el.get_attribute('aria-label') or "").strip()
            if not text:
                text = (await input_el.get_attribute('placeholder') or "").strip()
            if not text:
                text = (await input_el.get_attribute('name') or "").strip()
            if not text:
                text = (await input_el.get_attribute('id') or "").strip()
            if text:
                return f" ('{text[:30]}')"
        except Exception:
            pass
        return ""

    async def _get_minimum_length(self, input_el) -> int:
        try:
            minlength = await input_el.get_attribute('minlength')
            if minlength and minlength.isdigit():
                return int(minlength)

            pattern = await input_el.get_attribute('pattern')
            if pattern:
                match = re.search(r'\.{\s*(\d+)\s*,', pattern)
                if match:
                    return int(match.group(1))

            required = await input_el.get_attribute('required')
            if required is not None:
                input_type = await input_el.get_attribute('type') or 'text'
                if input_type == 'password':
                    return 8
        except Exception:
            pass

        return 0

    @staticmethod
    def _pad_value(base_value: str, min_length: int) -> str:
        if len(base_value) >= min_length:
            return base_value

        padding_needed = min_length - len(base_value)
        if '@' in base_value:
            local_part, domain = base_value.split('@', 1)
            local_part += 'x' * padding_needed
            return f"{local_part}@{domain}"
        return base_value + 'x' * padding_needed
