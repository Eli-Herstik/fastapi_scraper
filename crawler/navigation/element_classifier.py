"""Classify interactive elements: destructive actions, date pickers, clickables."""
import logging
from typing import Iterable, List

from playwright.async_api import Page, Locator

from .selectors import (
    CLICKABLE_SELECTORS,
    DATE_INPUT_TYPES,
    DATE_PICKER_PATTERNS,
    DESTRUCTIVE_PATTERNS,
    DESTRUCTIVE_TEXT_EXACT,
)

logger = logging.getLogger(__name__)


async def is_destructive_action(element, text: str = "", exclude_patterns: Iterable[str] = ()) -> bool:
    """Check if element action is destructive or dismissive (logout, delete, close, etc.)."""
    if not text:
        try:
            text = await element.text_content() or ""
        except Exception:
            text = ""

    text_lower = text.strip().lower()

    href = ""
    classes = ""
    element_id = ""
    aria_label = ""
    try:
        href = (await element.get_attribute('href') or "").lower()
    except Exception:
        pass
    try:
        classes = (await element.get_attribute('class') or "").lower()
        element_id = (await element.get_attribute('id') or "").lower()
    except Exception:
        pass
    try:
        aria_label = (await element.get_attribute('aria-label') or "").lower()
    except Exception:
        pass

    searchable = [text_lower, href, classes, element_id, aria_label]

    for pattern in exclude_patterns:
        pattern_lower = pattern.lower()
        if any(pattern_lower in s for s in searchable):
            return True

    for pattern in DESTRUCTIVE_PATTERNS:
        if any(pattern in s for s in searchable):
            return True

    if text_lower in DESTRUCTIVE_TEXT_EXACT:
        return True

    return False


async def is_date_picker_element(element) -> bool:
    """Check if element is a date picker trigger that should be skipped."""
    try:
        input_type = (await element.get_attribute('type') or "").lower()
        if input_type in DATE_INPUT_TYPES:
            return True
    except Exception:
        pass

    attrs = []
    for attr_name in ('class', 'id', 'aria-label', 'name'):
        try:
            attrs.append((await element.get_attribute(attr_name) or "").lower())
        except Exception:
            pass

    for attr_val in attrs:
        for pattern in DATE_PICKER_PATTERNS:
            if pattern in attr_val:
                return True

    try:
        is_date_related = await element.evaluate('''(el) => {
            const pickerAncestor = el.closest(
                '[class*="datepicker"], [class*="date-picker"], [class*="calendar"], '
              + '[class*="flatpickr"], [class*="mat-datepicker"], [class*="ant-picker"], '
              + '[class*="react-datepicker"]'
            );
            if (pickerAncestor) return true;
            const parent = el.parentElement;
            if (parent) {
                const dateInput = parent.querySelector(
                    'input[type="date"], input[type="datetime-local"], '
                  + 'input[type="time"], input[type="month"], input[type="week"]'
                );
                if (dateInput) return true;
            }
            return false;
        }''')
        if is_date_related:
            return True
    except Exception:
        pass

    return False


async def get_clickable_elements(
    page: Page,
    max_clicks: int,
    exclude_patterns: Iterable[str] = (),
) -> List[Locator]:
    """Get all clickable elements on current page, filtered and deduplicated."""
    all_elements: List[Locator] = []
    seen_elements = set()

    for selector in CLICKABLE_SELECTORS:
        try:
            page_elements = await page.query_selector_all(selector)
            for idx, elem in enumerate(page_elements):
                try:
                    locator = page.locator(selector).nth(idx)

                    try:
                        elem_html = await elem.evaluate('el => el.outerHTML')
                        if elem_html in seen_elements:
                            continue
                        seen_elements.add(elem_html)
                    except Exception:
                        pass

                    try:
                        if await locator.is_visible():
                            is_enabled = await elem.evaluate('''el => {
                                if (el.disabled) return false;
                                if (el.getAttribute('aria-disabled') === 'true') return false;
                                const style = window.getComputedStyle(el);
                                if (style.pointerEvents === 'none') return false;
                                return true;
                            }''')

                            if is_enabled and not await is_destructive_action(locator, exclude_patterns=exclude_patterns):
                                if await is_date_picker_element(elem):
                                    logger.debug("Skipping date picker element")
                                    continue
                                all_elements.append(locator)
                                if len(all_elements) >= max_clicks:
                                    return all_elements
                    except Exception:
                        continue
                except Exception:
                    continue
        except Exception:
            continue

    return all_elements[:max_clicks]
