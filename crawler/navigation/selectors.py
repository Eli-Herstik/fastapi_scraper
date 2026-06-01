"""CSS/ARIA selector constants used by navigation handling."""

INTERACTIVE_SELECTORS = (
    'button, a[href], [role="button"], [role="menuitem"], '
    '[role="option"], input[type="submit"], input[type="button"]'
)

CLICKABLE_SELECTORS = [
    'a[href]',
    'button:not([disabled])',
    'input[type="submit"]:not([disabled])',
    '[onclick]',
    '[role="button"]',
    '[role="link"]',
    '[role="menuitem"]',
    'input[type="button"]:not([disabled])',
]

DATE_PICKER_PATTERNS = [
    'datepicker', 'date-picker', 'calendar', 'datetimepicker',
    'datetime-picker', 'daterangepicker', 'date-range-picker',
    'flatpickr', 'pikaday', 'react-datepicker', 'mat-datepicker',
    'ant-calendar', 'ant-picker',
]

DATE_INPUT_TYPES = {'date', 'datetime-local', 'time', 'month', 'week'}

CALENDAR_OVERLAY_SELECTORS = [
    '[class*="datepicker"]',
    '[class*="date-picker"]',
    '[class*="calendar"]',
    '[class*="flatpickr-calendar"]',
    '[class*="react-datepicker"]',
    '.mat-datepicker-popup',
    '[role="dialog"]:has([role="grid"])',
]

MODAL_CONTAINER_SELECTORS = [
    'dialog[open]',
    '[role="dialog"]',
    '[role="alertdialog"]',
    '.modal-content',
    '.modal-dialog',
    '.modal',
    '[class*="modal"]',
    '.overlay',
    '[class*="overlay"]',
    '.cdk-overlay-container',
    '.cdk-overlay-pane',
    '[class*="cdk-overlay"]',
    '.mat-mdc-menu-panel',
    '[class*="mat-menu"]',
]

POPUP_CONTAINER_SELECTORS = [
    '.cdk-overlay-pane',
    '[class*="cdk-overlay"]',
    '.mat-mdc-menu-panel',
    '[class*="mat-menu"]',
    '[role="menu"]',
    '[role="listbox"]',
    '.dropdown-menu',
    '[class*="dropdown"]',
]

DISMISS_SELECTORS = [
    'button[aria-label="Close"]',
    'button[aria-label="close"]',
    '.close-button',
    '.modal-close',
    'button:has-text("Close")',
    'button:has-text("Cancel")',
    'button:has-text("No thanks")',
    'button:has-text("Dismiss")',
]

DROPDOWN_OPTION_SELECTORS = [
    '[role="option"]',
    '.dropdown-item',
    '.select2-results__option',
    '.ant-select-item-option',
    '.el-select-dropdown__item',
    '.mat-option',
    '.v-list-item',
]

AFFIRMATIVE_ACTION_SELECTORS = [
    'button:has-text("Confirm")',
    'button:has-text("Yes")',
    'button:has-text("Accept")',
    'button:has-text("Submit")',
    'button:has-text("Continue")',
    'button:has-text("Save")',
    'button:has-text("Create")',
    'button:has-text("Update")',
    'button:has-text("Delete")',
    'input[type="submit"]',
    '.btn-primary:not([disabled])',
]

DESTRUCTIVE_PATTERNS = [
    'logout', 'delete', 'remove', 'destroy', 'clear',
    'close', 'cancel', 'dismiss', 'no thanks',
]

# Patterns that should only match the visible text content exactly (stripped),
# not as substrings in URLs, classes, or other attributes.
DESTRUCTIVE_TEXT_EXACT = ['x', '\u00d7']  # "x" and "×" (close buttons)
