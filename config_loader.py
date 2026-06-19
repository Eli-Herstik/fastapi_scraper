import json
import os
from typing import Dict, Optional
from dataclasses import dataclass


@dataclass
class FormConfig:
    """Form filling configuration."""
    enabled: bool = True
    fill_delay: int = 100
    defaults: Dict[str, str] = None  # selector -> value mapping

    def __post_init__(self):
        if self.defaults is None:
            self.defaults = {}


@dataclass
class LoginConfig:
    """Login flow configuration. Presence of this block enables login handling."""
    login_url: str
    username: str
    password: str
    username_selector: str = "#username"
    password_selector: str = "input[type='password']"
    submit_selector: str = "button[type='submit']"
    post_login_wait_ms: int = 3000
    storage_state_path: str = "storage_state.json"
    reuse_storage_state: bool = True
    # Additional login URLs (beyond `login_url`) that should also be recognized as
    # the login page — e.g. an SSO/IdP reachable under more than one hostname.
    extra_login_urls: list = None

    def __post_init__(self):
        if self.extra_login_urls is None:
            self.extra_login_urls = []

    @property
    def login_urls(self) -> list:
        """All URLs recognized as the login page; `login_url` first (canonical)."""
        return [self.login_url, *self.extra_login_urls]


@dataclass
class Config:
    """Main configuration class."""
    start_url: str
    max_depth: int
    max_clicks_per_page: int
    wait_timeout: int = 30000
    network_idle_timeout: int = 2000
    form_filling: FormConfig = None
    exclude_patterns: list = None
    login: Optional[LoginConfig] = None

    def __post_init__(self):
        if self.exclude_patterns is None:
            self.exclude_patterns = ["logout", "delete", "remove", "login", "signin"]


def _resolve_login(data: dict) -> Optional[LoginConfig]:
    if 'login' not in data:
        return None
    block = data['login']

    username_env = block.get('username_env')
    password_env = block.get('password_env')
    if not username_env or not password_env:
        raise ValueError("login block requires 'username_env' and 'password_env'")

    username = os.environ.get(username_env)
    password = os.environ.get(password_env)
    if not username or not password:
        missing = [e for e, v in ((username_env, username), (password_env, password)) if not v]
        raise ValueError(f"login env var(s) not set: {', '.join(missing)}")

    raw_url = block.get('login_url')
    if not raw_url:
        raise ValueError("login block requires 'login_url'")
    if isinstance(raw_url, str):
        login_urls = [raw_url]
    elif isinstance(raw_url, (list, tuple)) and raw_url and all(isinstance(u, str) and u for u in raw_url):
        login_urls = list(raw_url)
    else:
        raise ValueError("login 'login_url' must be a non-empty string or list of non-empty strings")

    return LoginConfig(
        login_url=login_urls[0],
        extra_login_urls=login_urls[1:],
        username=username,
        password=password,
        username_selector=block.get('username_selector', "#username"),
        password_selector=block.get('password_selector', "input[type='password']"),
        submit_selector=block.get('submit_selector', "button[type='submit']"),
        post_login_wait_ms=block.get('post_login_wait_ms', 3000),
        storage_state_path=block.get('storage_state_path', "storage_state.json"),
        reuse_storage_state=block.get('reuse_storage_state', True),
    )


def load_config(config_path: str) -> Config:
    """Load configuration from JSON file."""
    with open(config_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    form_data = data.get('form_filling', {})
    form_config = FormConfig(
        enabled=form_data.get('enabled', True),
        fill_delay=form_data.get('fill_delay', 100),
        defaults=form_data.get('defaults', {}),
    )

    return Config(
        start_url=data['start_url'],
        max_depth=data.get('max_depth', 3),
        max_clicks_per_page=data.get('max_clicks_per_page', 20),
        wait_timeout=data.get('wait_timeout', 30000),
        network_idle_timeout=data.get('network_idle_timeout', 2000),
        form_filling=form_config,
        exclude_patterns=data.get('exclude_patterns'),
        login=_resolve_login(data),
    )
