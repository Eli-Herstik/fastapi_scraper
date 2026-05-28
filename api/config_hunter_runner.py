"""Adapter that runs config_hunter end-to-end and returns host entries in the
same shape as `scraper/network/auth_analyzer.aggregate_by_host`, so they can
flow through `api.translate.hosts_to_findings` without any translator changes.
"""

from __future__ import annotations

import os
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse

from config_hunter.config_hunter import (
    AuthInfo,
    ConfigSource,
    _classify_url,
    crawl,
    merge_probe_results,
    probe_urls,
    reconcile_auth,
    resolve_hosts,
)


DEFAULT_TIMEOUT_MS = int(os.environ.get("CONFIG_HUNTER_TIMEOUT_MS", "30000"))
DEFAULT_WAIT_AFTER_LOAD_MS = int(os.environ.get("CONFIG_HUNTER_WAIT_AFTER_LOAD_MS", "5000"))
DEFAULT_INTERACT_BUDGET_MS = int(os.environ.get("CONFIG_HUNTER_INTERACT_BUDGET_MS", "8000"))
DEFAULT_PROBE_TIMEOUT_S = float(os.environ.get("CONFIG_HUNTER_PROBE_TIMEOUT_S", "5.0"))
DEFAULT_PROBE_CONCURRENCY = int(os.environ.get("CONFIG_HUNTER_PROBE_CONCURRENCY", "10"))


EventCallback = Callable[[str, dict[str, Any]], Awaitable[None]]


def _noop_event(_type: str, _payload: dict[str, Any]) -> Awaitable[None]:
    async def _coro() -> None:
        return None
    return _coro()


def _first_source_per_host(sources: list[ConfigSource]) -> dict[str, str]:
    """Map each host to the origin of the first ConfigSource that mentioned it."""
    out: dict[str, str] = {}
    for src in sources:
        for url in src.urls_found:
            host = urlparse(url).hostname
            if host and host not in out:
                out[host] = src.origin
    return out


def _pick_authentication(guesses: list[str]) -> str:
    """Prefer the most specific non-'unknown' guess. Strings here come from
    reconcile_auth — they're already recognized by normalize_auth_method via
    substring matching ('basic', 'bearer', 'negotiate', 'none', 'oauth', ...).
    """
    for g in guesses:
        if g and "unknown" not in g.lower():
            return g
    return guesses[0] if guesses else "unknown"


def _aggregate_to_host_entries(
    auth_map: dict[str, AuthInfo],
    sources: list[ConfigSource],
    unresolved: list[dict],
) -> list[dict]:
    host_first_source = _first_source_per_host(sources)

    buckets: dict[str, dict[str, Any]] = {}
    for url, info in auth_map.items():
        host = urlparse(url).hostname
        if not host:
            continue
        b = buckets.setdefault(host, {
            "guesses": [],
            "www_auths": [],
            "status_codes": [],
            "url_count": 0,
        })
        b["url_count"] += 1
        if info.best_guess:
            b["guesses"].append(info.best_guess)
        if info.probe_result:
            if info.probe_result.www_authenticate:
                b["www_auths"].append(info.probe_result.www_authenticate)
            if info.probe_result.status_code is not None:
                b["status_codes"].append(info.probe_result.status_code)

    # Hosts that failed DNS resolution never made it into the probe pool, but
    # we still want them to surface as findings.
    for entry in unresolved:
        host = entry.get("host")
        if host and host not in buckets:
            buckets[host] = {
                "guesses": ["unknown (unresolved host)"],
                "www_auths": [],
                "status_codes": [],
                "url_count": 0,
            }

    out: list[dict] = []
    for host, b in buckets.items():
        out.append({
            "host": host,
            "authentication": _pick_authentication(b["guesses"]),
            "request_count": max(1, b["url_count"]),
            "first_seen_on_page": f"config:{host_first_source.get(host, 'unknown')}",
            "headers_snippet": b["www_auths"][0] if b["www_auths"] else "",
            "status_code": b["status_codes"][0] if b["status_codes"] else 0,
        })
    return out


async def run_config_hunter(
    start_url: str,
    *,
    on_event: EventCallback | None = None,
) -> list[dict]:
    """Crawl `start_url`, harvest URLs from JSON/JS configs, probe their
    auth requirements, and return a list of host-level entries shaped for
    `hosts_to_findings`."""
    emit = on_event or (lambda t, p: _noop_event(t, p))

    await emit("config_hunter_started", {"url": start_url})

    sources = await crawl(
        url=start_url,
        timeout=DEFAULT_TIMEOUT_MS,
        wait_after_load=DEFAULT_WAIT_AFTER_LOAD_MS,
        headed=False,
        interact_budget_ms=DEFAULT_INTERACT_BUDGET_MS,
        follow_links=False,
        max_pages=1,
    )

    all_urls: list[str] = []
    for src in sources:
        all_urls.extend(src.urls_found)
    unique_urls = [u for u in dict.fromkeys(all_urls) if _classify_url(u) is None]

    auth_map: dict[str, AuthInfo] = {u: AuthInfo(url=u) for u in unique_urls}

    unresolved: list[dict] = []
    probeable_urls = unique_urls
    if unique_urls:
        hosts = sorted({urlparse(u).hostname for u in unique_urls if urlparse(u).hostname})
        unresolved = await resolve_hosts(hosts)
        unresolved_set = {entry["host"] for entry in unresolved}
        if unresolved_set:
            probeable_urls = [
                u for u in unique_urls if urlparse(u).hostname not in unresolved_set
            ]
            for url in unique_urls:
                if urlparse(url).hostname in unresolved_set:
                    auth_map[url].best_guess = "unknown (unresolved host)"

    if probeable_urls:
        probes = await probe_urls(
            probeable_urls,
            timeout=DEFAULT_PROBE_TIMEOUT_S,
            max_concurrent=DEFAULT_PROBE_CONCURRENCY,
        )
        merge_probe_results(auth_map, probes)
        reconcile_auth(auth_map)

    host_entries = _aggregate_to_host_entries(auth_map, sources, unresolved)

    await emit("config_hunter_progress", {
        "urls_found": len(unique_urls),
        "hosts_probed": len(host_entries),
        "unresolved_hosts": len(unresolved),
    })

    return host_entries
