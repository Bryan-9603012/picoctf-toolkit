# enumeration/discovery.py
from __future__ import annotations

from urllib.parse import urljoin
from typing import List

import requests

from core.http_client import request as http_request
from core.limiter import GlobalRateLimiter

COMMON_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/admin",
    "/debug",
    "/api",
    "/swagger",
    "/swagger.json",
    "/openapi.json",
    "/actuator",
]


def discover_paths(
    *,
    base: str,
    session: requests.Session,
    limiter: GlobalRateLimiter,
    timeout: float,
    retries: int,
    allow_redirects: bool,
    allow_hosts: List[str],
    allow_suffixes: List[str],
    deny_private: bool,
    verbose: bool,
    max_paths: int = 200,
) -> List[str]:
    paths: List[str] = []
    for p in COMMON_PATHS:
        url = urljoin(base + "/", p.lstrip("/"))
        r, _ = http_request(
            session,
            "GET",
            url,
            timeout=timeout,
            retries=retries,
            allow_redirects=allow_redirects,
            limiter=limiter,
            allow_hosts=allow_hosts,
            allow_suffixes=allow_suffixes,
            deny_private=deny_private,
        )
        if r and r.status_code < 500:
            paths.append(p)
            if verbose:
                print(f"[*] [discover] found {p}")
        if len(paths) >= max_paths:
            break
    return sorted(set(paths))