from __future__ import annotations

import random
import time
from typing import Dict, Optional, Tuple

import requests

from core.limiter import GlobalRateLimiter
from core.scope import in_scope


def headers_subset(headers: Dict[str, str]) -> Dict[str, str]:
    keep = {"content-type", "content-disposition", "server", "x-powered-by", "location"}
    out: Dict[str, str] = {}
    for k, v in headers.items():
        if k.lower() in keep:
            out[k] = v
    return out


def _backoff_sleep(attempt: int) -> None:
    # exponential backoff + jitter
    base = min(3.0, 0.25 * (2 ** max(0, attempt - 1)))
    time.sleep(base + random.random() * 0.25)


def _parse_headers(kvs) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for s in kvs or []:
        if ":" not in s:
            continue
        k, v = s.split(":", 1)
        k = k.strip()
        v = v.strip()
        if k:
            out[k] = v
    return out


def _merge_headers(user_headers: Optional[Dict[str, str]], cfg) -> Dict[str, str]:
    merged: Dict[str, str] = {}
    if user_headers:
        merged.update(user_headers)

    if cfg is None:
        return merged

    merged.update(_parse_headers(getattr(cfg, "extra_headers", [])))

    ck = getattr(cfg, "cookie", "")
    if ck:
        merged["Cookie"] = ck

    bearer = getattr(cfg, "bearer", "")
    if bearer:
        merged["Authorization"] = f"Bearer {bearer}"

    return merged


def request(
    session: requests.Session,
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    data: Optional[bytes] = None,
    timeout: float = 12.0,
    retries: int = 1,
    allow_redirects: bool = True,
    limiter: Optional[GlobalRateLimiter] = None,
    allow_hosts=None,
    allow_suffixes=None,
    deny_private: bool = False,
) -> Tuple[Optional[requests.Response], str]:
    allow_hosts = allow_hosts or []
    allow_suffixes = allow_suffixes or []

    ok, why = in_scope(url, allow_hosts, allow_suffixes, deny_private=deny_private)
    if not ok:
        return None, why

    cfg = getattr(session, "_hunter_cfg", None)
    req_headers = _merge_headers(headers, cfg)

    last_err = "request-failed"
    max_tries = max(1, retries + 1)

    for attempt in range(1, max_tries + 1):
        if limiter:
            limiter.wait()

        try:
            start = time.perf_counter()
            resp = session.request(
                method=method,
                url=url,
                headers=req_headers,
                data=data,
                timeout=timeout,
                allow_redirects=allow_redirects,
            )
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            setattr(resp, "_hunter_elapsed_ms", elapsed_ms)

            # server says "slow down"
            if resp.status_code in (429, 503, 502, 504) and attempt < max_tries:
                _backoff_sleep(attempt)
                last_err = f"retryable-status:{resp.status_code}"
                continue

            return resp, "ok"

        except (requests.ConnectionError, requests.Timeout) as e:
            last_err = f"net-error:{e}"
            if attempt < max_tries:
                _backoff_sleep(attempt)
                continue
        except Exception as e:
            last_err = f"request-failed:{e}"
            if attempt < max_tries:
                _backoff_sleep(attempt)
                continue

    return None, last_err