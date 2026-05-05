from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests

from core.http_client import request as http_request
from core.limiter import GlobalRateLimiter

HREF_RX = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
SRC_RX  = re.compile(r"""src\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
FORM_RX = re.compile(r"""<form[^>]+action\s*=\s*["']([^"']+)["']""", re.IGNORECASE)

# 強化版 JS endpoint 抽取
JS_ENDPOINT_RXES = [
    # fetch("/api/...")
    re.compile(r"""fetch\(\s*["'](/[^"']+)["']""", re.IGNORECASE),

    # axios.get("/api/..."), axios.post(...)
    re.compile(r"""axios\.(get|post|put|delete|patch)\(\s*["'](/[^"']+)["']""", re.IGNORECASE),

    # xhr.open("GET", "/api/...")
    re.compile(r"""open\(\s*["'][A-Z]+["']\s*,\s*["'](/[^"']+)["']""", re.IGNORECASE),

    # 單純字串型 API path
    re.compile(r"""["'](/api/[^"'?#]+(?:\?[^"']*)?)["']""", re.IGNORECASE),
    re.compile(r"""["'](/graphql)["']""", re.IGNORECASE),
    re.compile(r"""["'](/internal/[^"'?#]+(?:\?[^"']*)?)["']""", re.IGNORECASE),
    re.compile(r"""["'](/v1/[^"'?#]+(?:\?[^"']*)?)["']""", re.IGNORECASE),
    re.compile(r"""["'](/v2/[^"'?#]+(?:\?[^"']*)?)["']""", re.IGNORECASE),
    re.compile(r"""["'](/admin/[^"'?#]+(?:\?[^"']*)?)["']""", re.IGNORECASE),
]


@dataclass
class CrawlResult:
    urls: List[str]
    paths: List[str]
    js_endpoints: List[str]


def _same_origin(base: str, u: str) -> bool:
    b = urlparse(base)
    x = urlparse(u)
    return (b.scheme, b.netloc) == (x.scheme, x.netloc)


def _norm_path(p: str) -> str:
    if not p:
        return ""
    p = p.split("#", 1)[0].split("?", 1)[0]
    if not p.startswith("/"):
        p = "/" + p
    return p


def crawl(
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
    seeds: List[str],
    depth: int = 2,
    max_pages: int = 60,
) -> CrawlResult:
    base_root = base.rstrip("/") + "/"
    queue: List[Tuple[str, int]] = []
    seen: Set[str] = set()
    found_paths: Set[str] = set()
    found_js: Set[str] = set()

    def enqueue(url: str, d: int):
        if len(seen) >= max_pages:
            return
        if not _same_origin(base, url):
            return
        if url not in seen:
            queue.append((url, d))

    enqueue(base_root, 0)
    for s in (seeds or [])[:200]:
        full = urljoin(base_root, str(s).lstrip("/"))
        enqueue(full, 0)

    while queue and len(seen) < max_pages:
        url, d = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)

        r, why = http_request(
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
        if r is None:
            if verbose:
                print(f"[!] [crawl] {url} skipped -> {why}")
            continue

        ct = (r.headers.get("Content-Type") or "").lower()
        if verbose:
            print(f"[*] [crawl] {url} -> {r.status_code} ct={ct.split(';')[0]}")

        try:
            found_paths.add(_norm_path(urlparse(url).path))
        except Exception:
            pass

        if d >= depth:
            continue

        # HTML parse
        if "text/html" in ct:
            html = ""
            try:
                html = r.text or ""
            except Exception:
                html = ""

            links = []
            links.extend(HREF_RX.findall(html))
            links.extend(SRC_RX.findall(html))
            links.extend(FORM_RX.findall(html))

            for u in links[:800]:
                if u.startswith("http"):
                    if _same_origin(base, u):
                        enqueue(u, d + 1)
                        found_paths.add(_norm_path(urlparse(u).path))
                else:
                    full = urljoin(base_root, u)
                    enqueue(full, d + 1)
                    found_paths.add(_norm_path(urlparse(full).path))

        # JS parse
        if ("javascript" in ct) or url.endswith(".js"):
            txt = ""
            try:
                txt = r.text or ""
            except Exception:
                txt = ""

            for rx in JS_ENDPOINT_RXES:
                for m in rx.finditer(txt):
                    # 取最後一個 capture group，避免 axios.get 取到 method 名稱
                    p = m.group(m.lastindex) if m.lastindex else m.group(0)
                    p = _norm_path(p)

                    if p.startswith("/"):
                        found_js.add(p)
                        enqueue(urljoin(base_root, p.lstrip("/")), d + 1)

                        if verbose:
                            print(f"[*] [crawl-js] found {p}")

    return CrawlResult(
        urls=sorted(seen),
        paths=sorted(found_paths),
        js_endpoints=sorted(found_js),
    )