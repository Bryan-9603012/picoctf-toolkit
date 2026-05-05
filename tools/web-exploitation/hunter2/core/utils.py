# core/utils.py
from __future__ import annotations

import hashlib
from typing import Iterable, List, Set
from urllib.parse import urlparse, urlunparse


def normalize_url(url: str) -> str:
    """Normalize URL for dedupe: strip fragment, keep scheme/netloc/path/query."""
    try:
        u = urlparse(url)
        u2 = u._replace(fragment="")
        return urlunparse(u2)
    except Exception:
        return url


def normalize_path(p: str) -> str:
    if not p:
        return "/"
    p = p.strip()
    p = p.split("#", 1)[0]
    if not p.startswith("/"):
        p = "/" + p
    return p


def unique_keep_order(items: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for x in items:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def short_hash(data: bytes, n: int = 10) -> str:
    return hashlib.sha1(data).hexdigest()[:n]