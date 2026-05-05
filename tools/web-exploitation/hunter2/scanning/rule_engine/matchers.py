from __future__ import annotations

import re
from typing import Any, Dict, List

import requests


def match_step(resp: requests.Response, match: Dict[str, Any]) -> List[str]:
    if not match:
        return []

    # status can be int or list[int]
    if "status" in match:
        st = match["status"]
        if isinstance(st, list):
            allowed = {int(x) for x in st}
            if int(resp.status_code) not in allowed:
                return []
        else:
            if int(resp.status_code) != int(st):
                return []

    # header_contains: checks Content-Type substring by default
    if "header_contains" in match:
        ct = (resp.headers.get("Content-Type") or "").lower()
        want = [str(x).lower() for x in (match.get("header_contains") or [])]
        if want and not any(w in ct for w in want):
            return []

    patterns = match.get("body_regex", []) or []
    require_all = bool(match.get("require_all_regex", False))

    hits: List[str] = []
    matched_count = 0

    for rx in patterns:
        try:
            found = re.findall(rx.encode(), resp.content or b"")
            if found:
                matched_count += 1
                for b in found:
                    if isinstance(b, tuple):
                        b = b[0]
                    hits.append(b.decode(errors="ignore"))
        except re.error:
            continue

    if patterns:
        if require_all and matched_count < len(patterns):
            return []
        if (not require_all) and matched_count == 0:
            return []

    return hits