# fingerprint/fingerprint.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

import requests
from core.session import build_session

from config.config import Config
from core.http_client import request as http_request
from core.limiter import GlobalRateLimiter


@dataclass
class FingerprintResult:
    tech: List[str]
    waf: List[str]


def _match_header_rules(headers: Dict[str, str], rules: List[str]) -> bool:
    # rules examples:
    #   "cf-ray"  (header key exists)
    #   "Server: nginx" (key:value contains)
    if not rules:
        return False

    lower_map = {k.lower(): str(v) for k, v in (headers or {}).items()}

    for r in rules:
        s = str(r)
        if ":" in s:
            k, v = s.split(":", 1)
            k = k.strip().lower()
            v = v.strip().lower()
            if k in lower_map and v in lower_map[k].lower():
                return True
        else:
            k = s.strip().lower()
            if k in lower_map:
                return True
    return False


def _match_body_rules(body_text: str, rules: List[str]) -> bool:
    t = (body_text or "").lower()
    for r in rules or []:
        if str(r).lower() in t:
            return True
    return False


def fingerprint_target(
    tech_db: Dict = None,
    waf_db: Dict = None,
    base: str = "",
    cfg: Config = None,
) -> FingerprintResult:
    tech_db = tech_db if isinstance(tech_db, dict) else {}
    waf_db = waf_db if isinstance(waf_db, dict) else {}
    if cfg is None:
        cfg = Config(base=base or "http://example.com")
    if not base:
        base = getattr(cfg, "base", "http://example.com")

    try:
        sess = build_session(cfg)
        limiter = GlobalRateLimiter(getattr(cfg, "qps", 2.0))
        home = base.rstrip("/") + "/"
        resp, _ = http_request(
            sess,
            "GET",
            home,
            timeout=getattr(cfg, "timeout", 10.0),
            retries=getattr(cfg, "retries", 0),
            allow_redirects=getattr(cfg, "allow_redirects", True),
            limiter=limiter,
            allow_hosts=getattr(cfg, "allow_hosts", []) or getattr(cfg, "allow_host", []),
            allow_suffixes=getattr(cfg, "allow_suffixes", []),
            deny_private=getattr(cfg, "deny_private", False),
        )
    except Exception:
        resp = None

    headers = dict(resp.headers) if resp is not None else {}
    body_text = ""
    if resp is not None:
        try:
            body_text = (resp.text or "")[:8000]
        except Exception:
            body_text = ""

    tech: List[str] = []
    for name, defs in (tech_db or {}).items():
        defs = defs or {}
        if _match_header_rules(headers, defs.get("headers") or []) or _match_body_rules(body_text, defs.get("body") or []):
            tech.append(str(name))

    waf: List[str] = []
    for name, defs in (waf_db or {}).items():
        defs = defs or {}
        if _match_header_rules(headers, defs.get("headers") or []) or _match_body_rules(body_text, defs.get("body") or []):
            waf.append(str(name))

    return FingerprintResult(tech=sorted(set(tech)), waf=sorted(set(waf)))