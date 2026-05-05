# scanning/fuzz/fuzz.py
from __future__ import annotations

from typing import List, Optional
from urllib.parse import urljoin
import re
import requests

from core.http_client import request as http_request, headers_subset
from core.limiter import GlobalRateLimiter
from core.models import Finding, Evidence
from scanning.fuzz.targets import FuzzTarget


def fuzz_one(
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
    target: FuzzTarget,
    payloads: List[str],
    match_regex: Optional[str] = None,
    max_tries: int = 60,
) -> List[Finding]:
    findings: List[Finding] = []
    rx = re.compile(match_regex, re.IGNORECASE) if match_regex else None

    tried = 0
    for p in payloads:
        if tried >= max_tries:
            break
        tried += 1

        path = target.template_path.replace("FUZZ", p)
        url = urljoin(base + "/", path.lstrip("/"))

        r, why = http_request(
            session, target.method, url,
            timeout=timeout, retries=retries,
            allow_redirects=allow_redirects, limiter=limiter,
            allow_hosts=allow_hosts, allow_suffixes=allow_suffixes,
            deny_private=deny_private
        )
        if r is None:
            if verbose:
                print(f"[!] [fuzz] {url} skipped -> {why}")
            continue

        ct = (r.headers.get("Content-Type") or "").lower()
        body = b""
        try:
            body = r.content or b""
        except Exception:
            body = b""

        ok = False
        matches: List[str] = []
        if rx:
            found = rx.findall(body.decode("utf-8", errors="ignore"))
            if found:
                ok = True
                matches = [str(x)[:200] for x in found[:10]]
        else:
            if r.status_code not in (404,) and len(body) > 50:
                ok = True
                matches.append(f"payload={p}")

        if verbose:
            print(f"[*] [fuzz:{target.payload_set}] {url} -> {r.status_code} ct={ct.split(';')[0]} len={len(body)}")

        if not ok:
            continue

        ev = Evidence(
            method=target.method,
            url=url,
            status=r.status_code,
            headers=headers_subset(dict(r.headers)),
            content_length=len(body),
            elapsed_ms=getattr(r, "_hunter_elapsed_ms", None),
            snippet=body[:1200].decode("utf-8", errors="ignore"),
            artifact=None,
            scope_reason="ok",
        )
        f = Finding(
            rule_id=f"fuzz-{target.payload_set}",
            name=f"Fuzz hit ({target.payload_set})",
            category="fuzz",
            severity="high",
            url=url,
            evidence=ev,
            matches=matches[:10],
            tags=["fuzz", target.payload_set],
            remediation="Validate and sanitize inputs; implement allowlist; add WAF rules where appropriate.",
            variables={"payload": p},
        )
        f.compute_risk_score()
        findings.append(f)

    return findings