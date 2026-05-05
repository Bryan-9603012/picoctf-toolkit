from __future__ import annotations
from core.utils import unique_keep_order

import hashlib
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests
from core.session import build_session

from core.http_client import request as http_request, headers_subset
from core.limiter import GlobalRateLimiter
from core.models import Evidence, Finding

from scanning.rule_engine.matchers import match_step
from scanning.rule_engine.schema import (
    get_method_and_paths,
    get_rule_id,
    get_rule_info,
    get_rule_remediation,
    get_rule_tags,
)

FLAG_RX = re.compile(rb"picoCTF\{[^}]+\}")


def render_template(value: str, variables: Dict[str, Any]) -> str:
    out = str(value)
    for k, v in (variables or {}).items():
        out = out.replace(f"{{{{{k}}}}}", str(v))
    return out


def extract_variables(resp: requests.Response, extract_def: Dict[str, str], variables: Dict[str, Any]) -> None:
    if not extract_def:
        return
    body = resp.content or b""
    for var_name, rule_def in extract_def.items():
        if isinstance(rule_def, str) and rule_def.startswith("body_regex:"):
            pat = rule_def.split("body_regex:", 1)[1].strip()
            try:
                m = re.search(pat.encode(), body)
                if m:
                    variables[var_name] = m.group(1).decode(errors="ignore")
            except re.error:
                continue


def when_allows(when: Dict[str, Any], variables: Dict[str, Any]) -> bool:
    if not when:
        return True
    if "previous_status" in when:
        return int(variables.get("_previous_status", -1)) == int(when["previous_status"])
    return True


def save_artifact(outdir: str, rule_id: str, content: bytes, hint: str = "") -> str:
    os.makedirs(outdir, exist_ok=True)
    h = hashlib.sha1(content[:4096] + hint.encode()).hexdigest()[:10]
    path = os.path.join(outdir, f"{rule_id}_{h}.bin")
    with open(path, "wb") as f:
        f.write(content)
    return path


def run_singlestep_rule(
    rule: Dict[str, Any],
    base: str,
    session: requests.Session,
    *,
    limiter: GlobalRateLimiter,
    outdir: str,
    timeout: float,
    retries: int,
    allow_redirects: bool,
    allow_hosts: List[str],
    allow_suffixes: List[str],
    deny_private: bool,
    verbose: bool,
    print_matches: bool,
    req_budget: Optional[List[int]] = None,
) -> List[Finding]:
    rid = get_rule_id(rule)
    info = get_rule_info(rule)
    name = info.get("name", rid)
    category = info.get("category", "misc")
    severity = info.get("severity", "info")
    tags = get_rule_tags(rule)
    remediation = get_rule_remediation(rule)

    method, paths = get_method_and_paths(rule)
    if not paths:
        return []

    findings: List[Finding] = []
    for p in paths:
        if req_budget is not None and req_budget[0] <= 0:
            return findings

        url = urljoin(base + "/", str(p).lstrip("/"))
        if req_budget is not None:
            req_budget[0] -= 1

        resp, why = http_request(
            session,
            method,
            url,
            timeout=timeout,
            retries=retries,
            allow_redirects=allow_redirects,
            limiter=limiter,
            allow_hosts=allow_hosts,
            allow_suffixes=allow_suffixes,
            deny_private=deny_private,
        )
        if resp is None:
            if verbose:
                print(f"[!] [{rid}] {url} skipped -> {why}")
            continue

        if verbose:
            ct = (resp.headers.get("Content-Type") or "").split(";", 1)[0].lower()
            print(f"[*] [{rid}] {method} {url} -> {resp.status_code} ct={ct} len={len(resp.content or b'')}")

        hits: List[str] = []
        mdef = rule.get("match") or {}
        if mdef:
            hits = match_step(resp, mdef) or []
            hits = unique_keep_order(hits)
        else:
            hits = [m.decode(errors="ignore") for m in FLAG_RX.findall(resp.content or b"")]

        if not hits:
            continue

        artifact_path = None
        if rule.get("save_artifact"):
            artifact_path = save_artifact(outdir, rid, resp.content or b"", hint=url)

        snippet = None
        if rule.get("snippet"):
            try:
                snippet = (resp.text or "")[:2000]
            except Exception:
                snippet = None

        if print_matches and hits:
            print(f"[+] Matches for {rid} @ {url}:")
            for m in hits[:10]:
                print(m)

        ev = Evidence(
            method=method,
            url=url,
            status=resp.status_code,
            headers=headers_subset(dict(resp.headers)),
            content_length=len(resp.content or b""),
            elapsed_ms=getattr(resp, "_hunter_elapsed_ms", None),
            snippet=snippet,
            artifact=artifact_path,
            scope_reason="ok",
        )
        
        # Extract extended rule metadata
        info = get_rule_info(rule)
        
        fd = Finding(
            rule_id=rid,
            name=name,
            title=name,
            category=category,
            severity=severity,
            confidence=info.get("confidence", "medium"),
            url=url,
            evidence=ev,
            matches=hits,
            tags=tags,
            remediation=remediation,
            cwe=info.get("cwe"),
            owasp=info.get("owasp"),
            description=info.get("description"),
            references=info.get("references") or [],
            preconditions=info.get("preconditions") or [],
            safe_check=info.get("safe_check"),
            verify_check=info.get("verify_check"),
            evidence_type=info.get("evidence_type"),
            exploitability=info.get("exploitability"),
            variables={},
        )
        fd.compute_risk_score()
        findings.append(fd)

    return findings


def run_multistep_rule(
    rule: Dict[str, Any],
    base: str,
    session: requests.Session,
    *,
    limiter: GlobalRateLimiter,
    outdir: str,
    timeout: float,
    retries: int,
    allow_redirects: bool,
    allow_hosts: List[str],
    allow_suffixes: List[str],
    deny_private: bool,
    verbose: bool,
    print_matches: bool,
    req_budget: Optional[List[int]] = None,
) -> List[Finding]:
    rid = get_rule_id(rule)
    info = get_rule_info(rule)
    name = info.get("name", rid)
    category = info.get("category", "chain")
    severity = info.get("severity", "high")
    tags = get_rule_tags(rule)
    remediation = get_rule_remediation(rule)

    steps = rule.get("steps", []) or []
    if not steps:
        return []

    variables: Dict[str, Any] = {}
    findings: List[Finding] = []
    last_resp: Optional[requests.Response] = None

    for step in steps:
        sid = step.get("id", "step")
        when = step.get("when", {}) or {}

        variables["_previous_status"] = int(last_resp.status_code) if last_resp is not None else -1
        if not when_allows(when, variables):
            if verbose:
                print(f"[*] [{rid}::{sid}] skipped by when")
            continue

        req = step.get("request", {}) or {}
        method = (req.get("method") or "GET").upper()
        path = req.get("path") or "/"
        headers = req.get("headers", {}) or {}
        data = req.get("data")

        rendered_path = render_template(str(path), variables).lstrip("/")
        url = urljoin(base + "/", rendered_path)

        rendered_headers: Dict[str, str] = {}
        for k, v in headers.items():
            rendered_headers[str(k)] = render_template(str(v), variables)

        body_bytes: Optional[bytes] = None
        if data is not None:
            body_bytes = render_template(str(data), variables).encode()

        if req_budget is not None and req_budget[0] <= 0:
            return findings
        if req_budget is not None:
            req_budget[0] -= 1

        if verbose:
            print(f"[*] [{rid}::{sid}] {method} {url}")

        resp, why = http_request(
            session,
            method,
            url,
            headers=rendered_headers or None,
            data=body_bytes,
            timeout=timeout,
            retries=retries,
            allow_redirects=allow_redirects,
            limiter=limiter,
            allow_hosts=allow_hosts,
            allow_suffixes=allow_suffixes,
            deny_private=deny_private,
        )
        if resp is None:
            if verbose:
                print(f"[!] [{rid}::{sid}] request failed -> {why}")
            return []

        # expect.status support (list)
        expect = step.get("expect") or {}
        if "status" in expect:
            allowed = {int(x) for x in (expect.get("status") or [])}
            if allowed and int(resp.status_code) not in allowed:
                if verbose:
                    print(f"[!] [{rid}::{sid}] unexpected status {resp.status_code}, expected {sorted(allowed)}")
                return []

        last_resp = resp

        extract = step.get("extract", {}) or {}
        if extract:
            extract_variables(resp, extract, variables)

        report_on_this_step = bool(step.get("report", False)) or (step is steps[-1])
        if report_on_this_step:
            mdef = step.get("match", {}) or {}
            hits = match_step(resp, mdef) if mdef else [m.decode(errors="ignore") for m in FLAG_RX.findall(resp.content or b"")]
            if not hits:
                return []

            artifact_path = None
            if rule.get("save_artifact") or step.get("save_artifact"):
                artifact_path = save_artifact(outdir, f"{rid}_chain", resp.content or b"", hint=url)

            snippet = None
            if step.get("snippet") or rule.get("snippet"):
                try:
                    snippet = (resp.text or "")[:2000]
                except Exception:
                    snippet = None

            ev = Evidence(
                method=method,
                url=url,
                status=resp.status_code,
                headers=headers_subset(dict(resp.headers)),
                content_length=len(resp.content or b""),
                elapsed_ms=getattr(resp, "_hunter_elapsed_ms", None),
                snippet=snippet,
                artifact=artifact_path,
                scope_reason="ok",
            )
            fd = Finding(
                rule_id=rid,
                name=name,
                category=category,
                severity=severity,
                url=url,
                evidence=ev,
                matches=hits,
                tags=tags,
                remediation=remediation,
                variables=dict(variables),
            )
            fd.compute_risk_score()
            findings.append(fd)

    return findings


_tls = threading.local()


def _get_thread_session(base_session: requests.Session) -> requests.Session:
    s = getattr(_tls, "sess", None)
    if s is None:
        s = build_session(base_session._hunter_cfg)
        _tls.sess = s
    return s


def run_rules_concurrent(
    *,
    rules: List[Dict[str, Any]],
    base: str,
    session: requests.Session,
    limiter: GlobalRateLimiter,
    outdir: str,
    timeout: float,
    retries: int,
    allow_redirects: bool,
    allow_hosts: List[str],
    allow_suffixes: List[str],
    deny_private: bool,
    verbose: bool,
    print_matches: bool,
    threads: int,
    max_requests: int = 0,
) -> List[Finding]:
    findings: List[Finding] = []
    req_budget: Optional[List[int]] = [max_requests] if max_requests and max_requests > 0 else None

    def run_one(rule: Dict[str, Any]) -> List[Finding]:
        s = _get_thread_session(session)
        if rule.get("steps"):
            return run_multistep_rule(
                rule, base, s,
                limiter=limiter, outdir=outdir,
                timeout=timeout, retries=retries,
                allow_redirects=allow_redirects,
                allow_hosts=allow_hosts, allow_suffixes=allow_suffixes,
                deny_private=deny_private,
                verbose=verbose, print_matches=print_matches,
                req_budget=req_budget,
            )
        return run_singlestep_rule(
            rule, base, s,
            limiter=limiter, outdir=outdir,
            timeout=timeout, retries=retries,
            allow_redirects=allow_redirects,
            allow_hosts=allow_hosts, allow_suffixes=allow_suffixes,
            deny_private=deny_private,
            verbose=verbose, print_matches=print_matches,
            req_budget=req_budget,
        )

    if threads <= 1:
        for r in rules:
            findings.extend(run_one(r))
        return findings

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(run_one, r) for r in rules]
        for fut in as_completed(futs):
            try:
                findings.extend(fut.result())
            except Exception as e:
                if verbose:
                    print(f"[!] rule worker failed: {e}")

    return findings