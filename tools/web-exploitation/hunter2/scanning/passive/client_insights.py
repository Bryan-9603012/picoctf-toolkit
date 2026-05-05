from __future__ import annotations

import base64
import html
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests

from core.http_client import headers_subset, request as http_request
from core.limiter import GlobalRateLimiter
from core.models import Evidence, Finding

COMMENT_RX = re.compile(r"<!--(.*?)-->", re.I | re.S)
HIDDEN_INPUT_RX = re.compile(
    r"<input[^>]*type\s*=\s*['\"]hidden['\"][^>]*name\s*=\s*['\"]([^'\"]+)['\"][^>]*value\s*=\s*['\"]([^'\"]*)['\"]|"
    r"<input[^>]*name\s*=\s*['\"]([^'\"]+)['\"][^>]*type\s*=\s*['\"]hidden['\"][^>]*value\s*=\s*['\"]([^'\"]*)['\"]",
    re.I,
)
JS_URI_RX = re.compile(r"(?:href|src)\s*=\s*['\"](javascript:[^'\"]+)['\"]", re.I)
SCRIPT_SRC_RX = re.compile(r"<script[^>]+src\s*=\s*['\"]([^'\"]+)['\"]", re.I)
INLINE_SCRIPT_RX = re.compile(r"<script(?![^>]+src=)[^>]*>(.*?)</script>", re.I | re.S)
FORM_RX = re.compile(r"<form([^>]*)>(.*?)</form>", re.I | re.S)
ACTION_RX = re.compile(r"action\s*=\s*['\"]([^'\"]+)['\"]", re.I)
METHOD_RX = re.compile(r"method\s*=\s*['\"]([^'\"]+)['\"]", re.I)
INPUT_NAME_RX = re.compile(r"<input[^>]+name\s*=\s*['\"]([^'\"]+)['\"][^>]*>", re.I)
TEXTUAL_INPUT_RX = re.compile(r"<input[^>]+name\s*=\s*['\"]([^'\"]+)['\"][^>]*type\s*=\s*['\"]?(?:text|search|email|url)?['\"]?[^>]*>", re.I)
TEMPLATE_ERROR_RX = re.compile(
    r"jinja2|templatesyntaxerror|undefinederror|twig\\error|freemarker|velocity|mustache|handlebars|erb|pug|smarty",
    re.I,
)
ENCODED_RX = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
AUTH_JS_RX = re.compile(r"(admin\s*==|role\s*==|password\s*==|if\s*\(.{0,60}(admin|login|auth))", re.I | re.S)
COOKIE_NAME_RX = re.compile(r"(?:secret|recipe|admin|auth|role|debug|token|flag|session)", re.I)
COOKIE_VALUE_CLUE_RX = re.compile(r"(?:picoctf|flag\{|admin|role|secret|recipe|true|false|yes|no)", re.I)
INSPECT_HINT_RX = re.compile(r"(inspect|developer tools|devtools|source|view-source|bookmarklet|cookie|localstorage|sessionstorage)", re.I)
PARAM_SUSPECT_RX = re.compile(r"^(?:admin|role|access|debug|isadmin|is_admin|verified|step|stage|id)$", re.I)
DOM_HIDDEN_RX = re.compile(r"(?:display\s*:\s*none|hidden\b|aria-hidden\s*=\s*['\"]true['\"])", re.I)
COOKIE_SET_RX = re.compile(r"([^=;,\s]+)=([^;]*)(.*)")


@dataclass
class FormInfo:
    action: str
    method: str
    fields: List[str] = field(default_factory=list)
    hidden_fields: Dict[str, str] = field(default_factory=dict)


@dataclass
class AnalysisResult:
    findings: List[Finding] = field(default_factory=list)
    scripts_to_fetch: List[str] = field(default_factory=list)
    forms: List[FormInfo] = field(default_factory=list)


def _same_origin(base_url: str, other_url: str) -> bool:
    a = urlparse(base_url)
    b = urlparse(other_url)
    return (a.scheme, a.netloc) == (b.scheme, b.netloc)


def _make_finding(*, rule_id: str, name: str, severity: str, url: str, resp: requests.Response, snippet: str, matches: List[str], tags: List[str], remediation: str, category: str = "passive") -> Finding:
    ev = Evidence(
        method="GET",
        url=url,
        status=resp.status_code,
        headers=headers_subset(dict(resp.headers)),
        content_length=len(resp.content or b""),
        elapsed_ms=getattr(resp, "_hunter_elapsed_ms", None),
        snippet=snippet[:1800],
        matched_pattern=matches[0] if matches else None,
        scope_reason="ok",
    )
    fd = Finding(
        rule_id=rule_id,
        name=name,
        title=name,
        category=category,
        severity=severity,
        confidence="medium" if severity in {"info", "low"} else "high",
        url=url,
        evidence=ev,
        matches=matches[:10],
        tags=tags,
        remediation=remediation,
    )
    fd.compute_risk_score()
    return fd


def _decode_candidates(text: str) -> List[str]:
    out: List[str] = []
    for cand in ENCODED_RX.findall(text)[:10]:
        try:
            padded = cand + ('=' * ((4 - len(cand) % 4) % 4))
            decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
        except Exception:
            continue
        if COOKIE_VALUE_CLUE_RX.search(decoded) or "picoCTF{" in decoded:
            out.append(f"base64:{cand[:40]} => {decoded[:120]}")
    return out


def analyze_response(url: str, resp: requests.Response, text: str) -> AnalysisResult:
    result = AnalysisResult()
    lowered = text.lower()

    comments = [html.unescape(c.strip()) for c in COMMENT_RX.findall(text) if c.strip()]
    comment_hits = [c for c in comments if COOKIE_VALUE_CLUE_RX.search(c) or "picoCTF{" in c]
    if comment_hits:
        severity = "high" if any("picoCTF{" in c for c in comment_hits) else "medium"
        result.findings.append(_make_finding(
            rule_id="passive-html-comment-clue",
            name="Hidden HTML Comment Clue",
            severity=severity,
            url=url,
            resp=resp,
            snippet="\n".join(comment_hits[:3]),
            matches=[f"comment:{c[:120]}" for c in comment_hits[:3]],
            tags=["passive", "client-side", "source", "comment"],
            remediation="Remove secrets and challenge clues from HTML comments.",
        ))

    if DOM_HIDDEN_RX.search(text):
        hidden_matches = []
        for m in HIDDEN_INPUT_RX.finditer(text):
            name = m.group(1) or m.group(3) or ""
            value = m.group(2) or m.group(4) or ""
            hidden_matches.append(f"hidden_input:{name}={value}")
        if hidden_matches:
            result.findings.append(_make_finding(
                rule_id="passive-hidden-input-clue",
                name="Hidden Input or DOM Clue",
                severity="medium" if any(PARAM_SUSPECT_RX.search(h.split(':',1)[1].split('=')[0]) for h in hidden_matches) else "info",
                url=url,
                resp=resp,
                snippet="\n".join(hidden_matches[:5]),
                matches=hidden_matches[:5],
                tags=["passive", "client-side", "hidden-input"],
                remediation="Do not trust hidden fields for authorization or challenge secrets.",
            ))

    js_uris = JS_URI_RX.findall(text)
    if js_uris:
        result.findings.append(_make_finding(
            rule_id="passive-bookmarklet-uri",
            name="Client-side JavaScript URI Detected",
            severity="medium",
            url=url,
            resp=resp,
            snippet="\n".join(js_uris[:3]),
            matches=[f"javascript_uri:{u[:120]}" for u in js_uris[:3]],
            tags=["passive", "client-side", "javascript", "bookmarklet"],
            remediation="Avoid embedding secrets or sensitive workflow logic in javascript: URIs.",
        ))

    inline_scripts = [s.strip() for s in INLINE_SCRIPT_RX.findall(text) if s.strip()]
    for script in inline_scripts[:5]:
        findings_added = False
        if AUTH_JS_RX.search(script):
            result.findings.append(_make_finding(
                rule_id="passive-client-auth-logic",
                name="Client-side Authorization Logic Detected",
                severity="medium",
                url=url,
                resp=resp,
                snippet=script[:600],
                matches=["client_auth_logic"],
                tags=["passive", "client-side", "auth", "javascript"],
                remediation="Move authorization checks to the server side.",
            ))
            findings_added = True
        decoded = _decode_candidates(script)
        if decoded:
            result.findings.append(_make_finding(
                rule_id="passive-encoded-client-clue",
                name="Encoded Client-side Clue Detected",
                severity="medium" if any("picoCTF{" in d for d in decoded) else "info",
                url=url,
                resp=resp,
                snippet="\n".join(decoded[:3]),
                matches=decoded[:3],
                tags=["passive", "client-side", "encoded", "javascript"],
                remediation="Do not embed secrets in client-side encoded strings.",
            ))
            findings_added = True
        if INSPECT_HINT_RX.search(script) and not findings_added:
            result.findings.append(_make_finding(
                rule_id="passive-client-inspect-hint",
                name="Client-side Inspection Hint Detected",
                severity="info",
                url=url,
                resp=resp,
                snippet=script[:400],
                matches=["inspect_hint:inline_script"],
                tags=["passive", "ctf", "hint", "javascript"],
                remediation="Review inline scripts for exposed logic and embedded clues.",
            ))

    if INSPECT_HINT_RX.search(text) and not inline_scripts:
        result.findings.append(_make_finding(
            rule_id="passive-page-inspect-hint",
            name="Page Content Suggests Client-side Inspection",
            severity="info",
            url=url,
            resp=resp,
            snippet=text[:500],
            matches=["inspect_hint:page_text"],
            tags=["passive", "ctf", "hint"],
            remediation="Review page source, DOM, scripts, cookies, and storage for hidden clues.",
        ))

    for src in SCRIPT_SRC_RX.findall(text)[:8]:
        abs_src = urljoin(url, html.unescape(src))
        if _same_origin(url, abs_src):
            result.scripts_to_fetch.append(abs_src)

    for attrs, body in FORM_RX.findall(text):
        action_match = ACTION_RX.search(attrs)
        method_match = METHOD_RX.search(attrs)
        action = urljoin(url, action_match.group(1) if action_match else url)
        method = (method_match.group(1) if method_match else "GET").upper()
        names = INPUT_NAME_RX.findall(body)
        textual = TEXTUAL_INPUT_RX.findall(body)
        hidden: Dict[str, str] = {}
        for m in HIDDEN_INPUT_RX.finditer(body):
            name = m.group(1) or m.group(3) or ""
            value = m.group(2) or m.group(4) or ""
            if name:
                hidden[name] = value
        fi = FormInfo(action=action, method=method, fields=names, hidden_fields=hidden)
        result.forms.append(fi)
        suspicious = [n for n in names if PARAM_SUSPECT_RX.search(n)]
        if suspicious:
            result.findings.append(_make_finding(
                rule_id="passive-suspicious-form-parameters",
                name="Suspicious Form Parameters Observed",
                severity="info",
                url=url,
                resp=resp,
                snippet=f"action={action} method={method} fields={','.join(names[:10])}",
                matches=[f"param:{n}" for n in suspicious[:10]],
                tags=["passive", "form", "workflow", "parameter"],
                remediation="Do not rely on client-controlled form parameters for authorization or workflow control.",
            ))
        elif textual and INSPECT_HINT_RX.search(text):
            result.findings.append(_make_finding(
                rule_id="passive-user-input-surface",
                name="User Input Surface Detected",
                severity="info",
                url=url,
                resp=resp,
                snippet=f"action={action} method={method} fields={','.join(textual[:10])}",
                matches=[f"input:{n}" for n in textual[:10]],
                tags=["passive", "form", "input"],
                remediation="Review input surfaces for server-side validation and safe output rendering.",
            ))

    for raw_cookie in resp.headers.get_all("Set-Cookie") if hasattr(resp.headers, "get_all") else [resp.headers.get("Set-Cookie", "")]:
        if not raw_cookie:
            continue
        m = COOKIE_SET_RX.match(raw_cookie)
        if not m:
            continue
        cname, cval, attrs = m.groups()
        attrs_lower = attrs.lower()
        matches = [f"cookie:{cname}"]
        if COOKIE_NAME_RX.search(cname) or COOKIE_VALUE_CLUE_RX.search(cval):
            result.findings.append(_make_finding(
                rule_id="passive-cookie-clue",
                name="Suspicious Cookie Clue Detected",
                severity="medium" if "picoCTF{" in cval else "info",
                url=url,
                resp=resp,
                snippet=raw_cookie[:400],
                matches=[f"set-cookie:{raw_cookie[:160]}"],
                tags=["passive", "cookie", "client-state"],
                remediation="Avoid placing secrets, roles, or challenge clues directly in cookies.",
            ))
        if "expires=" not in attrs_lower and "max-age=" not in attrs_lower and re.search(r"session|sess|auth", cname, re.I):
            result.findings.append(_make_finding(
                rule_id="passive-session-missing-expiry",
                name="Session Cookie Without Explicit Expiry",
                severity="low",
                url=url,
                resp=resp,
                snippet=raw_cookie[:400],
                matches=matches,
                tags=["passive", "session", "cookie"],
                remediation="Define clear session expiration and invalidate server-side sessions on logout.",
            ))

    return result


def analyze_script_response(url: str, resp: requests.Response, text: str) -> List[Finding]:
    findings: List[Finding] = []
    if not text:
        return findings
    if AUTH_JS_RX.search(text):
        findings.append(_make_finding(
            rule_id="passive-script-auth-logic",
            name="Client-side Auth Logic in Script",
            severity="medium",
            url=url,
            resp=resp,
            snippet=text[:700],
            matches=["client_auth_logic:script"],
            tags=["passive", "javascript", "auth"],
            remediation="Enforce authentication and authorization on the server side.",
        ))
    decoded = _decode_candidates(text)
    if decoded:
        findings.append(_make_finding(
            rule_id="passive-script-encoded-clue",
            name="Encoded JavaScript Clue Detected",
            severity="medium" if any("picoCTF{" in d for d in decoded) else "info",
            url=url,
            resp=resp,
            snippet="\n".join(decoded[:3]),
            matches=decoded[:3],
            tags=["passive", "javascript", "encoded"],
            remediation="Do not store secrets or challenge data in encoded JavaScript constants.",
        ))
    if "javascript:" in text:
        findings.append(_make_finding(
            rule_id="passive-script-bookmarklet",
            name="Bookmarklet-style Logic in Script",
            severity="medium",
            url=url,
            resp=resp,
            snippet=text[:600],
            matches=["bookmarklet_logic:script"],
            tags=["passive", "javascript", "bookmarklet"],
            remediation="Avoid embedding sensitive functionality or data in bookmarklet-style client code.",
        ))
    return findings


def run_low_risk_probes(cfg, sess: requests.Session, limiter: GlobalRateLimiter, page_url: str, forms: List[FormInfo]) -> List[Finding]:
    findings: List[Finding] = []
    payloads = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"]
    numeric_indicators = {"49", "14"}

    for form in forms[:4]:
        text_fields = [f for f in form.fields if not PARAM_SUSPECT_RX.search(f)]
        if not text_fields:
            continue
        target_field = text_fields[0]
        for payload in payloads[:2 if cfg.policy == "safe" else 4]:
            data = {target_field: payload}
            for k, v in form.hidden_fields.items():
                data[k] = v
            method = form.method.upper()
            if method == "POST" and getattr(cfg, "allow_post", "restricted") == "deny":
                continue
            body = "&".join(f"{k}={requests.utils.quote(str(v), safe='')}" for k, v in data.items()).encode()
            resp, why = http_request(
                sess,
                method,
                form.action,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data=body if method == "POST" else None,
                timeout=cfg.timeout,
                retries=0,
                allow_redirects=cfg.allow_redirects,
                limiter=limiter,
                allow_hosts=cfg.allow_hosts,
                allow_suffixes=cfg.allow_suffixes,
                deny_private=cfg.deny_private,
            )
            if resp is None:
                continue
            if method == "GET":
                # re-issue properly with query string appended
                qs = "&".join(f"{k}={requests.utils.quote(str(v), safe='')}" for k, v in data.items())
                resp, why = http_request(
                    sess,
                    "GET",
                    form.action + ("&" if "?" in form.action else "?") + qs,
                    timeout=cfg.timeout,
                    retries=0,
                    allow_redirects=cfg.allow_redirects,
                    limiter=limiter,
                    allow_hosts=cfg.allow_hosts,
                    allow_suffixes=cfg.allow_suffixes,
                    deny_private=cfg.deny_private,
                )
                if resp is None:
                    continue
            text = resp.text or ""
            if any(ind in text for ind in numeric_indicators) or TEMPLATE_ERROR_RX.search(text):
                findings.append(_make_finding(
                    rule_id="probe-ssti-indicator",
                    name="Possible SSTI Indicator Detected",
                    severity="high" if TEMPLATE_ERROR_RX.search(text) else "medium",
                    url=getattr(resp, 'url', form.action),
                    resp=resp,
                    snippet=text[:900],
                    matches=[f"payload:{payload}", "template_indicator"],
                    tags=["probe", "ssti", "low-risk"],
                    remediation="Do not render user-controlled input as templates; enforce safe escaping and server-side validation.",
                    category="probe",
                ))
                return findings
    return findings
