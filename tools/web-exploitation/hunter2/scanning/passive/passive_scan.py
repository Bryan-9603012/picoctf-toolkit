from __future__ import annotations

import hashlib
import mimetypes
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

from core.session import build_session
from config.config import Config
from core.http_client import request as http_request, headers_subset
from core.limiter import GlobalRateLimiter
from core.models import Evidence, Finding
from core.secrets import scan_text, content_type_allows
from enumeration.enumerator import TargetSet
from postprocess.recover_pro_modular import analyze_file
from scanning.passive.client_insights import analyze_response, analyze_script_response, run_low_risk_probes


def _safe_name_from_url(url: str, content_type: str) -> str:
    parsed = urlparse(url)
    raw_name = Path(parsed.path).name.strip()

    if raw_name:
        name = raw_name
    else:
        ext = mimetypes.guess_extension((content_type or "").split(";")[0].strip()) or ".bin"
        name = f"index{ext}"

    digest = hashlib.sha1(url.encode("utf-8", errors="ignore")).hexdigest()[:10]
    stem = Path(name).stem or "artifact"
    suffix = Path(name).suffix or ""
    return f"{stem}_{digest}{suffix}"


def _should_save_artifact(cfg: Config, url: str, content_type: str, content: bytes, headers: dict) -> bool:
    if not getattr(cfg, "artifact_analysis", True):
        return False
    if not getattr(cfg, "save_artifacts", True):
        return False
    if not content:
        return False

    max_bytes = int(getattr(cfg, "max_artifact_bytes", 10 * 1024 * 1024) or (10 * 1024 * 1024))
    if len(content) > max_bytes:
        return False

    ct = (content_type or "").lower().split(";")[0].strip()
    cd = (headers.get("Content-Disposition") or "").lower()
    parsed = urlparse(url)
    suffix = Path(parsed.path).suffix.lower()
    name = Path(parsed.path).name.lower()

    deny_suffixes = {
        ".heapsnapshot", ".map", ".ico", ".svg",
        ".woff", ".woff2", ".ttf", ".eot",
        ".css", ".js",
    }
    if suffix in deny_suffixes:
        return False

    deny_content_types = {
        "image/avif",
        "image/webp",
        "image/svg+xml",
        "text/css",
        "application/javascript",
        "text/javascript",
    }
    if ct in deny_content_types:
        return False

    if name.endswith(".heapsnapshot"):
        return False

    if "attachment" in cd:
        return True

    allow_suffixes = {
        ".png", ".jpg", ".jpeg", ".gif", ".pdf",
        ".zip", ".rar", ".7z",
        ".docx", ".xlsx", ".pptx",
        ".apk", ".jar",
        ".wav", ".avi", ".mp3", ".mp4",
        ".bin",
    }
    if suffix in allow_suffixes:
        return True

    allow_content_types = {
        "image/png",
        "image/jpeg",
        "image/gif",
        "application/pdf",
        "application/zip",
        "application/x-zip-compressed",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.android.package-archive",
        "audio/wav",
        "video/avi",
        "audio/mpeg",
        "video/mp4",
        "application/octet-stream",
    }
    if ct in allow_content_types:
        return True

    return False


def _artifact_root(cfg: Config) -> Path:
    custom = getattr(cfg, "artifact_outdir", "") or ""
    if custom:
        return Path(custom)
    return Path(cfg.outdir)


def _save_response_artifact(cfg: Config, url: str, content: bytes, content_type: str) -> str | None:
    if not content:
        return None

    artifact_dir = _artifact_root(cfg) / "artifacts" / "passive"
    artifact_dir.mkdir(parents=True, exist_ok=True)

    filename = _safe_name_from_url(url, content_type)
    out_path = artifact_dir / filename
    out_path.write_bytes(content)
    return str(out_path)


def _analyze_saved_artifact(cfg: Config, saved_path: str) -> dict | None:
    if not getattr(cfg, "artifact_analysis", True):
        return None

    try:
        report = analyze_file(
            saved_path,
            no_write=False,
            report_json=False,
            output_dir=str(_artifact_root(cfg) / "recovered" / "passive"),
        )
        return report
    except Exception as e:
        return {
            "source_file": saved_path,
            "error": str(e),
        }


def _make_artifact_finding(
    url: str,
    resp: requests.Response,
    artifact_report: dict,
) -> Finding:
    best_guess = artifact_report.get("best_guess") or {}
    best_name = best_guess.get("name") or "unknown"
    subtype = best_guess.get("subtype")
    confidence = best_guess.get("confidence") or "Unknown"

    label = best_name if not subtype else f"{best_name} ({subtype})"

    validations = artifact_report.get("validations") or []
    severity = "info"
    if any(isinstance(v, str) and "[FAIL]" in v for v in validations):
        severity = "medium"
    elif artifact_report.get("repair_actions"):
        severity = "low"

    ev = Evidence(
        method="GET",
        url=url,
        status=resp.status_code,
        headers=headers_subset(dict(resp.headers)),
        content_length=len(resp.content or b""),
        elapsed_ms=getattr(resp, "_hunter_elapsed_ms", None),
        snippet="; ".join(validations[:4])[:1200],
        artifact=artifact_report,
        scope_reason="ok",
    )

    fd = Finding(
        rule_id="passive-artifact-analysis",
        name=f"Passive Artifact Analysis: {label}",
        category="passive",
        severity=severity,
        url=url,
        evidence=ev,
        matches=[
            f"best_guess:{label}",
            f"confidence:{confidence}",
        ],
        tags=["passive", "artifact", "file-analysis"],
        remediation="Review downloaded artifact, verify true file type, and inspect repaired output if generated.",
        variables={},
    )
    fd.compute_risk_score()
    return fd


def _passive_fetch_and_scan(cfg: Config, sess: requests.Session, limiter: GlobalRateLimiter, url: str) -> list[Finding]:
    resp, why = http_request(
        sess,
        "GET",
        url,
        timeout=cfg.timeout,
        retries=cfg.retries,
        allow_redirects=cfg.allow_redirects,
        limiter=limiter,
        allow_hosts=cfg.allow_hosts,
        allow_suffixes=cfg.allow_suffixes,
        deny_private=cfg.deny_private,
    )
    if resp is None:
        if cfg.verbose:
            print(f"[!] [passive] {url} skipped -> {why}")
        return []

    findings: list[Finding] = []
    ct = resp.headers.get("Content-Type") or ""
    content = resp.content or b""

    artifact_report = None

    if _should_save_artifact(cfg, url, ct, content, dict(resp.headers)):
        saved_path = _save_response_artifact(cfg, url, content, ct)
        if saved_path:
            artifact_report = _analyze_saved_artifact(cfg, saved_path)
            if artifact_report and artifact_report.get("best_guess"):
                best = artifact_report.get("best_guess") or {}
                confidence = (best.get("confidence") or "").lower()
                if confidence in {"medium", "high"}:
                    findings.append(_make_artifact_finding(url, resp, artifact_report))
                    if cfg.verbose:
                        print(
                            f"[+] [passive-artifact] {url} -> "
                            f"{best.get('name')}"
                            + (f" ({best.get('subtype')})" if best.get("subtype") else "")
                        )

    if not content_type_allows(ct):
        return findings

    try:
        text = resp.text or ""
    except Exception:
        return findings

    insights = analyze_response(url, resp, text)
    findings.extend(insights.findings)

    for script_url in insights.scripts_to_fetch[:5]:
        s_resp, s_why = http_request(
            sess,
            "GET",
            script_url,
            timeout=cfg.timeout,
            retries=cfg.retries,
            allow_redirects=cfg.allow_redirects,
            limiter=limiter,
            allow_hosts=cfg.allow_hosts,
            allow_suffixes=cfg.allow_suffixes,
            deny_private=cfg.deny_private,
        )
        if s_resp is None:
            continue
        try:
            script_text = s_resp.text or ""
        except Exception:
            script_text = ""
        findings.extend(analyze_script_response(script_url, s_resp, script_text))

    if getattr(cfg, "policy", "balanced") in {"balanced", "aggressive"}:
        findings.extend(run_low_risk_probes(cfg, sess, limiter, url, insights.forms))

    hits = scan_text(text, max_hits=20)
    if hits:
        matches = [f"{h.kind}:{h.value}" for h in hits]
        sev = "high" if any("picoctf_flag" in m for m in matches) else "medium"

        ev = Evidence(
            method="GET",
            url=url,
            status=resp.status_code,
            headers=headers_subset(dict(resp.headers)),
            content_length=len(content),
            elapsed_ms=getattr(resp, "_hunter_elapsed_ms", None),
            snippet=text[:1200],
            artifact=artifact_report,
            scope_reason="ok",
        )
        fd = Finding(
            rule_id="passive-secrets",
            name="Passive Secrets in Response",
            title="Passive Secrets in Response",
            category="passive",
            severity=sev,
            url=url,
            evidence=ev,
            matches=matches,
            tags=["passive", "secrets"],
            remediation="Remove secrets from client-facing responses; rotate exposed keys/tokens.",
            variables={},
        )
        fd.compute_risk_score()
        findings.append(fd)

    return findings


def run_passive_scan(cfg: Config, targets: TargetSet, scan_id: str = None) -> list[Finding]:
    sess = build_session(cfg)
    limiter = GlobalRateLimiter(cfg.qps)

    scan_urls = [cfg.base.rstrip("/") + "/"]
    for p in (targets.paths or [])[:200]:
        scan_urls.append(urljoin(cfg.base + "/", p.lstrip("/")))

    findings: list[Finding] = []
    for u in scan_urls:
        findings.extend(_passive_fetch_and_scan(cfg, sess, limiter, u))
    
    # Inject scan_id into all findings
    for f in findings:
        if scan_id:
            f.scan_id = scan_id
        if not f.id and f.rule_id:
            f.id = f"finding-{f.rule_id}-{hash(f.url) % 100000}"
        if not f.title and f.name:
            f.title = f.name
    
    return findings