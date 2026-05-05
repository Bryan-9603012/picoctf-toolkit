from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import List

from core.models import Finding
from postprocess.recover_pro_modular import analyze_file


def _collect_file_recovery(outdir: str) -> list[dict]:
    recovered_files: list[dict] = []

    loot_path = Path(outdir)
    if not loot_path.exists() or not loot_path.is_dir():
        return recovered_files

    allow_suffixes = {
        ".png", ".jpg", ".jpeg", ".gif",
        ".pdf",
        ".zip", ".rar", ".7z",
        ".docx", ".xlsx", ".pptx",
        ".apk", ".jar",
        ".avif", ".webp",
    }

    deny_suffixes = {
        ".json", ".bin", ".map", ".css", ".js",
        ".woff", ".woff2", ".ttf", ".eot",
        ".ico", ".svg", ".heapsnapshot",
    }

    for file_path in loot_path.rglob("*"):
        if not file_path.is_file():
            continue
        if "recovered" in file_path.parts or "artifacts" in file_path.parts:
            continue

        name_lower = file_path.name.lower()
        suffix = file_path.suffix.lower()

        if "heapdump-exposure" in name_lower:
            continue
        if name_lower.endswith(".heapsnapshot"):
            continue
        if suffix in deny_suffixes:
            continue
        if suffix not in allow_suffixes:
            continue

        try:
            report = analyze_file(
                str(file_path),
                no_write=False,
                report_json=False,
                output_dir=str(loot_path / "recovered"),
            )
            recovered_files.append(report)
        except Exception as e:
            recovered_files.append(
                {
                    "source_file": str(file_path),
                    "error": str(e),
                }
            )
    return recovered_files


def _finding_to_dict(f: Finding) -> dict:
    from reports.remediation import enrich_finding_with_remediation
    
    if is_dataclass(f):
        data = asdict(f)
    else:
        data = dict(getattr(f, "__dict__", {}))
    ev = data.get("evidence") or {}
    artifact = ev.get("artifact")
    if isinstance(artifact, dict):
        best = artifact.get("best_guess") or {}
        ev["artifact_summary"] = {
            "source_file": artifact.get("source_file"),
            "best_guess": best.get("name"),
            "subtype": best.get("subtype"),
            "confidence": best.get("confidence"),
            "repair_actions": artifact.get("repair_actions") or [],
            "output_file": artifact.get("output_file"),
            "validations": artifact.get("validations") or [],
            "repair_recommended": artifact.get("repair_recommended"),
            "suspicious_score": artifact.get("suspicious_score"),
        }
    
    # Add structured remediation
    remediation_data = enrich_finding_with_remediation(f)
    data.update(remediation_data)
    
    return data


def write_json(path: str, base: str, outdir: str, findings: List[Finding], cfg=None) -> None:
    # Build metadata
    from datetime import datetime
    metadata = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }
    
    if cfg:
        metadata.update({
            "scan_id": cfg.scan_id,
            "policy": cfg.policy,
            "environment": cfg.environment,
        })
    
    # Calculate summary stats
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    verification_counts = {"observed": 0, "suspected": 0, "verified": 0, "exploited": 0}
    
    for f in findings:
        sev = (f.severity or "unknown").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        
        ver = (f.verification_state or "observed").lower()
        if ver in verification_counts:
            verification_counts[ver] += 1
    
    metadata["summary"] = {
        "total_findings": len(findings),
        "by_severity": severity_counts,
        "by_verification": verification_counts,
    }
    
    obj = {
        "target": base,
        "loot_dir": outdir,
        "metadata": metadata,
        "findings": [_finding_to_dict(f) for f in findings],
        "file_recovery": _collect_file_recovery(outdir),
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)