# reports/sarif.py
from __future__ import annotations

import json
from typing import Dict, List

from core.models import Finding


_SEV_MAP = {
    "info": "note",
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}


def _sarif_level(sev: str) -> str:
    return _SEV_MAP.get((sev or "").lower(), "note")


def _rule_from_finding(f: Finding) -> Dict:
    return {
        "id": f.rule_id,
        "name": f.name,
        "shortDescription": {"text": f.name},
        "fullDescription": {"text": f.remediation or f.name},
        "help": {"text": f.remediation or "Review and remediate this finding."},
        "properties": {
            "category": f.category,
            "severity": f.severity,
            "tags": f.tags or [],
        },
    }


def _result_from_finding(f: Finding) -> Dict:
    msg = f"{f.name} ({f.severity})"
    if f.matches:
        msg += f" | matches: {', '.join(f.matches[:3])}"

    loc = {
        "physicalLocation": {
            "artifactLocation": {"uri": f.url},
        }
    }

    return {
        "ruleId": f.rule_id,
        "level": _sarif_level(f.severity),
        "message": {"text": msg},
        "locations": [loc],
        "properties": {
            "risk_score": f.risk_score,
            "method": f.evidence.method if f.evidence else None,
            "status": f.evidence.status if f.evidence else None,
        },
    }


def write_sarif(path: str, base: str, outdir: str, findings: List[Finding]) -> None:
    # SARIF 2.1.0 minimal
    rules = {}
    for f in findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = _rule_from_finding(f)

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "hunter-2",
                        "informationUri": "https://example.invalid/hunter-2",
                        "rules": list(rules.values()),
                    }
                },
                "properties": {"target": base, "loot_dir": outdir},
                "results": [_result_from_finding(f) for f in findings],
            }
        ],
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, ensure_ascii=False, indent=2)