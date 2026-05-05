from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import yaml


SEVERITY_TO_SCORE = {
    "low": 10,
    "medium": 20,
    "high": 35,
    "critical": 50,
}


def load_rules(path: Path) -> List[Dict[str, object]]:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data.get("rules", [])


def apply_rules(result: Dict[str, object], rules: List[Dict[str, object]]) -> Dict[str, object]:
    findings: List[Dict[str, object]] = []
    total_score = 0

    for rule in rules:
        matched, evidence = _evaluate_rule(rule, result)
        if matched:
            severity = str(rule.get("severity", "low")).lower()
            score = int(rule.get("score", SEVERITY_TO_SCORE.get(severity, 10)))
            findings.append({
                "id": rule.get("id", "unnamed_rule"),
                "name": rule.get("name", "Unnamed rule"),
                "severity": severity,
                "score": score,
                "description": rule.get("description", ""),
                "evidence": evidence,
            })
            total_score += score

    total_score = min(total_score, 100)
    return {
        "findings": findings,
        "risk_score": total_score,
        "risk_level": classify_risk(total_score),
    }


def classify_risk(score: int) -> str:
    if score <= 20:
        return "Low"
    if score <= 50:
        return "Medium"
    if score <= 80:
        return "High"
    return "Critical"


def _evaluate_rule(rule: Dict[str, object], result: Dict[str, object]) -> tuple[bool, str]:
    condition = rule.get("condition", {})
    cond_type = condition.get("type")

    if cond_type == "extension_mismatch":
        sig = result["signature"]
        if sig["detected"] and not sig["extension_matches"]:
            return True, f"Extension {sig['file_extension'] or '(none)'} does not match detected type {sig['type']}."
        return False, ""

    if cond_type == "double_extension":
        name = result["file_info"]["name"].lower()
        suspicious_exts = condition.get("extensions", [".exe", ".dll", ".js", ".vbs", ".scr", ".bat"])
        parts = name.split(".")
        if len(parts) >= 3 and any(name.endswith(ext) for ext in suspicious_exts):
            return True, f"Filename suggests double extension: {result['file_info']['name']}"
        return False, ""

    if cond_type == "entropy_above":
        threshold = float(condition.get("threshold", 7.2))
        score = float(result["entropy"]["score"])
        if score >= threshold:
            return True, f"Entropy {score:.3f} exceeds threshold {threshold:.3f}."
        return False, ""

    if cond_type == "detected_type_in":
        wanted = set(condition.get("values", []))
        detected = result["signature"]["type"]
        if detected in wanted:
            return True, f"Detected type {detected} matched watched types."
        return False, ""

    if cond_type == "suspicious_strings_present":
        strings = result.get("strings", {})
        suspicious = strings.get("suspicious_strings", [])
        if suspicious:
            return True, f"Found {len(suspicious)} suspicious strings."
        return False, ""

    if cond_type == "embedded_files_present":
        embedded = result.get("embedded", [])
        if embedded:
            return True, f"Found {len(embedded)} embedded artifact candidates."
        return False, ""

    return False, ""
