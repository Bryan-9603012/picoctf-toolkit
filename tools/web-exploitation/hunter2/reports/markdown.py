# reports/markdown.py
from __future__ import annotations

from datetime import datetime
from collections import defaultdict

from core.models import Finding


def _classify(rule_id: str) -> str:
    r = (rule_id or "").lower()
    if "heapdump" in r or "actuator" in r:
        return "設定錯誤"
    if "git" in r or "backup" in r or "env" in r:
        return "敏感檔案暴露"
    if "secret" in r or "token" in r or "key" in r:
        return "敏感資訊外洩"
    if "artifact" in r or "file" in r:
        return "檔案分析"
    if "sqli" in r:
        return "SQL 注入"
    if "xss" in r:
        return "跨站腳本"
    if "ssrf" in r:
        return "SSRF"
    if "lfi" in r or "path-traversal" in r:
        return "檔案包含／路徑穿越"
    return "其他"


def _artifact_from_finding(finding: Finding):
    evidence = getattr(finding, "evidence", None)
    if evidence is None:
        return None
    return getattr(evidence, "artifact", None)


def _severity_zh(severity: str) -> str:
    s = (severity or "").lower()
    mapping = {
        "critical": "重大",
        "high": "高",
        "medium": "中",
        "low": "低",
        "info": "資訊",
        "unknown": "未知",
    }
    return mapping.get(s, severity)


def _verification_state_zh(state: str) -> str:
    s = (state or "").lower()
    mapping = {
        "observed": "已觀察",
        "suspected": "可疑",
        "verified": "已驗證",
        "exploited": "已利用",
    }
    return mapping.get(s, state)




def _finding_to_md(finding: Finding) -> str:
    title = getattr(finding, "title", "") or getattr(finding, "rule_id", "finding")
    lines = [f"## {title}", "", f"- Rule: `{getattr(finding, 'rule_id', '')}`", f"- Severity: `{getattr(finding, 'severity', 'unknown')}`", f"- URL: `{getattr(finding, 'url', '')}`"]
    matches = getattr(finding, "matches", None) or []
    if matches:
        lines.append("- Matches:")
        lines.extend([f"  - `{m}`" for m in matches])
    remediation = getattr(finding, "remediation", None)
    if remediation:
        lines.append(f"- Remediation: {remediation}")
    return "\n".join(lines) + "\n"


def write_markdown(path, base, outdir, findings):
    groups = defaultdict(list)
    for finding in findings:
        groups[_classify(getattr(finding, "rule_id", ""))].append(finding)

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0,
    }

    artifact_count = 0
    repaired_count = 0
    validation_ok_count = 0
    validation_fail_count = 0

    for finding in findings:
        sev = (getattr(finding, "severity", "unknown") or "unknown").lower()
        if sev not in severity_counts:
            sev = "unknown"
        severity_counts[sev] += 1

        artifact = _artifact_from_finding(finding)
        if isinstance(artifact, dict):
            artifact_count += 1
            if artifact.get("output_file"):
                repaired_count += 1
            for msg in artifact.get("validations") or []:
                if "[OK]" in msg:
                    validation_ok_count += 1
                elif "[FAIL]" in msg:
                    validation_fail_count += 1

    with open(path, "w", encoding="utf-8") as f:
        f.write("# Hunter-2 安全掃描報告\n\n")
        f.write(f"**目標：** {base}\n\n")
        f.write(f"**產生時間：** {datetime.utcnow().isoformat()} UTC\n\n")
        f.write(f"**輸出資料夾：** `{outdir}`\n\n")
        f.write(f"**總發現數：** {len(findings)}\n\n")

        f.write("## 摘要\n\n")
        if not findings:
            f.write("未發現明確漏洞或可疑項目。\n")
            return

        for cat, items in groups.items():
            f.write(f"- **{cat}**：{len(items)} 項\n")

        f.write("\n### 風險等級統計\n\n")
        f.write(f"- **重大**：{severity_counts['critical']}\n")
        f.write(f"- **高**：{severity_counts['high']}\n")
        f.write(f"- **中**：{severity_counts['medium']}\n")
        f.write(f"- **低**：{severity_counts['low']}\n")
        f.write(f"- **資訊**：{severity_counts['info']}\n")
        f.write(f"- **未知**：{severity_counts['unknown']}\n")

        verification_counts = {"observed": 0, "suspected": 0, "verified": 0, "exploited": 0}
        for finding in findings:
            v = getattr(finding, "verification_state", "observed") or "observed"
            if v in verification_counts:
                verification_counts[v] += 1

        f.write("\n### 驗證狀態統計\n\n")
        f.write(f"- **已觀察 (observed)**：{verification_counts['observed']}\n")
        f.write(f"- **可疑 (suspected)**：{verification_counts['suspected']}\n")
        f.write(f"- **已驗證 (verified)**：{verification_counts['verified']}\n")
        f.write(f"- **已利用 (exploited)**：{verification_counts['exploited']}\n")

        f.write("\n### 檔案分析統計\n\n")
        f.write(f"- **已分析檔案數**：{artifact_count}\n")
        f.write(f"- **已輸出修補檔數**：{repaired_count}\n")
        f.write(f"- **驗證成功次數**：{validation_ok_count}\n")
        f.write(f"- **驗證失敗次數**：{validation_fail_count}\n")

        f.write("\n---\n\n")

        idx = 1
        for cat, items in groups.items():
            f.write(f"# {cat}\n\n")

            for finding in items:
                rule_id = getattr(finding, "rule_id", "unknown")
                severity = getattr(finding, "severity", "unknown")
                url = getattr(finding, "url", "")
                verification = getattr(finding, "verification_state", "observed")
                confidence = getattr(finding, "confidence", "medium")
                cwe = getattr(finding, "cwe", None)
                owasp = getattr(finding, "owasp", None)

                f.write(f"## {idx}. {rule_id}\n\n")
                f.write(f"**風險等級：** {_severity_zh(severity)}\n\n")
                f.write(f"**驗證狀態：** {_verification_state_zh(verification)}\n\n")
                f.write(f"**信心水準：** {confidence}\n\n")
                f.write(f"**網址：** `{url}`\n\n")

                if cwe or owasp:
                    f.write("**漏洞分類：** ")
                    parts = []
                    if cwe:
                        parts.append(f"CWE-{cwe}")
                    if owasp:
                        parts.append(f"OWASP {owasp}")
                    f.write(" | ".join(parts) + "\n\n")

                matches = getattr(finding, "matches", None)
                if matches:
                    f.write("**證據：**\n\n")
                    for m in matches:
                        f.write(f"- `{m}`\n")
                    f.write("\n")

                artifact = _artifact_from_finding(finding)
                if isinstance(artifact, dict):
                    best = artifact.get("best_guess") or {}
                    f.write("**檔案分析：**\n\n")

                    if artifact.get("source_file"):
                        f.write(f"- 來源檔案：`{artifact['source_file']}`\n")

                    if best.get("name"):
                        label = best["name"] + (f" ({best['subtype']})" if best.get("subtype") else "")
                        f.write(f"- 最可能類型：`{label}`\n")

                    if best.get("confidence"):
                        f.write(f"- 信心水準：`{best['confidence']}`\n")

                    if artifact.get("suspicious_score") is not None:
                        f.write(f"- 可疑分數：`{artifact['suspicious_score']}`\n")

                    if artifact.get("repair_recommended") is not None:
                        repair_text = "是" if artifact.get("repair_recommended") else "否"
                        f.write(f"- 建議修補：`{repair_text}`\n")

                    if artifact.get("output_file"):
                        f.write(f"- 修補後輸出：`{artifact['output_file']}`\n")

                    if artifact.get("repair_actions"):
                        f.write("- 修補動作：\n")
                        for action in artifact["repair_actions"]:
                            f.write(f"  - `{action}`\n")

                    if artifact.get("validations"):
                        f.write("- 驗證結果：\n")
                        for msg in artifact["validations"]:
                            f.write(f"  - `{msg}`\n")
                    elif best.get("name") in {"AVIF", "WEBP", "MP4"}:
                        f.write("- 驗證結果：\n")
                        f.write("  - `此格式目前以辨識為主，不進行修補與結構驗證。`\n")

                    f.write("\n")

                description = getattr(finding, "description", None)
                if description:
                    f.write(f"**說明：** {description}\n\n")

                remediation = getattr(finding, "remediation", None)
                if remediation:
                    f.write(f"**修補建議：** {remediation}\n\n")

                f.write("---\n\n")
                idx += 1