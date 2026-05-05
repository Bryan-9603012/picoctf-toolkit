# reports/html.py
from __future__ import annotations

import html
from datetime import datetime
from typing import Any, Dict, List

from core.models import Finding


SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#16a34a",
    "info": "#2563eb",
}


def _severity_zh(severity: str) -> str:
    s = (severity or "").lower()
    mapping = {
        "critical": "重大",
        "high": "高",
        "medium": "中",
        "low": "低",
        "info": "資訊",
    }
    return mapping.get(s, severity)


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


def _format_chain(chain: List) -> str:
    if not chain:
        return ""
    
    steps = []
    for i, step in enumerate(chain):
        url = getattr(step, "url", "unknown")
        action = getattr(step, "action", "unknown")
        steps.append(f"{i+1}. [{action}] {html.escape(url)}")
    
    return "\n".join(steps)


def generate_html_report(
    path: str,
    base: str,
    outdir: str,
    findings: List[Finding],
    artifacts: List[Dict] = None,
    chains: List[List[Finding]] = None,
    flags: List[str] = None,
    clues: List[str] = None,
    delta_report: Any = None,
    suppressed_count: int = 0,
    scan_metadata: Dict = None,
) -> None:
    if artifacts is None:
        artifacts = []
    if chains is None:
        chains = []
    if flags is None:
        flags = []
    if clues is None:
        clues = []
    if delta_report is None:
        delta_report = None
    if scan_metadata is None:
        scan_metadata = {}
    
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (getattr(f, "severity", "info") or "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    verification_counts = {"observed": 0, "suspected": 0, "verified": 0, "exploited": 0}
    for f in findings:
        state = getattr(f, "verification_state", "observed") or "observed"
        if state in verification_counts:
            verification_counts[state] += 1
    
    with open(path, "w", encoding="utf-8") as f:
        f.write("""<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hunter-2 Security Report</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
               background: #f5f5f5; color: #1f2937; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1 { color: #111827; border-bottom: 3px solid #3b82f6; padding-bottom: 10px; }
        h2 { color: #374151; margin-top: 30px; border-left: 4px solid #3b82f6; padding-left: 12px; }
        .meta { background: #e5e7eb; padding: 15px; border-radius: 8px; margin: 20px 0; }
        .meta p { margin: 5px 0; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .stat-card .count { font-size: 2em; font-weight: bold; }
        .stat-card.critical .count { color: """ + SEVERITY_COLORS["critical"] + """; }
        .stat-card.high .count { color: """ + SEVERITY_COLORS["high"] + """; }
        .stat-card.medium .count { color: """ + SEVERITY_COLORS["medium"] + """; }
        .stat-card.low .count { color: """ + SEVERITY_COLORS["low"] + """; }
        .stat-card.info .count { color: """ + SEVERITY_COLORS["info"] + """; }
        .finding { background: white; padding: 20px; margin: 15px 0; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .severity-badge { padding: 4px 12px; border-radius: 4px; color: white; font-weight: bold; font-size: 0.9em; }
        .severity-critical { background: """ + SEVERITY_COLORS["critical"] + """; }
        .severity-high { background: """ + SEVERITY_COLORS["high"] + """; }
        .severity-medium { background: """ + SEVERITY_COLORS["medium"] + """; }
        .severity-low { background: """ + SEVERITY_COLORS["low"] + """; }
        .severity-info { background: """ + SEVERITY_COLORS["info"] + """; }
        .url { font-family: monospace; background: #f3f4f6; padding: 8px 12px; border-radius: 4px; word-break: break-all; }
        .confidence { margin-top: 10px; font-size: 0.9em; }
        .confidence span { padding: 2px 8px; border-radius: 3px; }
        .confidence-high { background: #dcfce7; color: #166534; }
        .confidence-medium { background: #fef9c3; color: #854d0e; }
        .confidence-low { background: #fee2e2; color: #991b1b; }
        .evidence { background: #f8fafc; padding: 12px; border-radius: 4px; margin: 10px 0; font-family: monospace; font-size: 0.9em; overflow-x: auto; }
        .chain { background: #f0f9ff; padding: 15px; border-radius: 8px; margin: 10px 0; border-left: 4px solid #0ea5e9; }
        .chain-title { font-weight: bold; color: #0369a1; margin-bottom: 8px; }
        .chain-step { padding: 5px 0; }
        .remediation { background: #fef2f2; padding: 12px; border-radius: 4px; margin-top: 10px; border-left: 4px solid #ef4444; }
        .remediation-title { font-weight: bold; color: #b91c1c; }
        .flags { background: #f0fdf4; padding: 20px; border-radius: 8px; margin: 20px 0; border: 2px solid #22c55e; }
        .flag { font-family: monospace; font-size: 1.2em; color: #15803d; font-weight: bold; }
        .clues { background: #fff7ed; padding: 15px; border-radius: 8px; margin: 15px 0; }
        .clue { padding: 5px 0; border-bottom: 1px dashed #fdba74; }
        .artifacts { margin-top: 20px; }
        .artifact-item { background: #f8fafc; padding: 10px; margin: 8px 0; border-radius: 4px; }
        .artifact-type { font-weight: bold; color: #475569; }
        .artifact-path { font-family: monospace; font-size: 0.9em; color: #64748b; }
        .category-section { margin: 30px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Hunter-2 Security Report</h1>
        
        <div class="meta">
            <p><strong>Target:</strong> <span class="url">""" + html.escape(base) + """</span></p>
            <p><strong>Scan Time:</strong> """ + datetime.utcnow().isoformat() + """ UTC</p>
            <p><strong>Output Directory:</strong> """ + html.escape(outdir) + """</p>
            <p><strong>Total Findings:</strong> """ + str(len(findings)) + """</p>
        </div>
""")

        f.write("""        <h2>Summary</h2>
        <div class="summary">
            <div class="stat-card critical">
                <div class="count">""" + str(severity_counts["critical"]) + """</div>
                <div>Critical</div>
            </div>
            <div class="stat-card high">
                <div class="count">""" + str(severity_counts["high"]) + """</div>
                <div>High</div>
            </div>
            <div class="stat-card medium">
                <div class="count">""" + str(severity_counts["medium"]) + """</div>
                <div>Medium</div>
            </div>
            <div class="stat-card low">
                <div class="count">""" + str(severity_counts["low"]) + """</div>
                <div>Low</div>
            </div>
            <div class="stat-card info">
                <div class="count">""" + str(severity_counts["info"]) + """</div>
                <div>Info</div>
            </div>
        </div>
""")
        
        VERIFICATION_COLORS = {
            "observed": "#6b7280",
            "suspected": "#f59e0b", 
            "verified": "#10b981",
            "exploited": "#dc2626",
        }
        
        f.write("""        <h2>Verification Status</h2>
        <div class="summary">
            <div class="stat-card" style="border-left: 4px solid """ + VERIFICATION_COLORS["observed"] + """">
                <div class="count">""" + str(verification_counts["observed"]) + """</div>
                <div>Observed</div>
            </div>
            <div class="stat-card" style="border-left: 4px solid """ + VERIFICATION_COLORS["suspected"] + """">
                <div class="count">""" + str(verification_counts["suspected"]) + """</div>
                <div>Suspected</div>
            </div>
            <div class="stat-card" style="border-left: 4px solid """ + VERIFICATION_COLORS["verified"] + """">
                <div class="count">""" + str(verification_counts["verified"]) + """</div>
                <div>Verified</div>
            </div>
            <div class="stat-card" style="border-left: 4px solid """ + VERIFICATION_COLORS["exploited"] + """">
                <div class="count">""" + str(verification_counts["exploited"]) + """</div>
                <div>Exploited</div>
            </div>
        </div>
""")
        
        if suppressed_count > 0 or delta_report:
            f.write("""        <h2>Comparison</h2>
        <div class="summary">
""")
            if suppressed_count > 0:
                f.write(f"""            <div class="stat-card" style="border-left: 4px solid #8b5cf6;">
                <div class="count">{suppressed_count}</div>
                <div>Suppressed</div>
            </div>
""")
            if delta_report:
                new_count = len(getattr(delta_report, 'new_findings', []))
                resolved_count = len(getattr(delta_report, 'resolved_findings', []))
                changed_count = len(getattr(delta_report, 'changed_findings', []))
                f.write(f"""            <div class="stat-card" style="border-left: 4px solid #ef4444;">
                <div class="count">{new_count}</div>
                <div>New (vs baseline)</div>
            </div>
            <div class="stat-card" style="border-left: 4px solid #22c55e;">
                <div class="count">{resolved_count}</div>
                <div>Resolved</div>
            </div>
            <div class="stat-card" style="border-left: 4px solid #f59e0b;">
                <div class="count">{changed_count}</div>
                <div>Changed</div>
            </div>
""")
            f.write("""        </div>
""")

        if flags:
            f.write("""        <div class="flags">
            <h2>Flags Found</h2>
""")
            for flag in flags:
                f.write(f'            <div class="flag">{html.escape(flag)}</div>\n')
            f.write("""        </div>
""")

        if clues:
            f.write("""        <div class="clues">
            <h2>CTF Clues</h2>
""")
            for clue in clues:
                f.write(f'            <div class="clue">{html.escape(clue)}</div>\n')
            f.write("""        </div>
""")

        if chains:
            f.write("""        <h2>Exploitation Chains</h2>
""")
            for i, chain in enumerate(chains):
                f.write(f"""        <div class="chain">
            <div class="chain-title">Chain #{i+1}</div>
""")
                for step in chain:
                    f.write(f'            <div class="chain-step">[{html.escape(step.rule_id)}] {html.escape(step.url)}</div>\n')
                f.write("""        </div>
""")

        if artifacts:
            f.write("""        <div class="artifacts">
            <h2>Collected Artifacts</h2>
""")
            for art in artifacts:
                f.write(f"""            <div class="artifact-item">
                <div class="artifact-type">{html.escape(art.get('file_type', 'unknown'))}</div>
                <div class="artifact-path">{html.escape(art.get('path', ''))}</div>
                {f'<div>Secrets: {len(art.get("secrets", []))}</div>' if art.get("secrets") else ""}
            </div>
""")
            f.write("""        </div>
""")

        f.write("""        <h2>Technical Findings</h2>
""")

        from collections import defaultdict
        groups = defaultdict(list)
        for finding in findings:
            groups[_classify(getattr(finding, "rule_id", ""))].append(finding)

        idx = 1
        for cat, items in groups.items():
            f.write(f'        <div class="category-section">\n')
            f.write(f'            <h2>{html.escape(cat)}</h2>\n')
            
            for finding in items:
                rule_id = getattr(finding, "rule_id", "unknown")
                severity = getattr(finding, "severity", "info")
                url = getattr(finding, "url", "")
                confidence = getattr(finding, "confidence", "medium")
                chain = getattr(finding, "chain", [])
                remediation = getattr(finding, "remediation", "")
                matches = getattr(finding, "matches", [])
                clues_attr = getattr(finding, "clues", [])
                verification_state = getattr(finding, "verification_state", "observed") or "observed"
                
                sev_class = f"severity-{severity.lower()}"
                
                VERIFICATION_STATE_ZH = {
                    "observed": "觀測",
                    "suspected": "可疑",
                    "verified": "已驗證",
                    "exploited": "已利用",
                }
                
                f.write(f"""        <div class="finding">
            <div class="finding-header">
                <div>
                    <strong>{idx}. {html.escape(rule_id)}</strong>
                </div>
                <div>
                    <span class="severity-badge {sev_class}">{_severity_zh(severity)}</span>
                    <span class="severity-badge" style="background: #6b7280; margin-left: 8px;">{VERIFICATION_STATE_ZH.get(verification_state, verification_state)}</span>
                </div>
            </div>
            <div class="url">{html.escape(url)}</div>
            <div class="confidence">Confidence: <span class="confidence-{confidence}">{confidence.upper()}</span></div>
""")
                
                if matches:
                    f.write('            <div class="evidence"><strong>Evidence:</strong><br>\n')
                    for m in matches[:5]:
                        f.write(f'                {html.escape(str(m)[:200])}<br>\n')
                    f.write('            </div>\n')
                
                if chain:
                    f.write(f'            <div class="chain">\n')
                    f.write('                <div class="chain-title">Exploitation Chain</div>\n')
                    for step in chain:
                        f.write(f'                <div class="chain-step">[{html.escape(step.rule_id)}] {html.escape(step.url)}</div>\n')
                    f.write('            </div>\n')
                
                if clues_attr:
                    f.write('            <div class="clues"><strong>Clues:</strong>\n')
                    for clue in clues_attr:
                        f.write(f'                <div class="clue">{html.escape(clue)}</div>\n')
                    f.write('            </div>\n')
                
                if remediation:
                    f.write(f"""            <div class="remediation">
                <div class="remediation-title">Remediation</div>
                {html.escape(remediation)}
            </div>
""")
                
                f.write('        </div>\n')
                idx += 1
            
            f.write('        </div>\n')

        f.write("""    </div>
</body>
</html>
""")


def write_html(
    path: str,
    base: str,
    outdir: str,
    findings: List[Finding],
    delta_report=None,
    suppressed_count: int = 0,
    scan_metadata: dict = None,
) -> None:
    generate_html_report(path, base, outdir, findings)
