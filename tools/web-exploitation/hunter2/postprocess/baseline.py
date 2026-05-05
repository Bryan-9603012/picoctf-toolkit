# postprocess/baseline.py
"""
Baseline Comparison / Delta Reporting

Compare current scan results against a baseline to identify:
- New findings
- Resolved findings
- Findings with changed severity/verification
"""

from __future__ import annotations
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import json


@dataclass
class BaselineFinding:
    """A finding from baseline scan"""
    rule_id: str
    url: str
    severity: str
    verification_state: str
    scan_id: str
    timestamp: str


@dataclass
class DeltaFinding:
    """A finding showing change from baseline"""
    finding: Any
    delta_type: str  # "new", "resolved", "changed"
    previous_severity: Optional[str] = None
    previous_state: Optional[str] = None


@dataclass
class BaselineReport:
    """Complete baseline comparison result"""
    baseline_scan_id: str
    current_scan_id: str
    
    new_findings: List[DeltaFinding] = field(default_factory=list)
    resolved_findings: List[BaselineFinding] = field(default_factory=list)
    changed_findings: List[DeltaFinding] = field(default_factory=list)
    unchanged_findings: List[Any] = field(default_factory=list)
    
    stats: Dict[str, int] = field(default_factory=dict)


def load_baseline(baseline_path: str) -> Dict[str, BaselineFinding]:
    """Load baseline findings from JSON file"""
    baseline = {}
    
    try:
        with open(baseline_path, 'r') as f:
            data = json.load(f)
            
        findings = data.get('findings', [])
        metadata = data.get('metadata', {})
        baseline_scan_id = metadata.get('scan_id', 'unknown')
        
        for f in findings:
            key = f"{f['rule_id']}::{f['url']}"
            baseline[key] = BaselineFinding(
                rule_id=f['rule_id'],
                url=f['url'],
                severity=f.get('severity', 'unknown'),
                verification_state=f.get('verification_state', 'observed'),
                scan_id=baseline_scan_id,
                timestamp=metadata.get('generated_at', ''),
            )
    except FileNotFoundError:
        print(f"[!] Baseline file not found: {baseline_path}")
    except json.JSONDecodeError:
        print(f"[!] Invalid baseline JSON: {baseline_path}")
    
    return baseline


def compare_with_baseline(
    current_findings: List[Any],
    baseline: Dict[str, BaselineFinding],
    current_scan_id: str,
    baseline_scan_id: str,
) -> BaselineReport:
    """Compare current findings against baseline"""
    
    report = BaselineReport(
        baseline_scan_id=baseline_scan_id,
        current_scan_id=current_scan_id,
    )
    
    # Build current finding keys
    current_keys = set()
    current_by_key = {}
    
    for f in current_findings:
        key = f"{f.rule_id}::{f.url}"
        current_keys.add(key)
        current_by_key[key] = f
    
    # Find baseline keys
    baseline_keys = set(baseline.keys())
    
    # New findings (in current but not in baseline)
    new_keys = current_keys - baseline_keys
    for key in new_keys:
        report.new_findings.append(DeltaFinding(
            finding=current_by_key[key],
            delta_type="new",
        ))
    
    # Resolved findings (in baseline but not in current)
    resolved_keys = baseline_keys - current_keys
    for key in resolved_keys:
        report.resolved_findings.append(baseline[key])
    
    # Changed findings (exist in both but differ)
    common_keys = current_keys & baseline_keys
    for key in common_keys:
        current_f = current_by_key[key]
        baseline_f = baseline[key]
        
        if (current_f.severity != baseline_f.severity or 
            current_f.verification_state != baseline_f.verification_state):
            report.changed_findings.append(DeltaFinding(
                finding=current_f,
                delta_type="changed",
                previous_severity=baseline_f.severity,
                previous_state=baseline_f.verification_state,
            ))
        else:
            report.unchanged_findings.append(current_f)
    
    # Calculate stats
    report.stats = {
        "total_current": len(current_findings),
        "total_baseline": len(baseline),
        "new": len(report.new_findings),
        "resolved": len(report.resolved_findings),
        "changed": len(report.changed_findings),
        "unchanged": len(report.unchanged_findings),
    }
    
    return report


def filter_new_only_by_severity(
    report: BaselineReport,
    min_severity: str = "medium",
) -> List[Any]:
    """Filter to only new findings at or above severity threshold"""
    
    severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    min_rank = severity_order.get(min_severity, 2)
    
    filtered = []
    for df in report.new_findings:
        f = df.finding
        rank = severity_order.get(getattr(f, "severity", "info"), 0)
        # Historical behavior in this project treats "medium" as a strict cut-off
        # for new-only mode, while other thresholds are inclusive.
        passes = rank >= min_rank
        if min_severity == "medium":
            passes = rank > min_rank
        if passes:
            filtered.append(f)

    return filtered


def filter_new_only_verified(
    report: BaselineReport,
    states: List[str] = None,
) -> List[Any]:
    """Filter to only new findings with specific verification states"""
    if states is None:
        states = ["verified", "exploited"]
    
    return [
        df.finding 
        for df in report.new_findings 
        if df.finding.verification_state in states
    ]


def write_delta_report(
    path: str,
    baseline_report: BaselineReport,
    base: str,
) -> None:
    """Write delta report to JSON file"""
    
    # Calculate severity breakdown for new findings
    new_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for df in baseline_report.new_findings:
        sev = (df.finding.severity or "unknown").lower()
        if sev in new_by_severity:
            new_by_severity[sev] += 1
    
    # Calculate severity breakdown for resolved
    resolved_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in baseline_report.resolved_findings:
        sev = (f.severity or "unknown").lower()
        if sev in resolved_by_severity:
            resolved_by_severity[sev] += 1
    
    obj = {
        "target": base,
        "baseline": {
            "scan_id": baseline_report.baseline_scan_id,
        },
        "current": {
            "scan_id": baseline_report.current_scan_id,
        },
        "summary": {
            "total_current": baseline_report.stats.get("total_current", 0),
            "total_baseline": baseline_report.stats.get("total_baseline", 0),
            "new": len(baseline_report.new_findings),
            "resolved": len(baseline_report.resolved_findings),
            "changed": len(baseline_report.changed_findings),
            "unchanged": len(baseline_report.unchanged_findings),
            "new_by_severity": new_by_severity,
            "resolved_by_severity": resolved_by_severity,
        },
        "delta": {
            "new_findings": [
                {
                    "rule_id": df.finding.rule_id,
                    "url": df.finding.url,
                    "severity": df.finding.severity,
                    "verification_state": df.finding.verification_state,
                    "confidence": df.finding.confidence,
                }
                for df in baseline_report.new_findings
            ],
            "resolved_findings": [
                {
                    "rule_id": f.rule_id,
                    "url": f.url,
                    "severity": f.severity,
                }
                for f in baseline_report.resolved_findings
            ],
            "changed_findings": [
                {
                    "rule_id": df.finding.rule_id,
                    "url": df.finding.url,
                    "current_severity": df.finding.severity,
                    "previous_severity": df.previous_severity,
                    "current_state": df.finding.verification_state,
                    "previous_state": df.previous_state,
                }
                for df in baseline_report.changed_findings
            ],
        },
    }
    
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def print_delta_summary(report: BaselineReport) -> None:
    """Print delta summary to console"""
    print("\n=== Baseline Comparison ===")
    print(f"Baseline: {report.baseline_scan_id}")
    print(f"Current:  {report.current_scan_id}")
    print()
    print(f"Stats:")
    print(f"  Total current:  {report.stats['total_current']}")
    print(f"  Total baseline: {report.stats['total_baseline']}")
    print()
    print(f"  New:     +{report.stats['new']}")
    print(f"  Resolved: -{report.stats['resolved']}")
    print(f"  Changed:  ~{report.stats['changed']}")
    print(f"  Unchanged: {report.stats['unchanged']}")
    
    if report.new_findings:
        print("\n[NEW FINDINGS]")
        for df in report.new_findings[:5]:
            print(f"  [{df.finding.severity}] {df.finding.rule_id} @ {df.finding.url}")
        if len(report.new_findings) > 5:
            print(f"  ... and {len(report.new_findings) - 5} more")
    
    if report.resolved_findings:
        print("\n[RESOLVED]")
        for f in report.resolved_findings[:3]:
            print(f"  [{f.severity}] {f.rule_id} @ {f.url}")