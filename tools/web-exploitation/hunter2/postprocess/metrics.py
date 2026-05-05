# postprocess/metrics.py
"""
Metrics and Benchmarking Module

Tracks and computes:
- False positive rate
- Verification rate
- Delta usefulness
- Correlation uplift
- Exploitability ranking effectiveness
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
from core.models import Finding


@dataclass
class ScanMetrics:
    """Metrics for a single scan"""
    scan_id: str
    timestamp: str
    target: str
    
    total_findings: int = 0
    severity_breakdown: Dict[str, int] = field(default_factory=dict)
    verification_breakdown: Dict[str, int] = field(default_factory=dict)
    
    verified_count: int = 0
    exploited_count: int = 0
    
    fp_likely_count: int = 0
    
    correlation_chains_found: int = 0
    
    exploitability_summary: Dict[str, int] = field(default_factory=dict)
    
    avg_exploitability_score: float = 0.0


@dataclass
class BaselineMetrics:
    """Metrics comparison between scans"""
    baseline_scan_id: str
    current_scan_id: str
    
    new_findings: int = 0
    resolved_findings: int = 0
    changed_severity: int = 0
    
    delta_rate: float = 0.0
    
    useful_delta: bool = False


def compute_scan_metrics(
    findings: List[Finding],
    scan_id: str,
    target: str,
) -> ScanMetrics:
    """Compute metrics for a scan"""
    metrics = ScanMetrics(
        scan_id=scan_id,
        timestamp=datetime.utcnow().isoformat(),
        target=target,
        total_findings=len(findings),
    )
    
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    verification_counts = {"observed": 0, "suspected": 0, "verified": 0, "exploited": 0}
    exploitability_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    
    total_exploit_score = 0
    
    for f in findings:
        sev = (f.severity or "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        
        state = getattr(f, 'verification_state', 'observed') or 'observed'
        if state in verification_counts:
            verification_counts[state] += 1
        
        if state in ['verified', 'exploited']:
            metrics.verified_count += 1
        if state == 'exploited':
            metrics.exploited_count += 1
        
        exploit_rating = f.exploitability or "info"
        if exploit_rating in exploitability_counts:
            exploitability_counts[exploit_rating] += 1
        
        if hasattr(f, 'variables') and f.variables:
            score_data = f.variables.get('exploitability_score', {})
            total_exploit_score += score_data.get('total_score', 0)
        
        if f.chain:
            metrics.correlation_chains_found += 1
    
    metrics.severity_breakdown = severity_counts
    metrics.verification_breakdown = verification_counts
    metrics.exploitability_summary = exploitability_counts
    
    if findings:
        metrics.avg_exploitability_score = round(total_exploit_score / len(findings), 2)
    
    return metrics


def compute_baseline_metrics(
    baseline_findings: List[Finding],
    current_findings: List[Finding],
    baseline_scan_id: str,
    current_scan_id: str,
) -> BaselineMetrics:
    """Compute delta metrics between baseline and current"""
    baseline_keys = {f"{f.rule_id}::{f.url}" for f in baseline_findings}
    current_keys = {f"{f.rule_id}::{f.url}" for f in current_findings}
    
    new_keys = current_keys - baseline_keys
    resolved_keys = baseline_keys - current_keys
    
    changed_count = 0
    for f in current_findings:
        key = f"{f.rule_id}::{f.url}"
        if key in baseline_keys:
            baseline_f = next((bf for bf in baseline_findings if f"{bf.rule_id}::{bf.url}" == key), None)
            if baseline_f and baseline_f.severity != f.severity:
                changed_count += 1
    
    metrics = BaselineMetrics(
        baseline_scan_id=baseline_scan_id,
        current_scan_id=current_scan_id,
        new_findings=len(new_keys),
        resolved_findings=len(resolved_keys),
        changed_severity=changed_count,
    )
    
    total_findings = len(current_findings)
    if total_findings > 0:
        metrics.delta_rate = round((len(new_keys) + len(resolved_keys)) / total_findings, 2)
    
    metrics.useful_delta = (
        metrics.new_findings > 0 or
        metrics.resolved_findings > 0 or
        metrics.changed_severity > 0
    )
    
    return metrics


def compute_verification_rate(findings: List[Finding]) -> float:
    """Compute verification rate"""
    if not findings:
        return 0.0
    
    verified_states = ['suspected', 'verified', 'exploited']
    verified_count = sum(
        1 for f in findings
        if getattr(f, 'verification_state', 'observed') in verified_states
    )
    
    return round(verified_count / len(findings) * 100, 2)


def compute_correlation_uplift(findings: List[Finding]) -> float:
    """Compute correlation uplift - how many findings are in chains"""
    if not findings:
        return 0.0
    
    chained_count = sum(1 for f in findings if f.chain)
    
    return round(chained_count / len(findings) * 100, 2)


def compute_exploitability_distribution(findings: List[Finding]) -> Dict[str, float]:
    """Compute exploitability distribution percentages"""
    if not findings:
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    
    for f in findings:
        rating = f.exploitability or "info"
        if rating in counts:
            counts[rating] += 1
    
    total = len(findings)
    return {k: round(v / total * 100, 2) for k, v in counts.items()}


def generate_metrics_report(
    findings: List[Finding],
    scan_id: str,
    target: str,
    baseline_findings: List[Finding] = None,
    baseline_scan_id: str = None,
) -> Dict[str, Any]:
    """Generate comprehensive metrics report"""
    
    scan_metrics = compute_scan_metrics(findings, scan_id, target)
    
    verification_rate = compute_verification_rate(findings)
    correlation_uplift = compute_correlation_uplift(findings)
    exploitability_dist = compute_exploitability_distribution(findings)
    
    report = {
        "scan_metrics": {
            "scan_id": scan_metrics.scan_id,
            "target": scan_metrics.target,
            "timestamp": scan_metrics.timestamp,
            "total_findings": scan_metrics.total_findings,
            "severity_breakdown": scan_metrics.severity_breakdown,
            "verification_breakdown": scan_metrics.verification_breakdown,
            "verified_count": scan_metrics.verified_count,
            "exploited_count": scan_metrics.exploited_count,
            "correlation_chains": scan_metrics.correlation_chains_found,
            "avg_exploitability_score": scan_metrics.avg_exploitability_score,
        },
        "computed_metrics": {
            "verification_rate": verification_rate,
            "correlation_uplift": correlation_uplift,
            "exploitability_distribution": exploitability_dist,
        },
    }
    
    if baseline_findings and baseline_scan_id:
        baseline_metrics = compute_baseline_metrics(
            baseline_findings, findings, baseline_scan_id, scan_id
        )
        report["baseline_metrics"] = {
            "baseline_scan_id": baseline_metrics.baseline_scan_id,
            "new_findings": baseline_metrics.new_findings,
            "resolved_findings": baseline_metrics.resolved_findings,
            "changed_severity": baseline_metrics.changed_severity,
            "delta_rate": baseline_metrics.delta_rate,
            "useful_delta": baseline_metrics.useful_delta,
        }
    
    return report


def print_metrics_summary(report: Dict[str, Any]) -> None:
    """Print human-readable metrics summary"""
    print("\n" + "=" * 50)
    print("Hunter-2 Metrics Summary")
    print("=" * 50)
    
    scan = report.get("scan_metrics", {})
    print(f"\nScan: {scan.get('scan_id', 'N/A')}")
    print(f"Target: {scan.get('target', 'N/A')}")
    print(f"Total Findings: {scan.get('total_findings', 0)}")
    
    print("\n--- Severity Breakdown ---")
    for sev, count in scan.get("severity_breakdown", {}).items():
        print(f"  {sev}: {count}")
    
    print("\n--- Verification Breakdown ---")
    for state, count in scan.get("verification_breakdown", {}).items():
        print(f"  {state}: {count}")
    
    computed = report.get("computed_metrics", {})
    print(f"\nVerification Rate: {computed.get('verification_rate', 0)}%")
    print(f"Correlation Uplift: {computed.get('correlation_uplift', 0)}%")
    
    if "baseline_metrics" in report:
        base = report["baseline_metrics"]
        print("\n--- Delta from Baseline ---")
        print(f"  New: {base.get('new_findings', 0)}")
        print(f"  Resolved: {base.get('resolved_findings', 0)}")
        print(f"  Changed: {base.get('changed_severity', 0)}")
        print(f"  Delta Rate: {base.get('delta_rate', 0)}")
        print(f"  Useful: {base.get('useful_delta', False)}")
    
    print("\n" + "=" * 50)