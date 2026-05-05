# postprocess/risk.py
from __future__ import annotations

from typing import List
from core.models import Finding
from postprocess.correlation import correlate_findings, compute_enhanced_risk


def score_findings(findings: List[Finding]) -> None:
    for f in findings:
        compute_enhanced_risk(f)
    
    correlate_findings(findings)
    
    findings.sort(key=lambda x: x.risk_score, reverse=True)
