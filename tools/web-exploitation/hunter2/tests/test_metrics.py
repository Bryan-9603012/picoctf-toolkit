# tests/test_metrics.py
"""
Tests for Metrics and Benchmarking

Tests:
- Scan metrics computation
- Baseline metrics computation
- Verification rate
- Correlation uplift
- Exploitability distribution
"""

import pytest
from core.models import Finding, ChainStep
from postprocess.metrics import (
    compute_scan_metrics,
    compute_baseline_metrics,
    compute_verification_rate,
    compute_correlation_uplift,
    compute_exploitability_distribution,
    generate_metrics_report,
)


class TestScanMetrics:
    """Test scan metrics computation"""
    
    def test_basic_metrics(self):
        """Test basic metrics computation"""
        findings = [
            Finding(id="1", rule_id="a", url="http://a.com", severity="critical"),
            Finding(id="2", rule_id="b", url="http://b.com", severity="high"),
            Finding(id="3", rule_id="c", url="http://c.com", severity="medium"),
        ]
        
        metrics = compute_scan_metrics(findings, "scan-001", "http://target.com")
        
        assert metrics.scan_id == "scan-001"
        assert metrics.target == "http://target.com"
        assert metrics.total_findings == 3
        assert metrics.severity_breakdown["critical"] == 1
        assert metrics.severity_breakdown["high"] == 1
    
    def test_verification_breakdown(self):
        """Test verification state breakdown"""
        findings = [
            Finding(id="1", rule_id="a", url="http://a.com", severity="high"),
            Finding(id="2", rule_id="b", url="http://b.com", severity="high"),
        ]
        findings[0].verification_state = "observed"
        findings[1].verification_state = "verified"
        
        metrics = compute_scan_metrics(findings, "scan-001", "http://target.com")
        
        assert metrics.verification_breakdown["observed"] == 1
        assert metrics.verification_breakdown["verified"] == 1
    
    def test_correlation_chains_counted(self):
        """Test correlation chains are counted"""
        findings = [
            Finding(id="1", rule_id="a", url="http://a.com", severity="high"),
            Finding(id="2", rule_id="b", url="http://b.com", severity="high"),
        ]
        findings[0].chain = [
            ChainStep(finding_id="1", rule_id="step1", url="http://a.com", action="access", result="success"),
        ]
        
        metrics = compute_scan_metrics(findings, "scan-001", "http://target.com")
        
        assert metrics.correlation_chains_found == 1


class TestBaselineMetrics:
    """Test baseline metrics computation"""
    
    def test_new_findings_detected(self):
        """Test new findings are detected"""
        baseline = [
            Finding(id="1", rule_id="a", url="http://a.com", severity="high"),
        ]
        current = [
            Finding(id="1", rule_id="a", url="http://a.com", severity="high"),
            Finding(id="2", rule_id="b", url="http://b.com", severity="critical"),
        ]
        
        metrics = compute_baseline_metrics(baseline, current, "baseline", "current")
        
        assert metrics.new_findings == 1
        assert metrics.resolved_findings == 0
    
    def test_resolved_findings_detected(self):
        """Test resolved findings are detected"""
        baseline = [
            Finding(id="1", rule_id="a", url="http://a.com", severity="high"),
            Finding(id="2", rule_id="b", url="http://b.com", severity="medium"),
        ]
        current = [
            Finding(id="1", rule_id="a", url="http://a.com", severity="high"),
        ]
        
        metrics = compute_baseline_metrics(baseline, current, "baseline", "current")
        
        assert metrics.new_findings == 0
        assert metrics.resolved_findings == 1
    
    def test_severity_change_detected(self):
        """Test severity changes are detected"""
        baseline = [
            Finding(id="1", rule_id="a", url="http://a.com", severity="high"),
        ]
        current = [
            Finding(id="1", rule_id="a", url="http://a.com", severity="critical"),
        ]
        
        metrics = compute_baseline_metrics(baseline, current, "baseline", "current")
        
        assert metrics.changed_severity == 1
    
    def test_delta_rate_calculation(self):
        """Test delta rate is calculated"""
        baseline = [
            Finding(id="1", rule_id="a", url="http://a.com", severity="high"),
        ]
        current = [
            Finding(id="1", rule_id="a", url="http://a.com", severity="high"),
            Finding(id="2", rule_id="b", url="http://b.com", severity="medium"),
        ]
        
        metrics = compute_baseline_metrics(baseline, current, "baseline", "current")
        
        assert metrics.delta_rate > 0


class TestComputedMetrics:
    """Test computed metrics functions"""
    
    def test_verification_rate(self):
        """Test verification rate calculation"""
        findings = [
            Finding(id="1", rule_id="a", url="http://a.com", severity="high"),
            Finding(id="2", rule_id="b", url="http://b.com", severity="medium"),
        ]
        findings[0].verification_state = "verified"
        findings[1].verification_state = "observed"
        
        rate = compute_verification_rate(findings)
        
        assert rate == 50.0
    
    def test_correlation_uplift(self):
        """Test correlation uplift calculation"""
        findings = [
            Finding(id="1", rule_id="a", url="http://a.com", severity="high"),
            Finding(id="2", rule_id="b", url="http://b.com", severity="medium"),
        ]
        findings[0].chain = [ChainStep(finding_id="1", rule_id="step1", url="http://a.com", action="access", result="success")]
        
        uplift = compute_correlation_uplift(findings)
        
        assert uplift == 50.0
    
    def test_exploitability_distribution(self):
        """Test exploitability distribution"""
        findings = [
            Finding(id="1", rule_id="a", url="http://a.com", severity="critical"),
            Finding(id="2", rule_id="b", url="http://b.com", severity="high"),
        ]
        findings[0].exploitability = "critical"
        findings[1].exploitability = "high"
        
        dist = compute_exploitability_distribution(findings)
        
        assert dist["critical"] == 50.0
        assert dist["high"] == 50.0


class TestGenerateMetricsReport:
    """Test comprehensive metrics report"""
    
    def test_report_structure(self):
        """Test report has required sections"""
        findings = [
            Finding(id="1", rule_id="a", url="http://a.com", severity="high"),
        ]
        
        report = generate_metrics_report(findings, "scan-001", "http://target.com")
        
        assert "scan_metrics" in report
        assert "computed_metrics" in report
    
    def test_report_with_baseline(self):
        """Test report with baseline"""
        baseline = [
            Finding(id="1", rule_id="a", url="http://a.com", severity="high"),
        ]
        current = [
            Finding(id="1", rule_id="a", url="http://a.com", severity="high"),
            Finding(id="2", rule_id="b", url="http://b.com", severity="critical"),
        ]
        
        report = generate_metrics_report(
            current, "scan-002", "http://target.com",
            baseline, "scan-001"
        )
        
        assert "baseline_metrics" in report
        assert report["baseline_metrics"]["new_findings"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])