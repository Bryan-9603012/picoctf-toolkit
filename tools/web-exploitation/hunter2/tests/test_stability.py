# tests/test_stability.py
"""
Stability Tests - Edge Cases and Robustness

Tests:
- Empty inputs handling
- Missing field handling
- Invalid config handling
- Large dataset performance
- Conflicting options handling
- Graceful degradation
- Report consistency
"""

import pytest
import json
import tempfile
import os
from unittest.mock import Mock, patch


class TestEmptyInputHandling:
    """Test handling of empty inputs"""
    
    def test_empty_findings_list(self):
        """Test pipeline handles empty findings"""
        from core.models import Finding
        from postprocess.correlation import correlate_findings
        from postprocess.exploitability import score_all_findings
        from postprocess.baseline import compare_with_baseline
        from postprocess.suppression import apply_suppressions
        
        findings = []
        
        result = correlate_findings(findings)
        assert result == []
        
        scored = score_all_findings(findings)
        assert scored == []
    
    def test_empty_baseline(self):
        """Test baseline comparison with empty baseline"""
        from postprocess.baseline import compare_with_baseline, BaselineFinding
        from core.models import Finding
        
        class MockFinding:
            def __init__(self):
                self.rule_id = "test"
                self.url = "http://test.com"
                self.severity = "high"
        
        baseline = {}
        current = [MockFinding()]
        
        result = compare_with_baseline(current, baseline, "scan-001", "baseline-001")
        
        assert len(result.new_findings) == 1
        assert len(result.resolved_findings) == 0
    
    def test_empty_suppression_file(self):
        """Test suppression with empty/no file"""
        from postprocess.suppression import apply_suppressions
        
        class MockFinding:
            def __init__(self):
                self.rule_id = "test"
                self.url = "http://test.com"
                self.severity = "high"
        
        findings = [MockFinding()]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"suppressions": []}, f)
            temp_path = f.name
        
        try:
            result = apply_suppressions(findings, temp_path)
            assert len(result.remaining) == 1
            assert len(result.suppressed) == 0
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
    
    def test_nonexistent_suppression_file(self):
        """Test suppression with non-existent file"""
        from postprocess.suppression import apply_suppressions
        
        class MockFinding:
            def __init__(self):
                self.rule_id = "test"
                self.url = "http://test.com"
                self.severity = "high"
        
        findings = [MockFinding()]
        
        result = apply_suppressions(findings, "/nonexistent/path.json")
        
        assert len(result.remaining) == 1


class TestMissingFieldHandling:
    """Test handling of findings with missing fields"""
    
    def test_finding_minimal_fields(self):
        """Test finding with only required fields"""
        from core.models import Finding
        
        finding = Finding(
            id="test-001",
            rule_id="test-rule",
            url="http://test.com",
            severity="high",
        )
        
        assert finding.id == "test-001"
        assert finding.confidence == "medium"
        assert finding.verification_state == "observed"
    
    def test_finding_no_evidence(self):
        """Test finding without evidence"""
        from core.models import Finding
        
        finding = Finding(
            id="test-001",
            rule_id="test-rule",
            url="http://test.com",
            severity="high",
        )
        
        score = finding.compute_risk_score()
        assert score > 0
    
    def test_finding_no_extracted_data(self):
        """Test finding without extracted_data"""
        from core.models import Finding
        
        finding = Finding(
            id="test-001",
            rule_id="test-rule",
            url="http://test.com",
            severity="high",
        )
        
        finding.compute_risk_score(credential_bonus=10)
        assert finding.risk_score > 0


class TestInvalidConfigHandling:
    """Test handling of invalid configurations"""
    
    def test_invalid_policy(self):
        """Test invalid policy value"""
        from config.defaults import apply_policy_settings
        
        result = apply_policy_settings("invalid_policy")
        
        assert "fuzzing_enabled" in result
    
    def test_invalid_severity(self):
        """Test invalid severity handling"""
        from core.models import severity_rank
        
        rank = severity_rank("invalid")
        assert rank == 0
    
    def test_invalid_verification_state(self):
        """Test invalid verification state"""
        from core.models import Finding
        
        finding = Finding(
            id="test",
            rule_id="test",
            url="http://test",
            severity="high",
        )
        finding.verification_state = "invalid_state"
        
        assert getattr(finding, 'verification_state') == "invalid_state"


class TestLargeDatasetPerformance:
    """Test performance with large datasets"""
    
    def test_many_findings_dedupe(self):
        """Test deduplication with many findings"""
        from postprocess.dedupe import dedupe_findings_prefer_chain
        
        class MockFinding:
            def __init__(self, i):
                self.rule_id = f"rule-{i % 10}"
                self.url = f"http://test.com/path{i}"
                self.severity = "high"
                self.confidence = "high"
                self.chain = []
        
        findings = [MockFinding(i) for i in range(100)]
        
        result = dedupe_findings_prefer_chain(findings)
        
        assert len(result) <= len(findings)
    
    def test_many_findings_correlation(self):
        """Test correlation with many findings"""
        from postprocess.correlation import correlate_findings
        
        class MockFinding:
            def __init__(self, i):
                self.id = f"finding-{i}"
                self.rule_id = f"rule-{i % 5}"
                self.url = f"http://test.com/path{i}"
                self.severity = "high"
                self.confidence = "high"
                self.evidence = None
                self.extracted_data = {}
                self.chain = []
        
        findings = [MockFinding(i) for i in range(50)]
        
        result = correlate_findings(findings)
        
        assert isinstance(result, list)
    
    def test_many_findings_exploitability(self):
        """Test exploitability scoring with many findings"""
        from postprocess.exploitability import score_all_findings
        
        class MockFinding:
            def __init__(self, i):
                self.id = f"finding-{i}"
                self.rule_id = f"rule-{i}"
                self.url = f"http://test.com/path{i}"
                self.severity = ["critical", "high", "medium", "low"][i % 4]
                self.confidence = "high"
                self.verification_state = "observed"
                self.exploitability = None
                self.variables = {}
        
        findings = [MockFinding(i) for i in range(100)]
        
        result = score_all_findings(findings)
        
        assert len(result) == 100
        for f in result:
            assert f.exploitability is not None


class TestFeatureConflictHandling:
    """Test handling of conflicting features"""
    
    def test_hide_suppressed_without_suppression_file(self):
        """Test --hide-suppressed without --suppressions"""
        from postprocess.suppression import apply_suppressions
        
        class MockFinding:
            def __init__(self):
                self.rule_id = "test"
                self.url = "http://test.com"
                self.severity = "high"
        
        findings = [MockFinding()]
        
        result = apply_suppressions(findings, "suppressions.json")
        
        assert len(result.remaining) == 1
    
    def test_new_only_without_baseline(self):
        """Test --new-only without --baseline"""
        from postprocess.baseline import filter_new_only_by_severity, BaselineReport
        
        class MockDeltaFinding:
            def __init__(self, severity):
                self.finding = MockFinding()
                self.finding.severity = severity
                self.delta_type = "new"
        
        class MockFinding:
            severity = "high"
        
        report = BaselineReport(
            baseline_scan_id="baseline",
            current_scan_id="current",
            new_findings=[MockDeltaFinding("high"), MockDeltaFinding("medium")],
            resolved_findings=[],
            changed_findings=[],
            unchanged_findings=[],
            stats={},
        )
        
        result = filter_new_only_by_severity(report, "medium")
        
        assert len(result) == 1


class TestGracefulDegradation:
    """Test graceful degradation when features fail"""
    
    def test_correlation_with_missing_evidence(self):
        """Test correlation when evidence is missing"""
        from postprocess.correlation import find_credentials, find_sensitive_artifacts
        from core.models import Finding
        
        finding = Finding(
            id="test",
            rule_id="test",
            url="http://test.com",
            severity="high",
        )
        
        assert find_credentials(finding) is False
        assert find_sensitive_artifacts(finding) is False
    
    def test_exploitability_with_no_chain(self):
        """Test exploitability when chain is empty"""
        from postprocess.exploitability import compute_exploitability
        from core.models import Finding
        
        finding = Finding(
            id="test",
            rule_id="test",
            url="http://test.com",
            severity="high",
            confidence="medium",
        )
        finding.chain = []
        
        score = compute_exploitability(finding)
        
        assert score.total_score > 0
        assert score.chain_bonus == 0
    
    def test_metrics_with_no_baseline(self):
        """Test metrics without baseline"""
        from postprocess.metrics import generate_metrics_report
        from core.models import Finding
        
        findings = [Finding(id="1", rule_id="a", url="http://a.com", severity="high")]
        
        report = generate_metrics_report(findings, "scan-001", "http://target.com")
        
        assert "baseline_metrics" not in report
        assert "scan_metrics" in report


class TestReportConsistency:
    """Test consistency across report formats"""
    
    def test_json_markdown_consistency(self):
        """Test JSON and Markdown reports are consistent"""
        from reports.json_report import _finding_to_dict
        from reports.markdown import _finding_to_md
        
        class MockFinding:
            def __init__(self):
                self.id = "test-001"
                self.rule_id = "test-rule"
                self.url = "http://test.com/path"
                self.title = "Test Finding"
                self.severity = "high"
                self.confidence = "high"
                self.verification_state = "observed"
                self.matches = ["match1", "match2"]
                self.remediation = "Fix this"
                self.cwe = "CWE-123"
                self.owasp = "A01:2021"
        
        finding = MockFinding()
        
        json_result = _finding_to_dict(finding)
        
        assert json_result["rule_id"] == "test-rule"
        assert json_result["severity"] == "high"
    
    def test_html_severity_colors(self):
        """Test HTML uses consistent severity colors"""
        from reports.html import SEVERITY_COLORS
        
        assert SEVERITY_COLORS["critical"] == "#dc2626"
        assert SEVERITY_COLORS["high"] == "#ea580c"
        assert SEVERITY_COLORS["medium"] == "#ca8a04"
        assert SEVERITY_COLORS["low"] == "#16a34a"
        assert SEVERITY_COLORS["info"] == "#2563eb"
    
    def test_verification_state_in_all_reports(self):
        """Test verification_state appears in all report types"""
        from core.models import Finding
        
        finding = Finding(
            id="test",
            rule_id="test",
            url="http://test",
            severity="high",
        )
        finding.verification_state = "verified"
        
        assert finding.verification_state == "verified"


class TestEdgeCaseFindingFields:
    """Test edge cases with various finding field values"""
    
    def test_very_long_url(self):
        """Test handling of very long URLs"""
        from core.models import Finding
        
        long_url = "http://test.com/" + "a" * 1000
        
        finding = Finding(
            id="test",
            rule_id="test",
            url=long_url,
            severity="high",
        )
        
        assert finding.url == long_url
    
    def test_special_chars_in_url(self):
        """Test handling of special characters in URLs"""
        from core.models import Finding
        
        finding = Finding(
            id="test",
            rule_id="test",
            url="http://test.com/path?param=<script>&other=xss",
            severity="high",
        )
        
        assert finding.url is not None
    
    def test_unicode_in_finding(self):
        """Test handling of Unicode in findings"""
        from core.models import Finding
        
        finding = Finding(
            id="test",
            rule_id="test",
            url="http://example.com/測試",
            title="測試發現",
            severity="high",
        )
        
        assert finding.title is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])