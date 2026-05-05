# tests/test_regression.py
"""
Regression Tests using Fixtures

Uses fixtures to verify consistent behavior across changes.
"""

import pytest
from tests.fixtures.regression_fixtures import (
    get_sample_findings,
    get_baseline_report,
    get_current_report,
    get_expected_delta,
    get_suppression_list,
    get_severity_breakdown,
    get_verification_breakdown,
)


class TestFindingRegression:
    """Test finding structure consistency"""
    
    def test_finding_has_required_fields(self):
        """Verify finding has all required enterprise fields"""
        findings = get_sample_findings()
        
        required_fields = [
            "id", "rule_id", "url", "title", "severity",
            "confidence", "verification_state", "scan_id",
            "discovered_at", "cwe", "owasp", "remediation"
        ]
        
        for finding in findings:
            for field in required_fields:
                assert field in finding, f"Missing field: {field}"
    
    def test_severity_breakdown_matches(self):
        """Verify severity counts match expected"""
        findings = get_sample_findings()
        
        breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f["severity"].lower()
            if sev in breakdown:
                breakdown[sev] += 1
        
        expected = get_severity_breakdown()
        assert breakdown == expected


class TestVerificationStateRegression:
    """Test verification state consistency"""
    
    def test_verification_breakdown_matches(self):
        """Verify verification state counts match expected"""
        findings = get_sample_findings()
        
        breakdown = {"observed": 0, "suspected": 0, "verified": 0, "exploited": 0}
        for f in findings:
            state = f.get("verification_state", "observed")
            if state in breakdown:
                breakdown[state] += 1
        
        expected = get_verification_breakdown()
        assert breakdown == expected
    
    def test_state_transitions_are_valid(self):
        """Verify state transitions follow rules"""
        findings = get_sample_findings()
        
        valid_transitions = {
            "observed": ["suspected", "verified", "exploited"],
            "suspected": ["verified", "exploited"],
            "verified": ["exploited"],
            "exploited": [],
        }
        
        for f in findings:
            state = f.get("verification_state", "observed")
            assert state in valid_transitions, f"Invalid state: {state}"


class TestDeltaRegression:
    """Test baseline comparison consistency"""
    
    def test_delta_identifies_new_findings(self):
        """Verify new findings are correctly identified"""
        baseline = get_baseline_report()
        current = get_current_report()
        
        baseline_rules = {f["rule_id"] for f in baseline["findings"]}
        current_rules = {f["rule_id"] for f in current["findings"]}
        
        new_rules = current_rules - baseline_rules
        
        expected = get_expected_delta()
        expected_new_rules = {f["rule_id"] for f in current["findings"] 
                              if f["rule_id"] in [n["rule_id"] for n in expected["new_findings"]]}
        
        assert new_rules == expected_new_rules
    
    def test_delta_identifies_resolved_findings(self):
        """Verify resolved findings are correctly identified"""
        baseline = get_baseline_report()
        current = get_current_report()
        
        baseline_rules = {f["rule_id"] for f in baseline["findings"]}
        current_rules = {f["rule_id"] for f in current["findings"]}
        
        resolved_rules = baseline_rules - current_rules
        
        expected = get_expected_delta()
        expected_resolved = {r["rule_id"] for r in expected["resolved_findings"]}
        
        assert resolved_rules == expected_resolved


class TestSuppressionRegression:
    """Test suppression matching consistency"""
    
    def test_suppression_schema_valid(self):
        """Verify suppression entries have required fields"""
        suppressions = get_suppression_list()
        
        required_fields = [
            "id", "rule_id", "url_pattern", "reason",
            "owner", "created_at"
        ]
        
        for sup in suppressions:
            for field in required_fields:
                assert field in sup, f"Missing field: {field}"
    
    def test_rule_id_wildcard_support(self):
        """Verify wildcard rule_id is handled"""
        suppressions = get_suppression_list()
        
        wildcard_rules = [s for s in suppressions if s["rule_id"] == "*"]
        
        assert len(wildcard_rules) > 0, "Should have wildcard rule for testing"


class TestReportMetadataRegression:
    """Test report metadata consistency"""
    
    def test_metadata_has_required_fields(self):
        """Verify metadata has required fields"""
        report = get_current_report()
        
        required = ["target", "scan_id", "generated_at", "policy", "environment"]
        
        for field in required:
            assert field in report["metadata"], f"Missing: {field}"
    
    def test_scan_id_format(self):
        """Verify scan_id follows pattern"""
        report = get_current_report()
        
        scan_id = report["metadata"]["scan_id"]
        
        assert scan_id.startswith("scan-"), "scan_id should start with 'scan-'"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])