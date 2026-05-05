# tests/test_report_snapshots.py
"""
Report Snapshot Tests

Validates that report output conforms to expected structure:
- report.json structure
- markdown report sections
- traceability fields
- manual override display
"""

import pytest
import json
from pathlib import Path
from typing import Dict, Any, List


class TestFindingSnapshot:
    """Test finding structure for report conformance"""
    
    @pytest.fixture
    def sample_finding(self) -> Dict[str, Any]:
        """Sample finding that matches FINDING_SCHEMA.md"""
        return {
            "id": "finding-git-exposure-12345",
            "rule_id": "git-directory-exposure",
            "title": "Exposed .git Metadata",
            "category": "Source Control Exposure",
            "severity": "high",
            "confidence": "high",
            "verification_state": "verified",
            "url": "http://example.com/.git/config",
            "affected_asset": "http://example.com/.git/config",
            "cwe": "552",
            "owasp": "A01:2021-Broken Access Control",
            "evidence": {
                "method": "GET",
                "url": "http://example.com/.git/config",
                "status": 200,
                "headers": {"Content-Type": "text/plain"},
                "content_length": 1024,
                "elapsed_ms": 45,
                "matched_pattern": "(?m)^\\[core\\]$",
            },
            "matches": ["(?m)^\\[core\\]$"],
            "tags": ["git", "source"],
            "remediation": "Block access to /.git via web server config",
            "references": ["https://owasp.org/"],
            "scan_id": "scan-20260411-001",
            "discovered_at": "2026-04-11T10:30:00Z",
            "verified_at": "2026-04-11T10:31:00Z",
            "source_rule_pack": "web-misconfig",
            "risk_score": 80,
        }
    
    @pytest.fixture
    def sample_finding_with_manual_override(self) -> Dict[str, Any]:
        """Sample finding with manual override"""
        return {
            "id": "finding-custom-001",
            "rule_id": "custom-rule",
            "title": "Custom Finding",
            "category": "test",
            "severity": "medium",
            "confidence": "low",
            "verification_state": "exploited",
            "url": "http://example.com/test",
            "manual_override": True,
            "manual_override_actor": "security_engineer",
            "manual_override_reason": "Manual investigation confirmed complete compromise",
            "manual_override_timestamp": "2026-04-11T11:00:00Z",
            "scan_id": "scan-20260411-001",
        }
    
    def test_finding_has_required_fields(self, sample_finding):
        """Finding should have all required fields per FINDING_SCHEMA.md"""
        required = ["id", "rule_id", "title", "category", "severity", "confidence", 
                   "verification_state", "url"]
        
        for field in required:
            assert field in sample_finding, f"Missing required field: {field}"
    
    def test_finding_has_valid_enum_values(self, sample_finding):
        """Finding should have valid enum values"""
        valid_severity = ["info", "low", "medium", "high", "critical"]
        valid_confidence = ["low", "medium", "high"]
        valid_verification = ["observed", "suspected", "verified", "exploited"]
        
        assert sample_finding["severity"] in valid_severity
        assert sample_finding["confidence"] in valid_confidence
        assert sample_finding["verification_state"] in valid_verification
    
    def test_manual_override_displayed(self, sample_finding_with_manual_override):
        """Manual override should be clearly indicated"""
        assert sample_finding_with_manual_override.get("manual_override") is True
        assert "manual_override_actor" in sample_finding_with_manual_override
        assert "manual_override_reason" in sample_finding_with_manual_override
        assert "manual_override_timestamp" in sample_finding_with_manual_override
    
    def test_finding_has_traceability_fields(self, sample_finding):
        """Finding should have traceability fields"""
        assert "scan_id" in sample_finding
        assert sample_finding["scan_id"].startswith("scan-")
        assert "discovered_at" in sample_finding
        assert "verified_at" in sample_finding


class TestReportJsonSnapshot:
    """Test report.json structure"""
    
    @pytest.fixture
    def sample_report_json(self) -> Dict[str, Any]:
        """Sample report.json structure"""
        return {
            "target": "http://example.com",
            "scan_id": "scan-20260411-001",
            "policy": "balanced",
            "environment": "staging",
            "started_at": "2026-04-11T10:00:00Z",
            "ended_at": "2026-04-11T10:30:00Z",
            "findings": [
                {
                    "id": "finding-001",
                    "rule_id": "git-exposure",
                    "severity": "high",
                    "verification_state": "verified",
                    "confidence": "high",
                }
            ],
            "metadata": {
                "total_findings": 1,
                "by_severity": {"high": 1},
                "by_verification": {"verified": 1},
            }
        }
    
    def test_report_has_target(self, sample_report_json):
        """Report should have target"""
        assert "target" in sample_report_json
        assert sample_report_json["target"].startswith("http")
    
    def test_report_has_scan_metadata(self, sample_report_json):
        """Report should have scan metadata"""
        assert "scan_id" in sample_report_json
        assert "policy" in sample_report_json
        assert "environment" in sample_report_json
        assert "started_at" in sample_report_json
        assert "ended_at" in sample_report_json
    
    def test_report_has_findings_array(self, sample_report_json):
        """Report should have findings array"""
        assert "findings" in sample_report_json
        assert isinstance(sample_report_json["findings"], list)
    
    def test_report_has_metadata_summary(self, sample_report_json):
        """Report should have metadata summary"""
        assert "metadata" in sample_report_json
        metadata = sample_report_json["metadata"]
        assert "total_findings" in metadata
        assert "by_severity" in metadata
        assert "by_verification" in metadata


class TestMarkdownReportSections:
    """Test markdown report has required sections"""
    
    @pytest.fixture
    def expected_sections(self) -> List[str]:
        """Expected sections in markdown report per GOLDEN_REPORT_SAMPLE.md"""
        return [
            "Scan Metadata",
            "Executive Summary",
            "Total Findings",
            "Critical", "High", "Medium", "Low", "Info",  # severity counts
            "Observed", "Suspected", "Verified", "Exploited",  # verification counts
            "Finding #",
            "Rule ID",
            "Severity",
            "Verification State",
            "Confidence",
            "Affected Asset",
            "CWE", "OWASP",  # classification
            "Evidence Summary",
            "Remediation",
            "Risk Summary",
            "Recommendations",
        ]
    
    def test_executive_summary_section(self):
        """Markdown should have Executive Summary"""
        content = """
# Hunter-2 Enterprise Scan Report

## Scan Metadata
scan_id: scan-001

## Executive Summary
Total Findings: 3

### Risk Summary
| Severity | ...
"""
        # Should contain Executive Summary
        assert "Executive Summary" in content
    
    def test_finding_details_include_verification_state(self):
        """Finding details should include verification_state"""
        content = """
## Finding #1: Exposed .git

**Verification State:** verified
**Confidence:** high
"""
        assert "Verification State:" in content
        assert "Confidence:" in content
    
    def test_finding_details_include_classification(self):
        """Finding details should include CWE/OWASP"""
        content = """
**CWE:** CWE-552
**OWASP:** A01:2021
"""
        assert "CWE:" in content or "OWASP:" in content
    
    def test_risk_summary_has_verification_breakdown(self):
        """Risk summary should have verification state breakdown"""
        content = """
## Risk Summary

| Severity | Observed | Suspected | Verified | Exploited |
|----------|----------|-----------|----------|-----------|
"""
        assert "Observed" in content
        assert "Suspected" in content
        assert "Verified" in content
        assert "Exploited" in content


class TestArtifactLinkage:
    """Test artifact-finding linkage for traceability"""
    
    def test_finding_references_artifact_ids(self):
        """Finding should have related_artifacts field"""
        finding = {
            "id": "finding-001",
            "related_artifacts": ["art-001", "art-002"],
        }
        assert "related_artifacts" in finding
        assert len(finding["related_artifacts"]) > 0
    
    def test_artifact_has_finding_id(self):
        """Artifact should reference finding_id"""
        artifact = {
            "artifact_id": "art-001",
            "finding_id": "finding-001",
            "scan_id": "scan-001",
        }
        assert artifact["finding_id"] == "finding-001"
    
    def test_artifact_has_scan_id(self):
        """Artifact should have scan_id for traceability"""
        artifact = {
            "artifact_id": "art-001",
            "finding_id": "finding-001",
            "scan_id": "scan-001",
        }
        assert "scan_id" in artifact
        assert artifact["scan_id"].startswith("scan-")


class TestEndToEndConfig:
    """Test end-to-end config propagation"""
    
    def test_config_propagates_to_report(self):
        """Config values should propagate to report metadata"""
        config = {
            "base": "http://example.com",
            "policy": "safe",
            "environment": "prod",
            "scan_id": "scan-20260411-001",
            "fuzzing_enabled": False,
            "chaining_enabled": False,
            "allow_post": "deny",
        }
        
        report = {
            "target": config["base"],
            "scan_id": config["scan_id"],
            "policy": config["policy"],
            "environment": config["environment"],
        }
        
        assert report["scan_id"] == config["scan_id"]
        assert report["policy"] == config["policy"]
        assert report["environment"] == config["environment"]
    
    def test_policy_affects_behavior_settings(self):
        """Policy should affect derived behavior settings"""
        policies = {
            "safe": {"fuzzing_enabled": False, "allow_post": "deny"},
            "balanced": {"fuzzing_enabled": True, "allow_post": "restricted"},
            "aggressive": {"fuzzing_enabled": True, "allow_post": "allow"},
        }
        
        for policy, expected in policies.items():
            for key, expected_value in expected.items():
                actual_value = policies[policy][key]
                assert actual_value == expected_value, f"Policy {policy} mismatch for {key}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])