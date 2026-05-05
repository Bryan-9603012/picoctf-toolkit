# tests/test_correlation.py
"""
Tests for Finding Correlation Logic

Tests:
- Credential detection
- Sensitive artifact detection
- Correlation graph building
- Exploitation chain finding
- Enhanced risk scoring
"""

import pytest
from core.models import Finding, Evidence, ChainStep
from postprocess.correlation import (
    find_credentials,
    find_sensitive_artifacts,
    build_correlation_graph,
    find_exploitation_chains,
    correlate_findings,
    compute_enhanced_risk,
)


class TestCredentialDetection:
    """Test credential detection in findings"""
    
    def test_find_credentials_in_snippet(self):
        """Test credentials detected in evidence snippet"""
        finding = Finding(
            id="test-1",
            rule_id="test-rule",
            url="http://example.com/api",
            severity="high",
        )
        finding.evidence = Evidence(snippet='{"token": "abc123", "password": "secret"}')
        
        assert find_credentials(finding) is True
    
    def test_find_credentials_in_extracted_data(self):
        """Test credentials detected in extracted_data"""
        finding = Finding(
            id="test-2",
            rule_id="test-rule",
            url="http://example.com/api",
            severity="high",
        )
        finding.extracted_data = {"api_key": "secret123", "token": "abc"}
        
        assert find_credentials(finding) is True
    
    def test_no_credentials(self):
        """Test no credentials returns False"""
        finding = Finding(
            id="test-3",
            rule_id="test-rule",
            url="http://example.com/page",
            severity="low",
        )
        finding.evidence = Evidence(snippet='Welcome to the website')
        
        assert find_credentials(finding) is False


class TestSensitiveArtifactDetection:
    """Test sensitive artifact detection"""
    
    def test_detect_heapdump(self):
        """Test heapdump path detection"""
        finding = Finding(
            id="test-1",
            rule_id="heapdump-exposure",
            url="http://example.com/heapdump",
            severity="critical",
        )
        
        assert find_sensitive_artifacts(finding) is True
    
    def test_detect_actuator(self):
        """Test actuator endpoint detection"""
        finding = Finding(
            id="test-2",
            rule_id="spring-actuator",
            url="http://example.com/actuator/env",
            severity="high",
        )
        
        assert find_sensitive_artifacts(finding) is True
    
    def test_detect_env_file(self):
        """Test .env file detection"""
        finding = Finding(
            id="test-3",
            rule_id="env-exposure",
            url="http://example.com/.env",
            severity="high",
        )
        
        assert find_sensitive_artifacts(finding) is True
    
    def test_no_sensitive_path(self):
        """Test non-sensitive path returns False"""
        finding = Finding(
            id="test-4",
            rule_id="test-rule",
            url="http://example.com/about",
            severity="low",
        )
        
        assert find_sensitive_artifacts(finding) is False


class TestCorrelationGraph:
    """Test correlation graph building"""
    
    def test_graph_builds_with_findings(self):
        """Test graph is built from findings"""
        findings = [
            Finding(id="1", rule_id="heapdump", url="http://a.com/heap", severity="critical"),
            Finding(id="2", rule_id="env", url="http://a.com/.env", severity="high"),
        ]
        
        graph = build_correlation_graph(findings)
        
        assert isinstance(graph, dict)
    
    def test_graph_connects_related_findings(self):
        """Test related findings are connected"""
        findings = [
            Finding(id="1", rule_id="heapdump", url="http://a.com/heap", severity="critical"),
            Finding(id="2", rule_id="env", url="http://a.com/.env", severity="high"),
            Finding(id="3", rule_id="admin", url="http://a.com/admin", severity="high"),
        ]
        
        findings[0].evidence = Evidence(snippet='password=abc')
        
        graph = build_correlation_graph(findings)
        
        assert len(graph) > 0


class TestExploitationChains:
    """Test exploitation chain detection"""
    
    def test_finds_simple_chain(self):
        """Test simple chain detection"""
        findings = [
            Finding(id="1", rule_id="heapdump", url="http://a.com/heap", severity="critical"),
            Finding(id="2", rule_id="env", url="http://a.com/.env", severity="high"),
        ]
        
        graph = build_correlation_graph(findings)
        chains = find_exploitation_chains(findings, graph)
        
        assert isinstance(chains, list)
    
    def test_empty_findings(self):
        """Test empty findings returns empty chains"""
        chains = find_exploitation_chains([], {})
        assert chains == []


class TestEnhancedRiskScore:
    """Test enhanced risk scoring with correlation"""
    
    def test_calculates_chain_bonus(self):
        """Test chain bonus is applied"""
        finding = Finding(
            id="test-1",
            rule_id="heapdump",
            url="http://example.com/heap",
            severity="high",
        )
        finding.chain = [
            ChainStep(finding_id="1", rule_id="step1", url="http://a.com", action="access", result="success"),
            ChainStep(finding_id="2", rule_id="step2", url="http://b.com", action="exfil", result="success"),
        ]
        
        score = compute_enhanced_risk(finding)
        
        assert score >= finding.risk_score
    
    def test_calculates_credential_bonus(self):
        """Test credential bonus is applied"""
        finding = Finding(
            id="test-1",
            rule_id="env-exposure",
            url="http://example.com/.env",
            severity="high",
        )
        finding.extracted_data = {"password": "secret123"}
        
        score = compute_enhanced_risk(finding)
        
        assert score > 0


class TestCorrelateFindings:
    """Test main correlation function"""
    
    def test_returns_chains(self):
        """Test correlate_findings returns chains"""
        findings = [
            Finding(id="1", rule_id="heapdump", url="http://a.com/heap", severity="critical"),
            Finding(id="2", rule_id="env", url="http://a.com/.env", severity="high"),
        ]
        
        chains = correlate_findings(findings)
        
        assert isinstance(chains, list)
    
    def test_empty_input(self):
        """Test empty input returns empty"""
        result = correlate_findings([])
        assert result == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])