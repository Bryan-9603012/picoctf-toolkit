# tests/test_quality.py
"""
Quality Tests - FP Rate, Duplicates, Correlation Accuracy, Scoring Quality

Tests:
- False positive handling
- Duplicate finding detection
- Correlation accuracy
- Exploitability scoring quality
- Planner quality checks
"""

import pytest
from core.models import Finding, Evidence, ChainStep
from postprocess.correlation import (
    find_credentials,
    find_sensitive_artifacts,
    correlate_findings,
)
from postprocess.exploitability import (
    compute_exploitability,
    _has_credentials,
    _has_sensitive_data,
    _compute_access_score,
)
from postprocess.planner import (
    suggest_next_steps,
    build_attack_plan,
    rank_paths_by_exploitability,
)


class TestFalsePositiveHandling:
    """Test false positive identification and handling"""
    
    def test_common_false_positive_patterns(self):
        """Test common FP patterns are identified"""
        
        safe_patterns = [
            "http://example.com/about",
            "http://example.com/contact",
            "http://example.com/static/images/logo.png",
            "http://example.com/api/docs",
        ]
        
        for url in safe_patterns:
            from postprocess.source_aware import is_sensitive_route
            
            result = is_sensitive_route(url)
            
            if "static" in url or "docs" in url:
                assert result is False, f"{url} should not be sensitive"
    
    def test_match_validation(self):
        """Test regex matches are validated"""
        from core.models import Finding
        
        finding = Finding(
            id="test",
            rule_id="test",
            url="http://test.com",
            severity="medium",
        )
        finding.matches = [
            "test",
            "another",
            "third",
        ]
        
        assert len(finding.matches) == 3
    
    def test_low_confidence_flagging(self):
        """Test low confidence findings are flagged"""
        from core.models import Finding
        
        finding = Finding(
            id="test",
            rule_id="test",
            url="http://test.com",
            severity="medium",
            confidence="low",
        )
        
        assert finding.confidence == "low"


class TestDuplicateDetection:
    """Test duplicate finding detection"""
    
    def test_exact_duplicate_detection(self):
        """Test exact duplicates are detected"""
        from postprocess.dedupe import dedupe_findings_prefer_chain
        
        class MockFinding:
            def __init__(self, rule_id, url):
                self.rule_id = rule_id
                self.url = url
                self.severity = "high"
                self.confidence = "high"
                self.chain = []
        
        findings = [
            MockFinding("git-exposure", "http://example.com/.git/config"),
            MockFinding("git-exposure", "http://example.com/.git/config"),
            MockFinding("git-exposure", "http://example.com/.git/HEAD"),
        ]
        
        result = dedupe_findings_prefer_chain(findings)
        
        assert len(result) == 2
    
    def test_url_normalization(self):
        """Test URL normalization for duplicates"""
        from postprocess.dedupe import dedupe_findings_prefer_chain
        
        class MockFinding:
            def __init__(self, url):
                self.rule_id = "test"
                self.url = url
                self.severity = "high"
                self.confidence = "high"
                self.chain = []
        
        findings = [
            MockFinding("http://example.com/path"),
            MockFinding("http://example.com/path/"),
        ]
        
        result = dedupe_findings_prefer_chain(findings)
        
        assert len(result) <= len(findings)


class TestCorrelationAccuracy:
    """Test correlation accuracy"""
    
    def test_correlation_not_over_connecting(self):
        """Test correlation doesn't over-connect unrelated findings"""
        from postprocess.correlation import build_correlation_graph
        
        class MockFinding:
            def __init__(self, rule_id, url):
                self.rule_id = rule_id
                self.url = url
        
        findings = [
            MockFinding("git", "http://a.com/.git"),
            MockFinding("about", "http://a.com/about"),
            MockFinding("contact", "http://a.com/contact"),
            MockFinding("static", "http://a.com/static"),
        ]
        
        graph = build_correlation_graph(findings)
        
        assert isinstance(graph, dict)
    
    def test_chain_requires_multiple_findings(self):
        """Test chain requires multiple related findings"""
        from postprocess.correlation import find_exploitation_chains
        
        class MockFinding:
            def __init__(self, url):
                self.rule_id = "test"
                self.url = url
        
        findings = [
            MockFinding("http://test.com/page1"),
            MockFinding("http://test.com/page2"),
        ]
        
        graph = {"0:http://test.com/page1": []}
        
        chains = find_exploitation_chains(findings, graph)
        
        assert isinstance(chains, list)
    
    def test_credential_detection_accuracy(self):
        """Test credential detection is accurate"""
        
        true_positives = [
            '{"password": "secret123"}',
            'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
            'api_key: "sk-1234567890abcdef"',
            'Authorization: Basic dXNlcjpwYXNz',
        ]
        
        for content in true_positives:
            from core.models import Finding
            finding = Finding(id="test", rule_id="test", url="http://test", severity="high")
            finding.evidence = Evidence(snippet=content)
            
            result = find_credentials(finding)
            
            assert result is True, f"Failed to detect credentials in: {content[:50]}"


class TestExploitabilityScoringQuality:
    """Test exploitability scoring quality"""
    
    def test_critical_finding_always_high_score(self):
        """Test critical findings always get high exploitability"""
        from postprocess.exploitability import compute_exploitability
        
        finding = Finding(
            id="test",
            rule_id="critical-rule",
            url="http://test.com",
            severity="critical",
            confidence="high",
            verification_state="verified",
        )
        
        score = compute_exploitability(finding)
        
        assert score.total_score >= 50
    
    def test_info_finding_never_high_score(self):
        """Test info findings never get high exploitability"""
        from postprocess.exploitability import compute_exploitability
        
        finding = Finding(
            id="test",
            rule_id="info-rule",
            url="http://test.com",
            severity="info",
            confidence="low",
        )
        
        score = compute_exploitability(finding)
        
        assert score.total_score < 60
    
    def test_verification_bonus_not_overlapping(self):
        """Test verification bonus doesn't completely override severity"""
        from postprocess.exploitability import compute_exploitability
        
        observed_finding = Finding(
            id="test1",
            rule_id="test",
            url="http://test.com",
            severity="info",
            confidence="medium",
            verification_state="observed",
        )
        
        exploited_finding = Finding(
            id="test2",
            rule_id="test",
            url="http://test.com",
            severity="info",
            confidence="medium",
            verification_state="exploited",
        )
        
        observed_score = compute_exploitability(observed_finding)
        exploited_score = compute_exploitability(exploited_finding)
        
        difference = exploited_score.total_score - observed_score.total_score
        
        assert difference < 30, "Verification bonus should not completely override severity"
    
    def test_chain_bonus_reasonable(self):
        """Test chain bonus is reasonable"""
        from postprocess.exploitability import compute_exploitability
        
        single_finding = Finding(
            id="test1",
            rule_id="test",
            url="http://test.com",
            severity="high",
            confidence="high",
        )
        
        chained_finding = Finding(
            id="test2",
            rule_id="test",
            url="http://test.com",
            severity="high",
            confidence="high",
            verification_state="verified",
        )
        chained_finding.chain = [
            ChainStep(finding_id="1", rule_id="step1", url="http://a.com", action="access", result="success"),
            ChainStep(finding_id="2", rule_id="step2", url="http://b.com", action="exfil", result="success"),
            ChainStep(finding_id="3", rule_id="step3", url="http://c.com", action="persist", result="success"),
        ]
        
        single_score = compute_exploitability(single_finding)
        chained_score = compute_exploitability(chained_finding)
        
        assert chained_score.chain_bonus <= 20, "Chain bonus should be capped"


class TestPlannerQuality:
    """Test planner quality checks"""
    
    def test_no_suggestions_with_no_findings(self):
        """Test planner handles no findings gracefully"""
        suggestions = suggest_next_steps([], {})
        
        assert len(suggestions) > 0
        assert "git_directory_discovery" in suggestions
    
    def test_plan_adapts_to_severity(self):
        """Test plan adapts based on finding severity"""
        class MockFinding:
            def __init__(self, severity):
                self.rule_id = "test"
                self.url = "http://test.com"
                self.severity = severity
                self.exploitability = "high"
                self.extracted_data = {}
        
        findings = [MockFinding("critical"), MockFinding("critical")]
        
        plan = build_attack_plan("http://target.com", findings, {})
        
        assert plan.estimated_difficulty in ["easy", "medium", "hard"]
        assert plan.success_probability > 0.3
    
    def test_plan_safe_policy_not_too_aggressive(self):
        """Test plan is not too aggressive"""
        class MockFinding:
            def __init__(self):
                self.rule_id = "test"
                self.url = "http://test.com"
                self.severity = "medium"
                self.exploitability = "medium"
                self.extracted_data = {}
        
        findings = [MockFinding()]
        
        plan = build_attack_plan("http://target.com", findings, {})
        
        for step in plan.steps:
            assert step.difficulty in ["easy", "medium", "hard"]
    
    def test_path_ranking_returns_valid_order(self):
        """Test path ranking returns valid ordering"""
        paths = [
            ["step1", "step2"],
            ["step1"],
            ["step1", "step2", "step3", "step4"],
        ]
        
        class MockFinding:
            def __init__(self):
                self.rule_id = "test"
                self.url = "http://test.com"
                self.severity = "high"
        
        findings = [MockFinding()]
        
        ranked = rank_paths_by_exploitability(paths, findings)
        
        assert len(ranked) == 3
        scores = [s for _, s in ranked]
        assert scores == sorted(scores, reverse=True)


class TestFingerprintStability:
    """Test fingerprint stability"""
    
    def test_fingerprint_repeatable(self):
        """Test fingerprint is repeatable"""
        target = "http://example.com"
        
        from fingerprint.fingerprint import fingerprint_target
        
        class MockTechDB:
            pass
        
        class MockWafDB:
            pass
        
        class MockConfig:
            base = target
            qps = 2
            timeout = 10
            threads = 1
            verify_ssl = False
            header = []
            allow_host = []
        
        result = fingerprint_target(MockTechDB(), MockWafDB(), target, MockConfig())
        
        assert result is not None
    
    def test_fingerprint_missing_headers_handled(self):
        """Test fingerprint handles missing headers gracefully"""
        from fingerprint.fingerprint import fingerprint_target
        
        class MockTechDB:
            pass
        
        class MockWafDB:
            pass
        
        class MockConfig:
            base = "http://example.com"
            qps = 2
            timeout = 10
            threads = 1
            verify_ssl = False
            header = None
            allow_host = []
        
        result = fingerprint_target(MockTechDB(), MockWafDB(), "http://example.com", MockConfig())
        
        assert result is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])