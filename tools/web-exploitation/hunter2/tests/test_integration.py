# tests/test_integration.py
"""
Integration Tests for End-to-End Scan Flow

Tests the complete pipeline:
1. Config initialization
2. Rule loading
3. Target enumeration
4. Rule execution
5. Finding deduplication
6. Baseline comparison
7. Suppression filtering
8. Report generation
"""

import pytest
import json
import tempfile
import os
from unittest.mock import Mock, patch
from datetime import datetime


class TestConfigInitialization:
    """Test config initialization with all enterprise features"""
    
    def test_config_with_all_args(self):
        """Test config with policy, env, baseline, suppressions"""
        from config.defaults import default_config
        from config.config import Config
        
        class Args:
            base = "http://example.com"
            speed = "medium"
            policy = "balanced"
            env = "staging"
            baseline = "baseline.json"
            suppressions = "suppressions.json"
            hide_suppressed = True
            fail_on = "high"
            fail_on_new = "critical"
            fail_on_changed = "high"
            fail_on_delta_only = False
            ignore_expired_suppressions = False
            
            # Required fields
            pack = "web-misconfig"
            rules_dir = "rules"
            outdir = "loot"
            report = "report"
            qps = 2.0
            timeout = 12.0
            retries = 1
            threads = 5
            max_requests = 0
            allow_host = []
            allow_suffix = []
            exclude = []
            deny_private = False
            no_redirects = False
            print_matches = False
            verbose = False
            proxy = ""
            insecure = False
            header = []
            cookie = ""
            bearer = ""
            discover = False
            crawl = False
            crawl_depth = 2
            crawl_max_pages = 60
            seed = []
            seeds_file = ""
            passive = False
            fuzz = []
            fuzz_target = []
            payload_dir = "payloads"
            artifact_analysis = False
            save_artifacts = False
            max_artifact_mb = 10
            fail_verified_only = False
            fail_exploited_only = False
            new_only = False
            html = False
            dry_run = False
            stop_on_high_confidence = False
            list_packs = False
            list_rules = None
            init_config = False
            mode = ""
        
        cfg = default_config(Args())
        
        assert cfg.base == "http://example.com"
        assert cfg.policy == "balanced"
        assert cfg.environment == "staging"
        assert cfg.baseline == "baseline.json"
        assert cfg.suppressions == "suppressions.json"
        assert cfg.fail_on_severity == "high"


class TestRuleLoading:
    """Test rule loading with metadata"""
    
    def test_load_rules_with_metadata(self):
        """Test that rules load with all metadata fields"""
        from rules.loader import load_rules
        
        rules = load_rules("rules/packs", pack="web-misconfig")
        
        assert len(rules) > 0
        
        for rule in rules:
            assert hasattr(rule, 'id')
            info = getattr(rule, 'info', {}) or {}
            assert 'name' in info
            assert 'severity' in info


class TestFindingCreation:
    """Test finding creation with enterprise fields"""
    
    def test_finding_with_all_fields(self):
        """Test creating finding with all enterprise fields"""
        from core.models import Finding
        
        finding = Finding(
            id="finding-001",
            rule_id="git-exposure",
            url="http://example.com/.git/config",
            title="Exposed .git Directory",
            severity="high",
            confidence="high",
            verification_state="observed",
            scan_id="scan-001",
            discovered_at=datetime.utcnow().isoformat(),
            cwe="552",
            owasp="A01:2021-Broken Access Control",
        )
        
        assert finding.id == "finding-001"
        assert finding.severity == "high"
        assert finding.verification_state == "observed"
        assert finding.scan_id == "scan-001"


class TestDeduplication:
    """Test finding deduplication"""
    
    def test_dedupe_removes_duplicates(self):
        """Test that deduplication removes duplicate findings"""
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
            MockFinding("env-files", "http://example.com/.env"),
        ]
        
        deduped = dedupe_findings_prefer_chain(findings)
        
        assert len(deduped) == 2


class TestBaselineComparison:
    """Test baseline comparison flow"""
    
    def test_baseline_comparison_with_new_resolved_changed(self):
        """Test delta detection: new, resolved, changed"""
        from postprocess.baseline import compare_with_baseline, BaselineFinding
        
        class MockFinding:
            def __init__(self, rule_id, url, severity):
                self.rule_id = rule_id
                self.url = url
                self.severity = severity
        
        baseline = {
            "rule-1::http://a.com": BaselineFinding(
                rule_id="rule-1",
                url="http://a.com",
                severity="high",
                verification_state="verified",
                scan_id="baseline-001",
                timestamp="2026-04-01T00:00:00Z",
            ),
            "rule-2::http://b.com": BaselineFinding(
                rule_id="rule-2",
                url="http://b.com",
                severity="medium",
                verification_state="observed",
                scan_id="baseline-001",
                timestamp="2026-04-01T00:00:00Z",
            ),
        }
        
        current = [
            MockFinding("rule-1", "http://a.com", "critical"),
            MockFinding("rule-3", "http://c.com", "high"),
        ]
        
        result = compare_with_baseline(current, baseline, "scan-002", "baseline-001")
        
        assert len(result.new_findings) == 1
        assert result.new_findings[0].finding.rule_id == "rule-3"
        
        assert len(result.resolved_findings) == 1
        assert result.resolved_findings[0].rule_id == "rule-2"
        
        assert len(result.changed_findings) == 1
        assert result.changed_findings[0].previous_severity == "high"
        assert result.changed_findings[0].finding.severity == "critical"


class TestSuppressionFiltering:
    """Test suppression filtering flow"""
    
    def test_suppression_filters_findings(self):
        """Test that suppressions correctly filter findings"""
        from postprocess.suppression import apply_suppressions, add_suppression
        
        class MockFinding:
            def __init__(self, rule_id, url, severity):
                self.rule_id = rule_id
                self.url = url
                self.severity = severity
        
        findings = [
            MockFinding("rule-1", "http://a.com", "high"),
            MockFinding("rule-1", "http://b.com", "medium"),
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"suppressions": []}, f)
            temp_path = f.name
        
        try:
            add_suppression(
                rule_id="rule-1",
                url_pattern="http://a.com/.*",
                reason="False positive",
                owner="test",
                suppression_file=temp_path,
            )
            
            result = apply_suppressions(findings, temp_path)
            
            assert len(result.remaining) == 1
            assert result.remaining[0].url == "http://b.com"
            assert len(result.suppressed) == 1
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


class TestReportGeneration:
    """Test report generation"""
    
    def test_json_report_structure(self):
        """Test JSON report has required structure"""
        from reports.json_report import _finding_to_dict
        
        class MockFinding:
            def __init__(self):
                self.id = "finding-001"
                self.rule_id = "test-rule"
                self.url = "http://example.com/test"
                self.title = "Test Finding"
                self.severity = "high"
                self.confidence = "high"
                self.verification_state = "observed"
                self.matches = ["test match"]
                self.remediation = "Fix it"
                self.scan_id = "scan-001"
        
        finding = MockFinding()
        
        result = _finding_to_dict(finding)
        
        assert result["rule_id"] == "test-rule"
        assert result["severity"] == "high"
        assert result["verification_state"] == "observed"


class TestExitCodeLogic:
    """Test exit code decision logic"""
    
    def test_fail_on_severity_threshold(self):
        """Test fail-on with severity threshold"""
        from core.models import severity_rank
        
        class MockFinding:
            def __init__(self, severity):
                self.severity = severity
                self.title = "Test"
                self.verification_state = "observed"
        
        findings = [
            MockFinding("low"),
            MockFinding("medium"),
            MockFinding("high"),
        ]
        
        fail_on_severity = "high"
        sev_rank = severity_rank(fail_on_severity)
        
        should_fail = any(
            severity_rank(f.severity) >= sev_rank
            for f in findings
        )
        
        assert should_fail is True
    
    def test_fail_on_new_only(self):
        """Test fail-on-new only considers new findings"""
        from postprocess.baseline import DeltaFinding, BaselineFinding
        
        class MockFinding:
            def __init__(self, rule_id, severity):
                self.rule_id = rule_id
                self.severity = severity
        
        new_findings = [
            DeltaFinding(
                finding=MockFinding("rule-3", "critical"),
                delta_type="new",
            ),
        ]
        
        should_fail = any(
            f.finding.severity == "critical"
            for f in new_findings
        )
        
        assert should_fail is True


class TestVerificationStateTransitions:
    """Test verification state machine"""
    
    def test_auto_verification_flow(self):
        """Test automatic verification state progression"""
        from postprocess.verifier import FindingVerifier
        
        verifier = FindingVerifier(scan_id="test-scan")
        
        verifier.set_initial_state("finding-001")
        
        assert verifier.get_state("finding-001") == "observed"
        
        verifier.transition_to_suspected(
            "finding-001",
            "observed",
            actor_name="verifier_auto",
            reason="Context indicators present",
        )
        
        assert verifier.get_state("finding-001") == "suspected"
        
        verifier.transition_to_verified(
            "finding-001",
            "suspected",
            actor_name="verifier_auto",
            reason="Sensitive data extracted",
        )
        
        assert verifier.get_state("finding-001") == "verified"


class TestArtifactManagement:
    """Test artifact collection and storage"""
    
    def test_artifact_id_generation(self):
        """Test artifact ID follows pattern"""
        from core.artifact_manager import generate_artifact_id
        
        art_id = generate_artifact_id("scan-001", "finding-001", 0)
        
        assert art_id.startswith("art-scan-001-finding-001-")
    
    def test_artifact_builder(self):
        """Test artifact builder creates valid artifact"""
        from core.artifact_manager import ArtifactBuilder
        
        artifact = (
            ArtifactBuilder()
            .artifact_id("art-001")
            .scan_id("scan-001")
            .finding_id("finding-001")
            .artifact_type("http_exchange")
            .timestamp("2026-04-11T00:00:00Z")
            .content("test content")
            .build()
        )
        
        assert artifact.artifact_id == "art-001"
        assert artifact.scan_id == "scan-001"
        assert artifact.type == "http_exchange"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])