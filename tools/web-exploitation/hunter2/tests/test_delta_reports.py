# tests/test_delta_reports.py
"""
Delta Report / Baseline Comparison Tests

Tests baseline comparison functionality:
- new/resolved/changed/unchanged classification
- --new-only behavior
- severity filtering
- delta JSON structure
"""

import pytest
import json
from pathlib import Path
from postprocess.baseline import (
    load_baseline,
    compare_with_baseline,
    write_delta_report,
    filter_new_only_by_severity,
    BaselineFinding,
    DeltaFinding,
    BaselineReport,
)


class MockFinding:
    def __init__(self, rule_id, url, severity="medium", verification_state="observed", confidence="medium"):
        self.rule_id = rule_id
        self.url = url
        self.severity = severity
        self.verification_state = verification_state
        self.confidence = confidence


class TestBaselineComparison:
    """Test baseline comparison logic"""
    
    def test_new_findings_detected(self):
        """New findings not in baseline should be detected"""
        baseline = {
            "git-exposure::http://example.com/.git/config": BaselineFinding(
                rule_id="git-exposure",
                url="http://example.com/.git/config",
                severity="high",
                verification_state="verified",
                scan_id="scan-001",
                timestamp="2026-04-11T10:00:00Z",
            )
        }
        
        current = [
            MockFinding("git-exposure", "http://example.com/.git/config"),
            MockFinding("heapdump-exposure", "http://example.com/heapdump", "critical"),
        ]
        
        report = compare_with_baseline(current, baseline, "scan-002", "scan-001")
        
        assert report.stats["new"] == 1
        assert report.new_findings[0].finding.rule_id == "heapdump-exposure"
    
    def test_resolved_findings_detected(self):
        """Findings in baseline but not in current should be detected as resolved"""
        baseline = {
            "git-exposure::http://example.com/.git/config": BaselineFinding(
                rule_id="git-exposure",
                url="http://example.com/.git/config",
                severity="high",
                verification_state="verified",
                scan_id="scan-001",
                timestamp="2026-04-11T10:00:00Z",
            ),
            "heapdump::http://example.com/heapdump": BaselineFinding(
                rule_id="heapdump-exposure",
                url="http://example.com/heapdump",
                severity="critical",
                verification_state="observed",
                scan_id="scan-001",
                timestamp="2026-04-11T10:00:00Z",
            ),
        }
        
        # Current only has git-exposure (heapdump resolved)
        current = [
            MockFinding("git-exposure", "http://example.com/.git/config"),
        ]
        
        report = compare_with_baseline(current, baseline, "scan-002", "scan-001")
        
        assert report.stats["resolved"] == 1
        assert report.resolved_findings[0].rule_id == "heapdump-exposure"
    
    def test_changed_severity_detected(self):
        """Findings with changed severity should be detected"""
        baseline = {
            "git-exposure::http://example.com/.git/config": BaselineFinding(
                rule_id="git-exposure",
                url="http://example.com/.git/config",
                severity="low",
                verification_state="observed",
                scan_id="scan-001",
                timestamp="2026-04-11T10:00:00Z",
            ),
        }
        
        current = [
            MockFinding("git-exposure", "http://example.com/.git/config", severity="high"),
        ]
        
        report = compare_with_baseline(current, baseline, "scan-002", "scan-001")
        
        assert report.stats["changed"] == 1
        assert report.changed_findings[0].previous_severity == "low"
        assert report.changed_findings[0].finding.severity == "high"
    
    def test_unchanged_findings(self):
        """Unchanged findings should be counted"""
        baseline = {
            "git-exposure::http://example.com/.git/config": BaselineFinding(
                rule_id="git-exposure",
                url="http://example.com/.git/config",
                severity="high",
                verification_state="suspected",
                scan_id="scan-001",
                timestamp="2026-04-11T10:00:00Z",
            ),
        }
        
        current = [
            MockFinding("git-exposure", "http://example.com/.git/config", severity="high", verification_state="suspected"),
        ]
        
        report = compare_with_baseline(current, baseline, "scan-002", "scan-001")
        
        assert report.stats["unchanged"] == 1


class TestFilterNewOnly:
    """Test --new-only filtering"""
    
    def test_filter_by_medium_severity(self):
        """Filter new findings at or above medium severity"""
        report = BaselineReport(
            baseline_scan_id="scan-001",
            current_scan_id="scan-002",
            new_findings=[
                DeltaFinding(MockFinding("heapdump", "http://test/heap", "critical"), "new"),
                DeltaFinding(MockFinding("info", "http://test/info", "info"), "new"),
            ],
        )
        
        filtered = filter_new_only_by_severity(report, "medium")
        
        assert len(filtered) == 1
        assert filtered[0].rule_id == "heapdump"
    
    def test_filter_by_high_severity(self):
        """Filter new findings at or above high severity"""
        report = BaselineReport(
            baseline_scan_id="scan-001",
            current_scan_id="scan-002",
            new_findings=[
                DeltaFinding(MockFinding("heapdump", "http://test/heap", "critical"), "new"),
                DeltaFinding(MockFinding("git", "http://test/git", "high"), "new"),
                DeltaFinding(MockFinding("actuator", "http://test/act", "medium"), "new"),
            ],
        )
        
        filtered = filter_new_only_by_severity(report, "high")
        
        assert len(filtered) == 2
        assert all(f.severity in ["critical", "high"] for f in filtered)


class TestDeltaJsonStructure:
    """Test delta JSON output structure"""
    
    def test_delta_has_summary(self):
        """Delta report should have summary section"""
        report = BaselineReport(
            baseline_scan_id="scan-001",
            current_scan_id="scan-002",
            new_findings=[DeltaFinding(MockFinding("test", "http://test", "high"), "new")],
        )
        
        # Write to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            write_delta_report(f.name, report, "http://test.com")
        
        with open(f.name) as fp:
            data = json.load(fp)
        
        assert "summary" in data
        assert data["summary"]["new"] == 1
        assert "new_by_severity" in data["summary"]
        
        Path(f.name).unlink()
    
    def test_delta_has_severity_breakdown(self):
        """Delta report should include severity breakdown"""
        report = BaselineReport(
            baseline_scan_id="scan-001",
            current_scan_id="scan-002",
            new_findings=[
                DeltaFinding(MockFinding("c1", "http://c1", "critical"), "new"),
                DeltaFinding(MockFinding("c2", "http://c2", "critical"), "new"),
                DeltaFinding(MockFinding("h", "http://h", "high"), "new"),
            ],
            resolved_findings=[
                BaselineFinding("r", "http://r", "medium", "observed", "scan-001", ""),
            ],
        )
        
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            write_delta_report(f.name, report, "http://test.com")
        
        with open(f.name) as fp:
            data = json.load(fp)
        
        assert data["summary"]["new_by_severity"]["critical"] == 2
        assert data["summary"]["new_by_severity"]["high"] == 1
        assert data["summary"]["resolved_by_severity"]["medium"] == 1
        
        Path(f.name).unlink()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])