# tests/test_suppressions.py
"""
Tests for Suppression / Exception Workflow

Tests:
- Adding/removing suppressions
- URL pattern matching
- Severity filtering
- Expiry handling
- Applying suppressions to findings
- Clean expired suppressions
- Hide suppressed behavior
- Traceability fields
"""

import pytest
import os
import json
import tempfile
from datetime import datetime, timedelta
from postprocess.suppression import (
    SuppressionStore,
    Suppression,
    apply_suppressions,
    add_suppression,
)


class MockFinding:
    """Mock finding for testing"""
    def __init__(
        self,
        rule_id: str = "test-rule-001",
        url: str = "http://example.com/test",
        severity: str = "high",
    ):
        self.rule_id = rule_id
        self.url = url
        self.severity = severity


class TestSuppressionStoreCRUD:
    """Test basic CRUD operations"""
    
    @pytest.fixture
    def temp_store(self):
        """Create temporary suppression file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"suppressions": []}, f)
            temp_path = f.name
        
        store = SuppressionStore(temp_path)
        yield store
        
        if os.path.exists(temp_path):
            os.remove(temp_path)
    
    def test_add_suppression(self, temp_store):
        """Test adding a suppression"""
        suppression_id = temp_store.add(
            rule_id="test-rule-001",
            url_pattern="http://example.com/*",
            reason="False positive in test environment",
            owner="security_team",
            expires_days=30,
            severity_filter="high",
        )
        
        assert suppression_id == "sup-0001"
        assert len(temp_store.suppressions) == 1
    
    def test_remove_suppression(self, temp_store):
        """Test removing a suppression"""
        temp_store.add(
            rule_id="test-rule-001",
            url_pattern="http://example.com/*",
            reason="Test",
            owner="test",
        )
        
        result = temp_store.remove("test-rule-001", "http://example.com/*")
        assert result is True
        assert len(temp_store.suppressions) == 0
    
    def test_remove_nonexistent(self, temp_store):
        """Test removing non-existent suppression"""
        result = temp_store.remove("non-existent", "http://example.com/*")
        assert result is False


class TestSuppressionMatching:
    """Test URL pattern and severity matching"""
    
    @pytest.fixture
    def store_with_suppression(self):
        """Create store with test suppression"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"suppressions": []}, f)
            temp_path = f.name
        
        store = SuppressionStore(temp_path)
        store.add(
            rule_id="test-rule-001",
            url_pattern="http://example.com/.*",
            reason="Test",
            owner="test",
        )
        
        yield store
        
        if os.path.exists(temp_path):
            os.remove(temp_path)
    
    def test_exact_url_match(self, store_with_suppression):
        """Test exact URL matches"""
        sup = store_with_suppression.is_suppressed(
            "test-rule-001",
            "http://example.com/path",
        )
        assert sup is not None
    
    def test_wildcard_url_match(self, store_with_suppression):
        """Test wildcard URL pattern matches"""
        sup = store_with_suppression.is_suppressed(
            "test-rule-001",
            "http://example.com/any/path/here",
        )
        assert sup is not None
    
    def test_no_url_match(self, store_with_suppression):
        """Test non-matching URL returns None"""
        sup = store_with_suppression.is_suppressed("test-rule-001", "http://other.com/")
        assert sup is None
    
    def test_rule_id_exact_match(self):
        """Test exact rule_id matching"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"suppressions": []}, f)
            temp_path = f.name
        
        store = SuppressionStore(temp_path)
        store.add(
            rule_id="specific-rule",
            url_pattern=".*",
            reason="Test",
            owner="test",
        )
        
        sup = store.is_suppressed(
            "specific-rule",
            "http://example.com/path",
        )
        assert sup is not None
        
        other_sup = store.is_suppressed(
            "different-rule",
            "http://example.com/path",
        )
        assert other_sup is None
        
        if os.path.exists(temp_path):
            os.remove(temp_path)
    
    def test_rule_id_wildcard(self):
        """Test wildcard rule_id matches any rule"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"suppressions": []}, f)
            temp_path = f.name
        
        store = SuppressionStore(temp_path)
        store.add(
            rule_id="*",
            url_pattern="http://example.com/*",
            reason="Test",
            owner="test",
        )
        
        sup = store.is_suppressed(
            "any-rule-id",
            "http://example.com/path",
        )
        assert sup is not None
        
        if os.path.exists(temp_path):
            os.remove(temp_path)
    
    def test_severity_filter_high_suppresses_critical(self):
        """Test severity filter - high suppresses high and critical"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"suppressions": []}, f)
            temp_path = f.name
        
        store = SuppressionStore(temp_path)
        store.add(
            rule_id="test-rule-001",
            url_pattern=".*",
            reason="Test",
            owner="test",
            severity_filter="high",
        )
        
        sup_critical = store.is_suppressed(
            "test-rule-001",
            "http://example.com/",
            severity="critical",
        )
        assert sup_critical is not None
        
        sup_high = store.is_suppressed(
            "test-rule-001",
            "http://example.com/",
            severity="high",
        )
        assert sup_high is not None
        
        sup_medium = store.is_suppressed(
            "test-rule-001",
            "http://example.com/",
            severity="medium",
        )
        assert sup_medium is None
        
        if os.path.exists(temp_path):
            os.remove(temp_path)


class TestHideSuppressedBehavior:
    """Test --hide-suppressed behavior"""
    
    @pytest.fixture
    def suppression_file(self):
        """Create temporary suppression file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"suppressions": []}, f)
            temp_path = f.name
        
        yield temp_path
        
        if os.path.exists(temp_path):
            os.remove(temp_path)
    
    def test_hide_suppressed_excludes_from_remaining(self):
        """Test that suppressed findings are excluded from remaining"""
        findings = [
            MockFinding(rule_id="rule-001", url="http://a.com/", severity="high"),
            MockFinding(rule_id="rule-001", url="http://b.com/", severity="high"),
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"suppressions": []}, f)
            temp_path = f.name
        
        add_suppression(
            rule_id="rule-001",
            url_pattern="http://a.com/.*",
            reason="Known false positive",
            owner="security_team",
            suppression_file=temp_path,
        )
        
        result = apply_suppressions(findings, temp_path)
        
        remaining_urls = [f.url for f in result.remaining]
        assert "http://b.com/" in remaining_urls
        assert "http://a.com/" not in remaining_urls
        
        if os.path.exists(temp_path):
            os.remove(temp_path)
    
    def test_suppressed_count_in_stats(self):
        """Test suppressed count is correctly reported"""
        findings = [
            MockFinding(rule_id="rule-001", url="http://a.com/", severity="high"),
            MockFinding(rule_id="rule-001", url="http://b.com/", severity="high"),
            MockFinding(rule_id="rule-002", url="http://c.com/", severity="medium"),
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"suppressions": []}, f)
            temp_path = f.name
        
        add_suppression(
            rule_id="rule-001",
            url_pattern=".*",
            reason="Test",
            owner="test",
            suppression_file=temp_path,
        )
        
        result = apply_suppressions(findings, temp_path)
        
        assert result.stats["total"] == 3
        assert result.stats["suppressed"] == 2
        assert result.stats["remaining"] == 1
        
        if os.path.exists(temp_path):
            os.remove(temp_path)
    
    def test_delta_stats_with_suppressions(self):
        """Test delta statistics correctly reflect suppressed findings"""
        findings = [
            MockFinding(rule_id="rule-001", url="http://a.com/", severity="critical"),
            MockFinding(rule_id="rule-001", url="http://b.com/", severity="high"),
            MockFinding(rule_id="rule-002", url="http://c.com/", severity="medium"),
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"suppressions": []}, f)
            temp_path = f.name
        
        add_suppression(
            rule_id="rule-001",
            url_pattern="http://a.com/.*",
            reason="Known issue",
            owner="security_team",
            severity_filter="critical",
            suppression_file=temp_path,
        )
        
        result = apply_suppressions(findings, temp_path)
        
        suppressed_critical = [f for f in result.suppressed if f.severity == "critical"]
        remaining_high = [f for f in result.remaining if f.severity == "high"]
        
        assert len(suppressed_critical) == 1
        assert len(remaining_high) == 1
        
        if os.path.exists(temp_path):
            os.remove(temp_path)


class TestSuppressionTraceability:
    """Test suppressed findings retain traceability"""
    
    def test_suppressed_finding_retains_all_fields(self):
        """Suppressed findings should retain all original fields"""
        class TraceableFinding:
            def __init__(self):
                self.rule_id = "test-rule"
                self.url = "http://example.com/test"
                self.severity = "high"
                self.verification_state = "verified"
                self.confidence = "high"
                self.scan_id = "scan-001"
                self.id = "finding-001"
                self.title = "Test Finding"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"suppressions": []}, f)
            temp_path = f.name
        
        finding = TraceableFinding()
        
        add_suppression(
            rule_id="test-rule",
            url_pattern="http://example.com/test",
            reason="Acknowledged risk",
            owner="security_team",
            suppression_file=temp_path,
        )
        
        result = apply_suppressions([finding], temp_path)
        
        assert len(result.suppressed) == 1
        suppressed = result.suppressed[0]
        assert hasattr(suppressed, 'rule_id')
        assert hasattr(suppressed, 'url')
        assert hasattr(suppressed, 'severity')
        assert hasattr(suppressed, 'verification_state')
        assert hasattr(suppressed, 'scan_id')
        assert hasattr(suppressed, 'id')
        
        if os.path.exists(temp_path):
            os.remove(temp_path)
    
    def test_owner_and_reason_preserved(self):
        """Test owner and reason are preserved in suppression"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"suppressions": []}, f)
            temp_path = f.name
        
        store = SuppressionStore(temp_path)
        store.add(
            rule_id="test-rule",
            url_pattern="http://example.com/*",
            reason="Known issue in staging",
            owner="dev_team",
            expires_days=30,
        )
        
        loaded = store.list_suppressions()
        
        assert len(loaded) == 1
        assert loaded[0]["reason"] == "Known issue in staging"
        assert loaded[0]["owner"] == "dev_team"
        
        if os.path.exists(temp_path):
            os.remove(temp_path)
    
    def test_severity_filter_blocks_lower_severity(self):
        """Test severity_filter correctly blocks lower severity"""
        findings = [
            MockFinding(rule_id="test-rule", url="http://example.com/", severity="critical"),
            MockFinding(rule_id="test-rule", url="http://example.com/", severity="high"),
            MockFinding(rule_id="test-rule", url="http://example.com/", severity="medium"),
            MockFinding(rule_id="test-rule", url="http://example.com/", severity="low"),
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"suppressions": []}, f)
            temp_path = f.name
        
        add_suppression(
            rule_id="test-rule",
            url_pattern="http://example.com/.*",
            reason="Test",
            owner="test",
            severity_filter="high",
            suppression_file=temp_path,
        )
        
        result = apply_suppressions(findings, temp_path)
        
        suppressed_severities = [f.severity for f in result.suppressed]
        remaining_severities = [f.severity for f in result.remaining]
        
        assert "critical" in suppressed_severities
        assert "high" in suppressed_severities
        assert "medium" in remaining_severities
        assert "low" in remaining_severities
        
        if os.path.exists(temp_path):
            os.remove(temp_path)


class TestSuppressionExpiry:
    """Test expiry date handling"""
    
    def test_expired_suppression_not_applied(self):
        """Test expired suppression is not applied"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"suppressions": []}, f)
            temp_path = f.name
        
        store = SuppressionStore(temp_path)
        
        expired_date = (datetime.utcnow() - timedelta(days=1)).isoformat() + "Z"
        store.suppressions["key"] = Suppression(
            id="sup-0001",
            rule_id="test-rule",
            url_pattern=".*",
            reason="Test",
            owner="test",
            created_at=datetime.utcnow().isoformat() + "Z",
            expires_at=expired_date,
        )
        
        sup = store.is_suppressed("test-rule", "http://example.com/")
        assert sup is None
        
        if os.path.exists(temp_path):
            os.remove(temp_path)
    
    def test_valid_suppression_applied(self):
        """Test valid (non-expired) suppression is applied"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"suppressions": []}, f)
            temp_path = f.name
        
        store = SuppressionStore(temp_path)
        
        future_date = (datetime.utcnow() + timedelta(days=30)).isoformat() + "Z"
        store.suppressions["key"] = Suppression(
            id="sup-0001",
            rule_id="test-rule",
            url_pattern=".*",
            reason="Test",
            owner="test",
            created_at=datetime.utcnow().isoformat() + "Z",
            expires_at=future_date,
        )
        
        sup = store.is_suppressed("test-rule", "http://example.com/")
        assert sup is not None
        
        if os.path.exists(temp_path):
            os.remove(temp_path)
    
    def test_no_expiry_always_valid(self):
        """Test suppression without expiry is always valid"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"suppressions": []}, f)
            temp_path = f.name
        
        store = SuppressionStore(temp_path)
        
        store.suppressions["key"] = Suppression(
            id="sup-0001",
            rule_id="test-rule",
            url_pattern=".*",
            reason="Test",
            owner="test",
            created_at=datetime.utcnow().isoformat() + "Z",
            expires_at=None,
        )
        
        sup = store.is_suppressed("test-rule", "http://example.com/")
        assert sup is not None
        
        if os.path.exists(temp_path):
            os.remove(temp_path)
    
    def test_clean_expired(self):
        """Test cleaning expired suppressions"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"suppressions": []}, f)
            temp_path = f.name
        
        store = SuppressionStore(temp_path)
        
        expired_date = (datetime.utcnow() - timedelta(days=1)).isoformat() + "Z"
        store.suppressions["expired"] = Suppression(
            id="sup-0001",
            rule_id="test-rule-1",
            url_pattern=".*",
            reason="Expired",
            owner="test",
            created_at=datetime.utcnow().isoformat() + "Z",
            expires_at=expired_date,
        )
        
        future_date = (datetime.utcnow() + timedelta(days=30)).isoformat() + "Z"
        store.suppressions["valid"] = Suppression(
            id="sup-0002",
            rule_id="test-rule-2",
            url_pattern=".*",
            reason="Valid",
            owner="test",
            created_at=datetime.utcnow().isoformat() + "Z",
            expires_at=future_date,
        )
        
        cleaned = store.clean_expired()
        assert cleaned == 1
        assert len(store.suppressions) == 1
        assert "valid" in store.suppressions
        
        if os.path.exists(temp_path):
            os.remove(temp_path)


class TestApplySuppressions:
    """Test applying suppressions to findings"""
    
    @pytest.fixture
    def findings(self):
        """Create mock findings"""
        return [
            MockFinding(rule_id="rule-001", url="http://a.com/", severity="high"),
            MockFinding(rule_id="rule-001", url="http://b.com/", severity="high"),
            MockFinding(rule_id="rule-002", url="http://c.com/", severity="low"),
        ]
    
    @pytest.fixture
    def suppression_file(self):
        """Create temporary suppression file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"suppressions": []}, f)
            temp_path = f.name
        
        yield temp_path
        
        if os.path.exists(temp_path):
            os.remove(temp_path)
    
    def test_no_suppressions_all_remaining(self, findings, suppression_file):
        """Test with no suppressions, all findings remain"""
        result = apply_suppressions(findings, suppression_file)
        
        assert len(result.remaining) == 3
        assert len(result.suppressed) == 0
        assert result.stats["total"] == 3
    
    def test_partial_suppression(self, findings, suppression_file):
        """Test partial suppression"""
        add_suppression(
            rule_id="rule-001",
            url_pattern="http://a.com/.*",
            reason="Test",
            owner="test",
            suppression_file=suppression_file,
        )
        
        result = apply_suppressions(findings, suppression_file)
        
        assert len(result.suppressed) == 1
        assert len(result.remaining) == 2
        assert result.stats["suppressed"] == 1
    
    def test_severity_filter_applied(self, findings, suppression_file):
        """Test severity filter in apply"""
        add_suppression(
            rule_id="rule-001",
            url_pattern=".*",
            reason="Test",
            owner="test",
            severity_filter="high",
            suppression_file=suppression_file,
        )
        
        result = apply_suppressions(findings, suppression_file)
        
        suppressed_rules = [f.rule_id for f in result.suppressed]
        assert "rule-001" in suppressed_rules
        assert "rule-002" not in suppressed_rules


class TestSuppressionList:
    """Test listing suppressions"""
    
    def test_list_empty(self):
        """Test listing empty store"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"suppressions": []}, f)
            temp_path = f.name
        
        store = SuppressionStore(temp_path)
        result = store.list_suppressions()
        
        assert result == []
        
        if os.path.exists(temp_path):
            os.remove(temp_path)
    
    def test_list_with_data(self):
        """Test listing suppressions"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"suppressions": []}, f)
            temp_path = f.name
        
        store = SuppressionStore(temp_path)
        store.add(
            rule_id="test-rule",
            url_pattern="http://example.com/*",
            reason="Test reason",
            owner="security_team",
            expires_days=30,
            severity_filter="high",
        )
        
        result = store.list_suppressions()
        
        assert len(result) == 1
        assert result[0]["rule_id"] == "test-rule"
        assert result[0]["reason"] == "Test reason"
        assert result[0]["owner"] == "security_team"
        assert result[0]["severity_filter"] == "high"
        
        if os.path.exists(temp_path):
            os.remove(temp_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])