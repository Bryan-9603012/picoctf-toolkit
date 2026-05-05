# tests/test_state_transitions.py
"""
Tests for Finding State Transition System

Tests the fixed model:
- Rule Engine: can only produce observed (initial state)
- Verifier: can go observed → suspected → verified
- Exploit Runner: can go verified → exploited
- Manual Override: can go any → any with reason/actor/timestamp
"""

import pytest
from datetime import datetime
from postprocess.verifier import (
    FindingVerifier,
    VerificationError,
    ALLOWED_TRANSITIONS,
    FORBIDDEN_TRANSITIONS,
)
from core.models import Finding, Evidence


class MockFinding:
    """Mock finding for testing"""
    def __init__(self, finding_id: str = "test-001", initial_state: str = "observed"):
        self.id = finding_id
        self.verification_state = initial_state


class TestAllowedTransitionsTable:
    """Test the explicit transition table"""
    
    def test_observed_to_suspected_allowed(self):
        """observed → suspected should be allowed by verifier"""
        assert ALLOWED_TRANSITIONS["observed"]["suspected"] == "verifier"
    
    def test_suspected_to_verified_allowed(self):
        """suspected → verified should be allowed by verifier"""
        assert ALLOWED_TRANSITIONS["suspected"]["verified"] == "verifier"
    
    def test_verified_to_exploited_allowed(self):
        """verified → exploited should be allowed by exploit_runner"""
        assert ALLOWED_TRANSITIONS["verified"]["exploited"] == "exploit_runner"
    
    def test_forbidden_transitions_listed(self):
        """Verify forbidden transitions are explicitly listed"""
        assert "observed → verified" in FORBIDDEN_TRANSITIONS
        assert "observed → exploited" in FORBIDDEN_TRANSITIONS
        assert "suspected → exploited" in FORBIDDEN_TRANSITIONS


class TestRuleEngineInitialState:
    """Test Rule Engine can only produce observed"""
    
    def test_rule_engine_sets_observed(self):
        """Rule engine should always set initial state to observed"""
        verifier = FindingVerifier(scan_id="test-scan-001")
        result = verifier.set_initial_state("test-finding-001")
        assert result == "observed"
    
    def test_rule_engine_logged(self):
        """Rule engine transition should be logged"""
        verifier = FindingVerifier(scan_id="test-scan-001")
        verifier.set_initial_state("test-finding-001")
        
        log = verifier.get_transition_log()
        assert len(log) == 1
        assert log[0].actor_type == "rule_engine"
        assert log[0].from_state == ""
        assert log[0].to_state == "observed"


class TestVerifierProgressive:
    """Test Verifier can progress through states"""
    
    def test_verifier_can_transition_observed_to_suspected(self):
        """Verifier should be able to transition observed → suspected"""
        verifier = FindingVerifier(scan_id="test-scan-001")
        result = verifier.transition_to_suspected(
            "test-finding-001",
            "observed",
            actor_name="verifier_auto",
            reason="Context indicators present",
        )
        assert result == "suspected"
    
    def test_verifier_can_transition_suspected_to_verified(self):
        """Verifier should be able to transition suspected → verified"""
        verifier = FindingVerifier(scan_id="test-scan-001")
        result = verifier.transition_to_verified(
            "test-finding-001",
            "suspected",
            actor_name="verifier_auto",
            reason="Sensitive data extracted",
        )
        assert result == "verified"
    
    def test_verifier_cannot_skip_to_verified_from_observed(self):
        """Verifier should NOT be able to skip from observed to verified"""
        verifier = FindingVerifier(scan_id="test-scan-001")
        
        with pytest.raises(VerificationError) as exc:
            verifier.transition_to_verified(
                "test-finding-001",
                "observed",  # Starting from observed, not suspected
                actor_name="verifier_auto",
            )
        
        assert "not allowed" in str(exc.value).lower()
    
    def test_verifier_cannot_go_backwards(self):
        """Verifier should NOT be able to go backwards"""
        verifier = FindingVerifier(scan_id="test-scan-001")
        
        # Try to go from suspected back to observed
        with pytest.raises(VerificationError):
            verifier.transition_to_suspected(
                "test-finding-001",
                "suspected",  # Already at suspected
            )


class TestExploitRunnerFinalState:
    """Test Exploit Runner can reach exploited state"""
    
    def test_exploit_runner_can_transition_verified_to_exploited(self):
        """Exploit runner should be able to transition verified → exploited"""
        verifier = FindingVerifier(scan_id="test-scan-001")
        result = verifier.transition_to_exploited(
            "test-finding-001",
            "verified",
            actor_name="exploit_runner_auto",
            reason="Privilege escalation confirmed",
        )
        assert result == "exploited"
    
    def test_exploit_runner_cannot_skip_from_observed(self):
        """Exploit runner should NOT be able to skip to exploited"""
        verifier = FindingVerifier(scan_id="test-scan-001")
        
        with pytest.raises(VerificationError):
            verifier.transition_to_exploited(
                "test-finding-001",
                "observed",  # Starting from observed, not verified
                actor_name="exploit_runner_auto",
            )
    
    def test_exploit_runner_cannot_skip_from_suspected(self):
        """Exploit runner should NOT be able to skip from suspected"""
        verifier = FindingVerifier(scan_id="test-scan-001")
        
        with pytest.raises(VerificationError):
            verifier.transition_to_exploited(
                "test-finding-001",
                "suspected",  # Starting from suspected, not verified
                actor_name="exploit_runner_auto",
            )


class TestManualOverride:
    """Test Manual Override with audit trail"""
    
    def test_manual_override_requires_reason(self):
        """Manual override should fail without reason"""
        verifier = FindingVerifier(scan_id="test-scan-001")
        
        with pytest.raises(VerificationError) as exc:
            verifier.manual_override(
                "test-finding-001",
                "observed",
                "verified",
                actor_name="security_engineer",
                reason="",  # Empty reason
            )
        
        assert "reason" in str(exc.value).lower()
    
    def test_manual_override_requires_actor_name(self):
        """Manual override should fail without actor name"""
        verifier = FindingVerifier(scan_id="test-scan-001")
        
        with pytest.raises(VerificationError) as exc:
            verifier.manual_override(
                "test-finding-001",
                "observed",
                "suspected",
                actor_name="",  # Empty actor
                reason="Manual review determined suspicious",
            )
        
        assert "actor" in str(exc.value).lower()
    
    def test_manual_override_allows_any_transition(self):
        """Manual override should allow any transition with proper audit"""
        verifier = FindingVerifier(scan_id="test-scan-001")
        
        # Skip from observed directly to exploited (normally forbidden)
        result = verifier.manual_override(
            "test-finding-001",
            "observed",
            "exploited",
            actor_name="security_engineer",
            reason="Manual investigation confirmed complete compromise",
        )
        
        assert result == "exploited"
        
        # Verify audit log
        log = verifier.get_transition_log()
        assert len(log) == 1
        assert log[0].actor_type == "manual"
        assert log[0].actor_name == "security_engineer"
        assert log[0].reason == "Manual investigation confirmed complete compromise"
    
    def test_manual_override_logged_with_scan_id(self):
        """Manual override should include scan_id and source_module"""
        verifier = FindingVerifier(scan_id="test-scan-001")
        
        verifier.manual_override(
            "test-finding-001",
            "observed",
            "suspected",
            actor_name="security_engineer",
            reason="Manual review",
        )
        
        log = verifier.get_transition_log()[0]
        assert log.scan_id == "test-scan-001"
        assert log.source_module == "manual_override"


class TestAuditLog:
    """Test audit log completeness"""
    
    def test_transition_log_contains_finding_id(self):
        """Transition log should include finding_id"""
        verifier = FindingVerifier(scan_id="test-scan-001")
        verifier.transition_to_suspected("finding-123", "observed")
        
        log = verifier.get_transition_log()[0]
        assert log.finding_id == "finding-123"
    
    def test_transition_log_contains_scan_id(self):
        """Transition log should include scan_id"""
        verifier = FindingVerifier(scan_id="scan-20260411-001")
        verifier.set_initial_state("finding-001")
        
        log = verifier.get_transition_log()[0]
        assert log.scan_id == "scan-20260411-001"
    
    def test_transition_log_contains_timestamp(self):
        """Transition log should include timestamp"""
        verifier = FindingVerifier(scan_id="test-scan-001")
        verifier.set_initial_state("finding-001")
        
        log = verifier.get_transition_log()[0]
        assert isinstance(log.timestamp, datetime)
    
    def test_transition_log_can_serialize(self):
        """Transition log should serialize to dict"""
        verifier = FindingVerifier(scan_id="test-scan-001")
        verifier.set_initial_state("finding-001")
        
        log_dicts = verifier.get_transition_log_as_dicts()
        assert isinstance(log_dicts, list)
        assert "finding_id" in log_dicts[0]
        assert "timestamp" in log_dicts[0]


class TestCentralizedAPI:
    """Test the centralized transition_finding_state API"""
    
    def test_transition_finding_state_rule_engine(self):
        """Test rule_engine actor type"""
        finding = MockFinding("finding-001")
        
        from postprocess.verifier import transition_finding_state
        
        result = transition_finding_state(
            finding,
            "observed",
            "rule_engine",
            "rule_engine",
            "Initial state",
            scan_id="scan-001",
        )
        
        assert result == "observed"
    
    def test_transition_finding_state_unknown_actor(self):
        """Test unknown actor type raises error"""
        finding = MockFinding("finding-001")
        
        from postprocess.verifier import transition_finding_state
        
        with pytest.raises(VerificationError):
            transition_finding_state(
                finding,
                "verified",
                "unknown_actor",  # Invalid actor type
                "test",
                "test reason",
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])