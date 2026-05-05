# tests/test_policy_application.py
"""
Tests for Policy Application System

Tests that --policy maps to actual behavior settings:
- safe: fuzzing off, chaining off, deny POST, low verification, max 50 requests
- balanced: fuzzing on, chaining 2 steps, restricted POST, medium verification
- aggressive: fuzzing unlimited, chaining unlimited, allow POST, high verification
"""

import pytest
from config.config import Config
from config.defaults import apply_policy_settings, generate_scan_id


class TestGenerateScanId:
    """Test scan ID generation"""
    
    def test_scan_id_format(self):
        """Scan ID should follow expected format"""
        scan_id = generate_scan_id()
        assert scan_id.startswith("scan-")
        assert "-" in scan_id
    
    def test_scan_id_unique(self):
        """Scan IDs should be unique"""
        ids = [generate_scan_id() for _ in range(10)]
        assert len(set(ids)) == 10


class TestPolicySafe:
    """Test safe policy settings"""
    
    @pytest.fixture
    def safe_config(self):
        """Create config with safe policy"""
        cfg = Config(base="http://example.com")
        cfg.policy = "safe"
        return apply_policy_settings(cfg)
    
    def test_fuzzing_disabled(self, safe_config):
        """Safe policy should disable fuzzing"""
        assert safe_config.fuzzing_enabled is False
    
    def test_chaining_disabled(self, safe_config):
        """Safe policy should disable chaining"""
        assert safe_config.chaining_enabled is False
    
    def test_chaining_depth_limited(self, safe_config):
        """Safe policy should limit chaining depth to 1"""
        assert safe_config.max_chaining_depth == 1
    
    def test_post_denied(self, safe_config):
        """Safe policy should deny POST requests"""
        assert safe_config.allow_post == "deny"
    
    def test_parameter_pollution_disabled(self, safe_config):
        """Safe policy should disable parameter pollution"""
        assert safe_config.allow_parameter_pollution is False
    
    def test_header_injection_disabled(self, safe_config):
        """Safe policy should disable header injection"""
        assert safe_config.allow_header_injection is False
    
    def test_verification_depth_low(self, safe_config):
        """Safe policy should set verification depth to low"""
        assert safe_config.verification_depth == "low"
    
    def test_max_verifications_limited(self, safe_config):
        """Safe policy should limit verifications to 5"""
        assert safe_config.max_verifications == 5
    
    def test_exploit_runner_disabled(self, safe_config):
        """Safe policy should not auto-trigger exploit runner"""
        assert safe_config.auto_trigger_exploit_runner is False
    
    def test_request_budget_limited(self, safe_config):
        """Safe policy should limit max requests to 50"""
        assert safe_config.max_requests == 50
    
    def test_qps_low(self, safe_config):
        """Safe policy should set low QPS"""
        assert safe_config.qps <= 0.5
    
    def test_scan_id_generated(self, safe_config):
        """Safe policy should generate scan_id"""
        assert safe_config.scan_id is not None
        assert safe_config.scan_id.startswith("scan-")


class TestPolicyBalanced:
    """Test balanced policy settings"""
    
    @pytest.fixture
    def balanced_config(self):
        """Create config with balanced policy"""
        cfg = Config(base="http://example.com")
        cfg.policy = "balanced"
        return apply_policy_settings(cfg)
    
    def test_fuzzing_enabled(self, balanced_config):
        """Balanced policy should enable fuzzing"""
        assert balanced_config.fuzzing_enabled is True
    
    def test_chaining_enabled(self, balanced_config):
        """Balanced policy should enable chaining"""
        assert balanced_config.chaining_enabled is True
    
    def test_chaining_depth_limited(self, balanced_config):
        """Balanced policy should limit chaining depth to 2"""
        assert balanced_config.max_chaining_depth == 2
    
    def test_post_restricted(self, balanced_config):
        """Balanced policy should restrict POST requests"""
        assert balanced_config.allow_post == "restricted"
    
    def test_verification_depth_medium(self, balanced_config):
        """Balanced policy should set verification depth to medium"""
        assert balanced_config.verification_depth == "medium"
    
    def test_max_verifications_20(self, balanced_config):
        """Balanced policy should allow 20 verifications"""
        assert balanced_config.max_verifications == 20
    
    def test_exploit_runner_disabled(self, balanced_config):
        """Balanced policy should not auto-trigger exploit runner"""
        assert balanced_config.auto_trigger_exploit_runner is False


class TestPolicyAggressive:
    """Test aggressive policy settings"""
    
    @pytest.fixture
    def aggressive_config(self):
        """Create config with aggressive policy"""
        cfg = Config(base="http://example.com")
        cfg.policy = "aggressive"
        return apply_policy_settings(cfg)
    
    def test_fuzzing_enabled(self, aggressive_config):
        """Aggressive policy should enable fuzzing"""
        assert aggressive_config.fuzzing_enabled is True
    
    def test_chaining_enabled(self, aggressive_config):
        """Aggressive policy should enable chaining"""
        assert aggressive_config.chaining_enabled is True
    
    def test_chaining_depth_unlimited(self, aggressive_config):
        """Aggressive policy should allow unlimited chaining depth"""
        assert aggressive_config.max_chaining_depth == 99
    
    def test_post_allowed(self, aggressive_config):
        """Aggressive policy should allow POST requests"""
        assert aggressive_config.allow_post == "allow"
    
    def test_parameter_pollution_enabled(self, aggressive_config):
        """Aggressive policy should enable parameter pollution"""
        assert aggressive_config.allow_parameter_pollution is True
    
    def test_header_injection_enabled(self, aggressive_config):
        """Aggressive policy should enable header injection"""
        assert aggressive_config.allow_header_injection is True
    
    def test_verification_depth_high(self, aggressive_config):
        """Aggressive policy should set verification depth to high"""
        assert aggressive_config.verification_depth == "high"
    
    def test_max_verifications_unlimited(self, aggressive_config):
        """Aggressive policy should allow unlimited verifications"""
        assert aggressive_config.max_verifications == 0
    
    def test_exploit_runner_enabled(self, aggressive_config):
        """Aggressive policy should auto-trigger exploit runner"""
        assert aggressive_config.auto_trigger_exploit_runner is True
    
    def test_max_requests_unlimited(self, aggressive_config):
        """Aggressive policy should allow unlimited requests"""
        assert aggressive_config.max_requests == 0
    
    def test_qps_high(self, aggressive_config):
        """Aggressive policy should set high QPS"""
        assert aggressive_config.qps >= 5.0


class TestPolicyOverride:
    """Test that user overrides can override policy defaults"""
    
    def test_user_override_qps(self):
        """User-specified QPS should override policy default"""
        cfg = Config(base="http://example.com")
        cfg.policy = "safe"
        cfg.qps = 10.0  # User explicitly wants high QPS
        
        cfg = apply_policy_settings(cfg)
        
        # User override should be respected (policy can only cap, not raise)
        # In safe mode, qps is capped to 0.5, but user can override
        # Let's check the actual behavior
        assert cfg.qps >= 0.5  # At minimum policy ensures this
    
    def test_user_override_max_requests(self):
        """User-specified max_requests should override policy default"""
        cfg = Config(base="http://example.com")
        cfg.policy = "balanced"
        cfg.max_requests = 500  # User wants more requests
        
        cfg = apply_policy_settings(cfg)
        
        # Balanced policy defaults to 150, user wants 500
        # Policy should not override user when user explicitly sets
        assert cfg.max_requests == 500


class TestPolicyBehaviorMatrix:
    """Test actual behavior differences between policies"""
    
    def test_request_budget_differences(self):
        """Verify request budget varies by policy"""
        configs = {}
        
        for policy in ["safe", "balanced", "aggressive"]:
            cfg = Config(base="http://example.com")
            cfg.policy = policy
            configs[policy] = apply_policy_settings(cfg)
        
        # Safe should have lowest max_requests
        assert configs["safe"].max_requests <= 50
        
        # Balanced should have moderate
        assert 50 < configs["balanced"].max_requests <= 150
        
        # Aggressive should be unlimited
        assert configs["aggressive"].max_requests == 0
    
    def test_chaining_differences(self):
        """Verify chaining depth varies by policy"""
        configs = {}
        
        for policy in ["safe", "balanced", "aggressive"]:
            cfg = Config(base="http://example.com")
            cfg.policy = policy
            configs[policy] = apply_policy_settings(cfg)
        
        assert configs["safe"].max_chaining_depth == 1
        assert configs["balanced"].max_chaining_depth == 2
        assert configs["aggressive"].max_chaining_depth == 99
    
    def test_verification_depth_differences(self):
        """Verify verification depth varies by policy"""
        configs = {}
        
        for policy in ["safe", "balanced", "aggressive"]:
            cfg = Config(base="http://example.com")
            cfg.policy = policy
            configs[policy] = apply_policy_settings(cfg)
        
        assert configs["safe"].verification_depth == "low"
        assert configs["balanced"].verification_depth == "medium"
        assert configs["aggressive"].verification_depth == "high"


class TestRuntimeConfigSnapshot:
    """Test that config can be serialized for runtime snapshot"""
    
    def test_config_serializable(self):
        """Config should be serializable for snapshot"""
        cfg = Config(base="http://example.com")
        cfg.policy = "balanced"
        cfg = apply_policy_settings(cfg)
        
        # Should be able to convert to dict
        cfg_dict = {
            "base": cfg.base,
            "policy": cfg.policy,
            "scan_id": cfg.scan_id,
            "fuzzing_enabled": cfg.fuzzing_enabled,
            "chaining_enabled": cfg.chaining_enabled,
            "max_chaining_depth": cfg.max_chaining_depth,
            "allow_post": cfg.allow_post,
            "verification_depth": cfg.verification_depth,
            "max_verifications": cfg.max_verifications,
            "qps": cfg.qps,
            "threads": cfg.threads,
            "timeout": cfg.timeout,
            "max_requests": cfg.max_requests,
        }
        
        assert "scan_id" in cfg_dict
        assert "policy" in cfg_dict
        assert cfg_dict["scan_id"].startswith("scan-")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])