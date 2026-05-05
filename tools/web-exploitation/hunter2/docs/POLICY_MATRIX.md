# Policy Behavior Matrix

## Overview

This document defines how `--policy` affects scanning behavior across all components.

## Policy Comparison Matrix

| Field | safe | balanced | aggressive |
|-------|------|----------|------------|
| **Fuzzing** | | | |
| Fuzzing enabled | off | limited | enabled |
| Fuzz payload count | 10 | 50 | unlimited |
| Fuzz target methods | GET only | GET + POST | All |
| | | | |
| **Chaining** | | | |
| Multi-step chains | disabled | max 2 | unlimited |
| Auth bypass attempts | no | limited | full |
| Chain depth limit | 1 | 2 | 10+ |
| | | | |
| **Verification** | | | |
| Credential extraction | minimal | standard | deep |
| Sensitive data check | secrets only | + config | + PII, keys |
| Response analysis | status | + headers | + timing, redirects |
| Auto-escalate to exploited | no | no | yes |
| | | | |
| **State-Changing** | | | |
| POST/PUT/DELETE | deny | restricted | allowed by rule |
| Parameter pollution | no | limited | yes |
| Header injection | no | limited | yes |
| | | | |
| **Request Budget** | | | |
| Max requests | 50 | 150 | unlimited |
| QPS limit | 0.5 | 2.0 | 5.0 |
| Threads | 1 | 4 | 8 |
| Timeout (sec) | 20 | 12 | 8 |
| Retries | 3 | 1 | 0 |
| | | | |
| **Verification Cap** | | | |
| Max findings to verify | 5 | 20 | unlimited |
| Verification timeout | 30s | 60s | 120s |

## Policy-Specific Behavior Details

### Safe Policy
```yaml
safe:
  description: "Minimal impact, suitable for production environments"
  rules:
    - No destructive payloads
    - No state-changing requests (POST/PUT/DELETE) unless explicitly allowed in rule
    - Lower concurrency (1 thread, 0.5 QPS)
    - Longer timeouts for stability
    - Cap verification attempts at 5
    - No chaining - only single-step detection
    - Limited fuzzing (top 10 payloads only)
  use_cases:
    - Scanning production systems
    - Quick smoke tests
    - CI/CD pipelines requiring minimal noise
  cli_defaults:
    qps: 0.5
    threads: 1
    timeout: 20
    retries: 3
    max_requests: 50
    fuzzing: false
    chaining: false
```

### Balanced Policy
```yaml
balanced:
  description: "Standard scanning, reasonable coverage with moderate impact"
  rules:
    - Moderate fuzzing with standard payloads
    - Limited chaining (max 2 steps)
    - Restricted state-changing (some POST allowed with safe params)
    - Standard concurrency (4 threads, 2 QPS)
    - 20 verification attempts max
  use_cases:
    - Regular security assessments
    - Staging environment scans
    - Standard pentests
  cli_defaults:
    qps: 2.0
    threads: 4
    timeout: 12
    retries: 1
    max_requests: 150
    fuzzing: true
    chaining: true
    max_chaining: 2
```

### Aggressive Policy
```yaml
aggressive:
  description: "Full testing, maximum coverage with higher impact"
  rules:
    - Full fuzzing with all payloads and mutations
    - Unlimited chaining depth
    - All state-changing requests allowed where rule permits
    - High concurrency (8 threads, 5 QPS)
    - Unlimited verification
    - Auto-escalate to exploited when conditions met
  use_cases:
    - Capture-the-flag environments
    - Full scope pentests
    - Deep security assessments
  cli_defaults:
    qps: 5.0
    threads: 8
    timeout: 8
    retries: 0
    max_requests: 0  # unlimited
    fuzzing: true
    chaining: true
    max_chaining: 99
    auto_escalate: true
```

## Implementation in ScanConfig

```python
@dataclass
class ScanConfig:
    policy: str = "balanced"
    
    # Derived from policy
    fuzzing_enabled: bool = True
    fuzz_payload_limit: int = 50
    chaining_enabled: bool = True
    max_chaining_depth: int = 2
    
    # Concurrency
    qps: float = 2.0
    threads: int = 4
    timeout: float = 12.0
    retries: int = 1
    max_requests: int = 150
    
    # State-changing
    allow_post: str = "restricted"  # "deny", "restricted", "allow"
    allow_parameter_pollution: bool = False
    allow_header_injection: bool = False
    
    # Verification
    verification_depth: str = "medium"  # "low", "medium", "high"
    max_verifications: int = 20
    auto_escalate_to_exploited: bool = False


def apply_policy_to_config(cfg: ScanConfig) -> ScanConfig:
    if cfg.policy == "safe":
        cfg.fuzzing_enabled = False
        cfg.chaining_enabled = False
        cfg.max_chaining_depth = 1
        cfg.qps = 0.5
        cfg.threads = 1
        cfg.timeout = 20.0
        cfg.retries = 3
        cfg.max_requests = 50
        cfg.allow_post = "deny"
        cfg.verification_depth = "low"
        cfg.max_verifications = 5
    elif cfg.policy == "aggressive":
        cfg.fuzzing_enabled = True
        cfg.chaining_enabled = True
        cfg.max_chaining_depth = 99
        cfg.qps = 5.0
        cfg.threads = 8
        cfg.timeout = 8.0
        cfg.retries = 0
        cfg.max_requests = 0  # unlimited
        cfg.allow_post = "allow"
        cfg.verification_depth = "high"
        cfg.max_verifications = 0  # unlimited
        cfg.auto_escalate_to_exploited = True
    # balanced is default
    return cfg
```

## Environment-Specific Defaults

| Environment | Recommended Policy | Reason |
|-------------|-------------------|--------|
| dev | aggressive | Can tolerate impact, need full coverage |
| staging | balanced | Limited impact tolerance |
| prod | safe | Zero tolerance for disruption |
| unknown | balanced | Default safe-ish option |

## Custom Policy Extension

```yaml
# In hunter.yaml
policy:
  name: "custom-audit"
  description: "Compliance audit mode"
  fuzzing_enabled: true
  fuzz_payload_limit: 30
  chaining_enabled: true
  max_chaining_depth: 1
  qps: 1.0
  threads: 2
  timeout: 15
  max_requests: 100
  allow_post: "deny"
  verification_depth: "high"
  max_verifications: 50
```