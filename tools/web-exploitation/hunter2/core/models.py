# core/models.py
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum
from datetime import datetime

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def severity_rank(sev: str) -> int:
    sev = (sev or "").strip().lower()
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return 0


class Confidence(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class VerificationState(Enum):
    OBSERVED = "observed"
    SUSPECTED = "suspected"
    VERIFIED = "verified"
    EXPLOITED = "exploited"


class ScanPolicy(Enum):
    SAFE = "safe"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"


class TargetEnvironment(Enum):
    DEV = "dev"
    STAGING = "staging"
    PROD = "prod"
    UNKNOWN = "unknown"


@dataclass
class Evidence:
    method: str = "GET"
    url: str = ""
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    content_length: int = 0
    elapsed_ms: Optional[float] = None
    snippet: Optional[str] = None
    artifact: Optional[str] = None
    scope_reason: Optional[str] = None
    
    request_body: Optional[str] = None
    response_body: Optional[str] = None
    response_headers: Optional[Dict[str, str]] = None
    matched_pattern: Optional[str] = None
    timestamp: Optional[datetime] = None


@dataclass
class Artifact:
    path: str
    original_url: str
    file_type: str = ""
    mime_type: str = ""
    size: int = 0
    magic_bytes: str = ""
    extracted_secrets: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    nested_artifacts: List[str] = field(default_factory=list)
    analysis_status: str = "pending"


@dataclass
class ChainStep:
    finding_id: str
    rule_id: str
    url: str
    action: str
    result: str


@dataclass
class Target:
    url: str
    environment: str = "unknown"
    tags: List[str] = field(default_factory=list)
    
    allow_hosts: List[str] = field(default_factory=list)
    allow_suffixes: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=list)
    
    policy: str = "balanced"
    
    resolved_ips: List[str] = field(default_factory=list)
    final_url: Optional[str] = None
    
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanConfig:
    base_url: str
    
    targets: List[str] = field(default_factory=list)
    scope_hosts: List[str] = field(default_factory=list)
    scope_suffixes: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=list)
    
    environment: str = "unknown"
    policy: str = "balanced"
    
    allow_hosts: List[str] = field(default_factory=list)
    allow_suffixes: List[str] = field(default_factory=list)
    deny_private: bool = False
    
    max_requests: int = 0
    qps: float = 2.0
    timeout: float = 12.0
    retries: int = 1
    threads: int = 5
    
    safe_mode: bool = False
    verify_findings: bool = True
    
    fail_on_severity: Optional[str] = None
    fail_on_verified_only: bool = False
    fail_on_exploited_only: bool = False
    
    baseline_scan_id: Optional[str] = None
    suppressions: List[str] = field(default_factory=list)


@dataclass
class Finding:
    id: str = ""
    rule_id: str = ""
    title: str = ""
    name: str = ""
    category: str = ""
    severity: str = "medium"
    confidence: str = "medium"
    
    url: str = ""
    affected_asset: str = ""
    
    verification_state: str = "observed"
    
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    description: Optional[str] = None
    
    evidence: Optional[Evidence] = None
    
    matches: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    
    preconditions: List[str] = field(default_factory=list)
    safe_check: Optional[str] = None
    verify_check: Optional[str] = None
    evidence_type: Optional[str] = None
    
    extracted_data: Dict[str, Any] = field(default_factory=dict)
    chain: List[ChainStep] = field(default_factory=list)
    related_artifacts: List[str] = field(default_factory=list)
    clues: List[str] = field(default_factory=list)
    
    variables: Dict[str, Any] = field(default_factory=dict)
    risk_score: int = 0
    
    exploitability: Optional[str] = None
    reproduction_steps: List[str] = field(default_factory=list)
    exploit_chain: List[str] = field(default_factory=list)
    
    scan_id: Optional[str] = None
    discovered_at: Optional[datetime] = None
    verified_at: Optional[datetime] = None
    
    source_rule_pack: Optional[str] = None
    remediation_draft: Optional[str] = None

    def compute_risk_score(
        self,
        chain_bonus: int = 0,
        credential_bonus: int = 0,
        sensitive_artifact_bonus: int = 0,
    ) -> int:
        base = (severity_rank(self.severity) + 1) * 20
        base += min(10, len(self.matches))
        
        evidence = self.evidence
        if evidence and getattr(evidence, "artifact", None):
            base += 10 + sensitive_artifact_bonus
        if evidence and getattr(evidence, "snippet", None):
            base += 5
        if self.extracted_data:
            data_keys = " ".join(str(k).lower() for k in self.extracted_data.keys())
            if self.extracted_data.get("credential") or any(k in data_keys for k in ["password", "token", "secret", "key", "auth"]):
                base += credential_bonus
        if self.chain:
            base += chain_bonus * len(self.chain)
            
        self.risk_score = base
        return base

    def set_confidence(self, confidence: str) -> None:
        if confidence in ["low", "medium", "high"]:
            self.confidence = confidence


@dataclass
class PipelineState:
    base_url: str
    targets: List[str] = field(default_factory=list)
    fingerprints: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    artifacts: List[Artifact] = field(default_factory=list)
    chains: List[List[Finding]] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    clues: List[str] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    
    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
    
    def add_artifact(self, artifact: Artifact) -> None:
        self.artifacts.append(artifact)
    
    def get_finding_by_url(self, url: str) -> List[Finding]:
        return [f for f in self.findings if f.url == url]
    
    def get_artifacts_by_type(self, file_type: str) -> List[Artifact]:
        return [a for a in self.artifacts if a.file_type == file_type]
