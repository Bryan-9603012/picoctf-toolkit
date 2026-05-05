# config/config.py
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Config:
    base: str

    rules_dir: str = "rules"
    outdir: str = "loot"
    report: str = "report"
    pack: str = "auto"

    qps: float = 2.0
    timeout: float = 12.0
    retries: int = 1
    threads: int = 5
    max_requests: int = 0

    allow_hosts: List[str] = field(default_factory=list)
    allow_suffixes: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=list)
    deny_private: bool = False
    allow_redirects: bool = True

    verbose: bool = False
    print_matches: bool = False

    # enumeration
    discover: bool = False
    crawl: bool = False
    crawl_depth: int = 2
    crawl_max_pages: int = 60
    seeds: List[str] = field(default_factory=list)
    seeds_file: str = ""

    # scanning
    passive: bool = False

    fuzz_sets: List[str] = field(default_factory=list)
    fuzz_targets: List[str] = field(default_factory=list)
    payload_dir: str = "payloads"

    fingerprints_dir: str = "fingerprints"

    # artifact analysis
    artifact_analysis: bool = True
    save_artifacts: bool = True
    max_artifact_bytes: int = 10 * 1024 * 1024
    artifact_outdir: str = ""

    # HTTP options
    extra_headers: List[str] = field(default_factory=list)
    cookie: str = ""
    bearer: str = ""
    proxy: str = ""
    insecure: bool = False

    # pipeline options
    dry_run: bool = False
    stop_on_high_confidence: bool = False

    # --- Enterprise features ---
    policy: str = "balanced"
    environment: str = "unknown"
    
    # Policy behavior derived fields
    fuzzing_enabled: bool = True
    fuzz_payload_limit: int = 50
    chaining_enabled: bool = True
    max_chaining_depth: int = 2
    allow_post: str = "restricted"  # "deny", "restricted", "allow"
    allow_parameter_pollution: bool = False
    allow_header_injection: bool = False
    verification_depth: str = "medium"  # "low", "medium", "high"
    max_verifications: int = 20
    auto_trigger_exploit_runner: bool = False  # Whether to attempt exploitation after verified
    
    # CI integration
    fail_on_severity: Optional[str] = None
    fail_verified_only: bool = False
    fail_exploited_only: bool = False
    
    # Workflow
    baseline_scan_id: Optional[str] = None
    suppressions: List[str] = field(default_factory=list)
    scan_id: Optional[str] = None  # Current scan identifier
    baseline: str = ""
