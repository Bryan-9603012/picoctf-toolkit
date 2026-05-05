# config/defaults.py
from __future__ import annotations

from urllib.parse import urlparse
from datetime import datetime
from uuid import uuid4

from config.config import Config


def normalize_base(base: str) -> str:
    base = base.strip()
    if not (base.startswith("http://") or base.startswith("https://")):
        base = "http://" + base
    return base.rstrip("/")


def generate_scan_id() -> str:
    """Generate unique scan ID"""
    ts = datetime.utcnow().strftime('%Y%m%d-%H%M%S-%f')
    return f"scan-{ts}-{uuid4().hex[:6]}"


def apply_policy_settings(cfg: Config | str):
    """
    Apply policy-specific settings to config.
    This maps --policy to actual behavior settings.
    """
    if isinstance(cfg, str):
        tmp = Config(base="http://example.com")
        tmp.policy = cfg
        return apply_policy_settings(tmp).__dict__

    policy = (cfg.policy or "balanced").lower()
    if policy not in {"safe", "balanced", "aggressive"}:
        policy = "balanced"
    
    if policy == "safe":
        cfg.fuzzing_enabled = False
        cfg.chaining_enabled = False
        cfg.max_chaining_depth = 1
        cfg.qps = min(cfg.qps, 0.5)
        cfg.threads = min(cfg.threads, 1)
        cfg.timeout = max(cfg.timeout, 20.0)
        cfg.retries = max(cfg.retries, 3)
        cfg.max_requests = min(cfg.max_requests, 50) if cfg.max_requests > 0 else 50
        cfg.allow_post = "deny"
        cfg.allow_parameter_pollution = False
        cfg.allow_header_injection = False
        cfg.verification_depth = "low"
        cfg.max_verifications = 5
        cfg.auto_trigger_exploit_runner = False
        cfg.fuzz_payload_limit = 10
        
    elif policy == "aggressive":
        cfg.fuzzing_enabled = True
        cfg.chaining_enabled = True
        cfg.max_chaining_depth = 99
        cfg.qps = max(cfg.qps, 5.0)
        cfg.threads = max(cfg.threads, 8)
        cfg.timeout = min(cfg.timeout, 8.0)
        cfg.retries = 0
        cfg.max_requests = 0  # unlimited
        cfg.allow_post = "allow"
        cfg.allow_parameter_pollution = True
        cfg.allow_header_injection = True
        cfg.verification_depth = "high"
        cfg.max_verifications = 0  # unlimited
        cfg.auto_trigger_exploit_runner = True
        cfg.fuzz_payload_limit = 0  # unlimited
        
    else:  # balanced (default)
        cfg.fuzzing_enabled = True
        cfg.chaining_enabled = True
        cfg.max_chaining_depth = 2
        cfg.allow_post = "restricted"
        cfg.allow_parameter_pollution = False
        cfg.allow_header_injection = False
        cfg.verification_depth = "medium"
        cfg.max_verifications = 20
        cfg.auto_trigger_exploit_runner = False
        cfg.fuzz_payload_limit = 50
        if cfg.max_requests == 0:
            cfg.max_requests = 100
    
    # Generate scan_id for this session
    cfg.scan_id = generate_scan_id()
    
    return cfg


def default_config(args) -> Config:
    base = normalize_base(args.base)
    cfg = Config(base=base)

    cfg.pack = args.pack
    cfg.rules_dir = args.rules_dir
    cfg.outdir = args.outdir
    cfg.report = args.report

    cfg.qps = float(args.qps)
    cfg.timeout = float(args.timeout)
    cfg.retries = int(args.retries)
    cfg.threads = int(args.threads)
    cfg.max_requests = int(args.max_requests)

    cfg.allow_hosts = list(args.allow_host or [])
    cfg.allow_suffixes = list(args.allow_suffix or [])
    cfg.deny_private = bool(args.deny_private)
    cfg.allow_redirects = not bool(args.no_redirects)

    cfg.verbose = bool(args.verbose)
    cfg.print_matches = bool(args.print_matches)

    cfg.discover = bool(args.discover)
    cfg.crawl = bool(args.crawl)
    cfg.crawl_depth = int(args.crawl_depth)
    cfg.crawl_max_pages = int(args.crawl_max_pages)

    cfg.seeds = list(args.seed or [])
    cfg.seeds_file = str(args.seeds_file or "")

    cfg.passive = bool(args.passive)

    cfg.fuzz_sets = list(args.fuzz or [])
    cfg.fuzz_targets = list(args.fuzz_target or [])
    cfg.payload_dir = str(args.payload_dir or "payloads")

    # --- NEW: pentest essentials ---
    cfg.extra_headers = list(getattr(args, "header", []) or [])
    cfg.cookie = str(getattr(args, "cookie", "") or "")
    cfg.bearer = str(getattr(args, "bearer", "") or "")
    cfg.proxy = str(getattr(args, "proxy", "") or "")
    cfg.insecure = bool(getattr(args, "insecure", False))

    # --- Enterprise features ---
    cfg.policy = str(getattr(args, "policy", "balanced") or "balanced")
    cfg.environment = str(getattr(args, "env", "unknown") or "unknown")
    
    cfg.fail_on_severity = str(getattr(args, "fail_on", "") or "") or None
    cfg.fail_verified_only = bool(getattr(args, "fail_verified_only", False))
    cfg.fail_exploited_only = bool(getattr(args, "fail_exploited_only", False))
    
    cfg.exclude_patterns = list(getattr(args, "exclude", []) or [])
    cfg.baseline = str(getattr(args, "baseline", "") or "")
    cfg.suppressions = str(getattr(args, "suppressions", "") or "")
    
    # Apply policy behavior settings
    cfg = apply_policy_settings(cfg)

    # safety: if user didn't set allow_hosts/suffixes, allow base host implicitly
    try:
        u = urlparse(cfg.base)
        if u.hostname and (not cfg.allow_hosts and not cfg.allow_suffixes):
            cfg.allow_hosts = [u.hostname]
    except Exception:
        pass

    return cfg