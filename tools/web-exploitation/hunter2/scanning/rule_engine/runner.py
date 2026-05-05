from __future__ import annotations

import requests
from typing import Optional
from core.session import build_session

from config.config import Config
from core.limiter import GlobalRateLimiter
from scanning.rule_engine.engine import run_rules_concurrent


def run_rules(cfg: Config, rules: list[dict], scan_id: Optional[str] = None) -> list:
    sess = build_session(cfg)
    limiter = GlobalRateLimiter(cfg.qps)

    findings = run_rules_concurrent(
        rules=rules,
        base=cfg.base,
        session=sess,
        limiter=limiter,
        outdir=cfg.outdir,
        timeout=cfg.timeout,
        retries=cfg.retries,
        allow_redirects=cfg.allow_redirects,
        allow_hosts=cfg.allow_hosts,
        allow_suffixes=cfg.allow_suffixes,
        deny_private=cfg.deny_private,
        verbose=cfg.verbose,
        print_matches=cfg.print_matches,
        threads=max(1, int(cfg.threads)),
        max_requests=max(0, int(cfg.max_requests)),
    )
    
    # Inject scan_id into all findings
    for f in findings:
        if scan_id:
            f.scan_id = scan_id
        
        # Also ensure id and title are populated from rule metadata
        if not f.id and f.rule_id:
            f.id = f"finding-{f.rule_id}-{hash(f.url) % 100000}"
        if not f.title and f.name:
            f.title = f.name
    
    return findings