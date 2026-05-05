# scanning/fuzz/runner.py
from __future__ import annotations

import requests

from config.config import Config
from core.limiter import GlobalRateLimiter
from scanning.fuzz.fuzz import fuzz_one
from scanning.fuzz.payload_loader import load_payloads
from scanning.fuzz.targets import FuzzTarget


def run_fuzz(cfg: Config) -> list:
    if not cfg.fuzz_targets or not cfg.fuzz_sets:
        return []

    # safety: fuzz only runs when user explicitly provides targets + sets
    payload_db = load_payloads(cfg.payload_dir)

    sess = requests.Session()
    sess.headers.update({"User-Agent": "hunter/2.0 (authorized scanning)", "Accept": "*/*"})
    limiter = GlobalRateLimiter(cfg.qps)

    findings = []
    for tpl in cfg.fuzz_targets:
        for s in cfg.fuzz_sets:
            if s not in payload_db:
                if cfg.verbose:
                    print(f"[!] [fuzz] payload set not found: {s}")
                continue
            target = FuzzTarget(template_path=tpl, payload_set=s, method="GET")
            findings.extend(
                fuzz_one(
                    base=cfg.base,
                    session=sess,
                    limiter=limiter,
                    timeout=cfg.timeout,
                    retries=cfg.retries,
                    allow_redirects=cfg.allow_redirects,
                    allow_hosts=cfg.allow_hosts,
                    allow_suffixes=cfg.allow_suffixes,
                    deny_private=cfg.deny_private,
                    verbose=cfg.verbose,
                    target=target,
                    payloads=payload_db[s].items,
                    max_tries=60,
                )
            )
    return findings