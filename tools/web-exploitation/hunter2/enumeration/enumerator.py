# enumeration/enumerator.py
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Set

import requests
from core.session import build_session

from config.config import Config
from core.limiter import GlobalRateLimiter

from enumeration.discovery import discover_paths
from enumeration.crawler import crawl
from enumeration.seeds import read_seeds_file, normalize_seeds


@dataclass
class TargetSet:
    paths: List[str] = field(default_factory=list)
    js_endpoints: List[str] = field(default_factory=list)


def enumerate_targets(cfg: Config) -> TargetSet:
    sess = build_session(cfg)
    limiter = GlobalRateLimiter(cfg.qps)

    seeds = normalize_seeds((cfg.seeds or []) + read_seeds_file(cfg.seeds_file))

    paths: Set[str] = set()
    js_eps: Set[str] = set()

    if cfg.discover:
        for p in discover_paths(
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
        ):
            paths.add(p)

    if cfg.crawl:
        res = crawl(
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
            seeds=seeds,
            depth=cfg.crawl_depth,
            max_pages=cfg.crawl_max_pages,
        )
        for p in res.paths:
            paths.add(p)
        for p in res.js_endpoints:
            js_eps.add(p)

    # always include user seeds as paths
    for s in seeds:
        paths.add(s)

    return TargetSet(paths=sorted(paths), js_endpoints=sorted(js_eps))