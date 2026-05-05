# config/validation.py
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List, Tuple
from urllib.parse import urlparse

from config.config import Config


@dataclass
class ValidationIssue:
    level: str   # "error" | "warn"
    message: str


def _is_url_like(base: str) -> bool:
    try:
        u = urlparse(base)
        return bool(u.scheme and u.netloc)
    except Exception:
        return False


def validate_config(cfg: Config) -> Tuple[bool, List[ValidationIssue]]:
    issues: List[ValidationIssue] = []

    # base url
    if not cfg.base or not _is_url_like(cfg.base):
        issues.append(ValidationIssue("error", f"Invalid base URL: {cfg.base!r}"))

    # paths
    if cfg.rules_dir and not os.path.isdir(cfg.rules_dir):
        issues.append(ValidationIssue("error", f"Rules dir not found: {cfg.rules_dir}"))
    if cfg.fingerprints_dir and not os.path.isdir(cfg.fingerprints_dir):
        issues.append(ValidationIssue("warn", f"Fingerprints dir not found: {cfg.fingerprints_dir}"))
    if cfg.payload_dir and not os.path.isdir(cfg.payload_dir):
        issues.append(ValidationIssue("warn", f"Payload dir not found: {cfg.payload_dir}"))

    # numeric bounds
    if cfg.qps < 0:
        issues.append(ValidationIssue("error", f"qps must be >= 0, got {cfg.qps}"))
    if cfg.timeout <= 0:
        issues.append(ValidationIssue("error", f"timeout must be > 0, got {cfg.timeout}"))
    if cfg.retries < 0:
        issues.append(ValidationIssue("error", f"retries must be >= 0, got {cfg.retries}"))
    if cfg.threads <= 0:
        issues.append(ValidationIssue("error", f"threads must be >= 1, got {cfg.threads}"))
    if cfg.max_requests < 0:
        issues.append(ValidationIssue("error", f"max_requests must be >= 0, got {cfg.max_requests}"))
    if cfg.crawl_depth < 0:
        issues.append(ValidationIssue("error", f"crawl_depth must be >= 0, got {cfg.crawl_depth}"))
    if cfg.crawl_max_pages <= 0:
        issues.append(ValidationIssue("error", f"crawl_max_pages must be >= 1, got {cfg.crawl_max_pages}"))

    # fuzz safety
    if cfg.fuzz_sets and not cfg.fuzz_targets:
        issues.append(ValidationIssue("warn", "Fuzz enabled but no --fuzz-target provided; fuzz will do nothing."))
    if cfg.fuzz_targets and not cfg.fuzz_sets:
        issues.append(ValidationIssue("warn", "Fuzz targets provided but no --fuzz set provided; fuzz will do nothing."))

    ok = not any(i.level == "error" for i in issues)
    return ok, issues