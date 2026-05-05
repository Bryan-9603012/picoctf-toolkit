# config/yaml_config.py
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


DEFAULT_CONFIG_FILE = "hunter.yaml"
DEFAULT_CONFIG_FILE_ALT = "hunter.yml"


@dataclass
class YAMLConfig:
    target: str = ""
    mode: str = ""
    
    pack: str = "auto"
    rules_dir: str = "rules"
    outdir: str = "loot"
    report: str = "report"
    
    speed: str = "medium"
    qps: float = 2.0
    timeout: float = 12.0
    retries: int = 1
    threads: int = 5
    max_requests: int = 0
    
    allow_hosts: List[str] = field(default_factory=list)
    allow_suffixes: List[str] = field(default_factory=list)
    deny_private: bool = False
    allow_redirects: bool = True
    
    verbose: bool = False
    print_matches: bool = False
    
    discover: bool = False
    crawl: bool = False
    crawl_depth: int = 2
    crawl_max_pages: int = 60
    seeds: List[str] = field(default_factory=list)
    
    passive: bool = False
    fuzz: List[str] = field(default_factory=list)
    fuzz_targets: List[str] = field(default_factory=list)
    payload_dir: str = "payloads"
    
    artifact_analysis: bool = True
    save_artifacts: bool = True
    max_artifact_mb: int = 10
    
    html: bool = False
    dry_run: bool = False
    stop_on_high_confidence: bool = False
    
    headers: Dict[str, str] = field(default_factory=dict)
    cookie: str = ""
    bearer: str = ""
    proxy: str = ""
    insecure: bool = False


def find_config_file(start_dir: str = ".") -> Optional[str]:
    search_dirs = [start_dir, os.getcwd()]
    
    for d in search_dirs:
        for fname in [DEFAULT_CONFIG_FILE, DEFAULT_CONFIG_FILE_ALT]:
            path = os.path.join(d, fname)
            if os.path.exists(path):
                return path
        
        parent = os.path.dirname(d)
        if parent and parent != d:
            for fname in [DEFAULT_CONFIG_FILE, DEFAULT_CONFIG_FILE_ALT]:
                path = os.path.join(parent, fname)
                if os.path.exists(path):
                    return path
    
    return None


def load_yaml_config(config_path: str) -> YAMLConfig:
    if not os.path.exists(config_path):
        return YAMLConfig()
    
    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    
    return YAMLConfig(
        target=data.get("target", ""),
        mode=data.get("mode", ""),
        pack=data.get("pack", "auto"),
        rules_dir=data.get("rules_dir", "rules"),
        outdir=data.get("outdir", "loot"),
        report=data.get("report", "report"),
        speed=data.get("speed", "medium"),
        qps=data.get("qps", 2.0),
        timeout=data.get("timeout", 12.0),
        retries=data.get("retries", 1),
        threads=data.get("threads", 5),
        max_requests=data.get("max_requests", 0),
        allow_hosts=data.get("allow_hosts", []),
        allow_suffixes=data.get("allow_suffixes", []),
        deny_private=data.get("deny_private", False),
        allow_redirects=data.get("allow_redirects", True),
        verbose=data.get("verbose", False),
        print_matches=data.get("print_matches", False),
        discover=data.get("discover", False),
        crawl=data.get("crawl", False),
        crawl_depth=data.get("crawl_depth", 2),
        crawl_max_pages=data.get("crawl_max_pages", 60),
        seeds=data.get("seeds", []),
        passive=data.get("passive", False),
        fuzz=data.get("fuzz", []),
        fuzz_targets=data.get("fuzz_targets", []),
        payload_dir=data.get("payload_dir", "payloads"),
        artifact_analysis=data.get("artifact_analysis", True),
        save_artifacts=data.get("save_artifacts", True),
        max_artifact_mb=data.get("max_artifact_mb", 10),
        html=data.get("html", False),
        dry_run=data.get("dry_run", False),
        stop_on_high_confidence=data.get("stop_on_high_confidence", False),
        headers=data.get("headers", {}),
        cookie=data.get("cookie", ""),
        bearer=data.get("bearer", ""),
        proxy=data.get("proxy", ""),
        insecure=data.get("insecure", False),
    )


def merge_yaml_to_args(yaml_config: YAMLConfig, args) -> None:
    if not hasattr(args, "base") or not args.base:
        if yaml_config.target:
            args.base = yaml_config.target
    
    if yaml_config.mode:
        args.mode = yaml_config.mode
    
    if hasattr(args, "pack") and args.pack == "auto":
        args.pack = yaml_config.pack
    
    if hasattr(args, "rules_dir") and args.rules_dir == "rules":
        args.rules_dir = yaml_config.rules_dir
    
    if hasattr(args, "outdir") and args.outdir == "loot":
        args.outdir = yaml_config.outdir
    
    if hasattr(args, "report") and args.report == "report":
        args.report = yaml_config.report
    
    if hasattr(args, "qps"):
        args.qps = yaml_config.qps
    if hasattr(args, "timeout"):
        args.timeout = yaml_config.timeout
    if hasattr(args, "retries"):
        args.retries = yaml_config.retries
    if hasattr(args, "threads"):
        args.threads = yaml_config.threads
    if hasattr(args, "max_requests"):
        args.max_requests = yaml_config.max_requests
    
    if hasattr(args, "allow_host"):
        args.allow_host = yaml_config.allow_hosts
    if hasattr(args, "allow_suffix"):
        args.allow_suffix = yaml_config.allow_suffixes
    
    if hasattr(args, "deny_private"):
        args.deny_private = yaml_config.deny_private
    
    if hasattr(args, "verbose"):
        args.verbose = yaml_config.verbose
    if hasattr(args, "print_matches"):
        args.print_matches = yaml_config.print_matches
    
    if hasattr(args, "discover"):
        args.discover = yaml_config.discover
    if hasattr(args, "crawl"):
        args.crawl = yaml_config.crawl
    if hasattr(args, "crawl_depth"):
        args.crawl_depth = yaml_config.crawl_depth
    if hasattr(args, "crawl_max_pages"):
        args.crawl_max_pages = yaml_config.crawl_max_pages
    if hasattr(args, "seed"):
        args.seed = yaml_config.seeds
    
    if hasattr(args, "passive"):
        args.passive = yaml_config.passive
    if hasattr(args, "fuzz"):
        args.fuzz = yaml_config.fuzz
    if hasattr(args, "fuzz_target"):
        args.fuzz_target = yaml_config.fuzz_targets
    if hasattr(args, "payload_dir"):
        args.payload_dir = yaml_config.payload_dir
    
    if hasattr(args, "artifact_analysis"):
        args.artifact_analysis = yaml_config.artifact_analysis
    if hasattr(args, "save_artifacts"):
        args.save_artifacts = yaml_config.save_artifacts
    
    if hasattr(args, "html"):
        args.html = yaml_config.html
    if hasattr(args, "dry_run"):
        args.dry_run = yaml_config.dry_run
    if hasattr(args, "stop_on_high_confidence"):
        args.stop_on_high_confidence = yaml_config.stop_on_high_confidence
    
    if hasattr(args, "header"):
        for k, v in yaml_config.headers.items():
            args.header.append(f"{k}: {v}")
    
    if hasattr(args, "cookie") and not args.cookie:
        args.cookie = yaml_config.cookie
    if hasattr(args, "bearer") and not args.bearer:
        args.bearer = yaml_config.bearer
    if hasattr(args, "proxy") and not args.proxy:
        args.proxy = yaml_config.proxy
    if hasattr(args, "insecure"):
        args.insecure = yaml_config.insecure


def write_example_config(path: str = "hunter.yaml") -> None:
    example = """# Hunter-2 Configuration File
# Example: http://example.com will be scanned with CTF mode

target: http://example.com
mode: ctf

# Output
outdir: loot
report: report

# Rate limiting
qps: 2.0
timeout: 12.0
threads: 5
max_requests: 150

# Scanning options
discover: true
crawl: true
crawl_depth: 2
passive: true

# Fuzzing
fuzz:
  - xss
  - sqli

# Additional headers (optional)
headers:
  User-Agent: Mozilla/5.0
  X-Custom-Header: value

# Security
# deny_private: true
# allow_hosts:
#   - example.com
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(example)
