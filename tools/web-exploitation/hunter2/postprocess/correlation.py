# postprocess/correlation.py
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Set, Tuple
from core.models import Finding, ChainStep


CREDENTIAL_KEYWORDS = {
    "password", "passwd", "secret", "token", "key", "api_key", "apikey",
    "credential", "auth", "bearer", "jwt", "session", "login", "user",
}


def find_credentials(finding: Finding) -> bool:
    content = ""
    evidence = getattr(finding, "evidence", None)
    if evidence and getattr(evidence, "snippet", None):
        content = evidence.snippet.lower()
    
    for keyword in CREDENTIAL_KEYWORDS:
        if keyword in content:
            return True
    
    extracted = getattr(finding, "extracted_data", {}) or {}
    if extracted:
        for key in extracted.keys():
            if any(k in key.lower() for k in CREDENTIAL_KEYWORDS):
                return True
    
    return False


def find_sensitive_artifacts(finding: Finding) -> bool:
    sensitive_paths = [
        "/heapdump", "/actuator", "/admin", "/manage", "/backup",
        ".env", ".git", ".svn", "config", "database", "db/",
    ]
    
    url = finding.url.lower()
    for path in sensitive_paths:
        if path in url:
            return True
    
    return False


def build_correlation_graph(findings: List[Finding]) -> Dict[str, List[str]]:
    graph = defaultdict(list)
    
    for i, f in enumerate(findings):
        node_id = f"{i}:{f.url}"
        
        for j, other in enumerate(findings):
            if i >= j:
                continue
            
            if find_credentials(other) and "/admin" in other.url:
                graph[node_id].append(f"{j}:{other.url}")
            
            if "/heapdump" in f.url and "/admin" in other.url:
                graph[node_id].append(f"{j}:{other.url}")
            
            if "/actuator" in f.url and find_credentials(other):
                graph[node_id].append(f"{j}:{other.url}")
            
            if find_sensitive_artifacts(f) and getattr(other, "url", "").startswith(f.url.rsplit("/", 1)[0]):
                graph[node_id].append(f"{j}:{other.url}")
    
    return dict(graph)


def find_exploitation_chains(
    findings: List[Finding],
    graph: Dict[str, List[str]],
) -> List[List[Finding]]:
    chains = []
    visited = set()
    
    def dfs(start_idx: int, chain: List[Finding]) -> None:
        key = f"{start_idx}:{chain[-1].url}" if chain else str(start_idx)
        if key in visited:
            return
        visited.add(key)
        
        if len(chain) >= 2:
            chains.append(chain[:])
        
        node_key = f"{start_idx}:{findings[start_idx].url}"
        if node_key in graph:
            for neighbor in graph[node_key]:
                idx = int(neighbor.split(":")[0])
                if idx < len(findings):
                    chain.append(findings[idx])
                    dfs(idx, chain)
                    chain.pop()
    
    for i, f in enumerate(findings):
        if find_sensitive_artifacts(f):
            dfs(i, [f])
    
    return chains


def correlate_findings(findings: List[Finding]) -> List[List[Finding]]:
    if not findings:
        return []
    
    graph = build_correlation_graph(findings)
    chains = find_exploitation_chains(findings, graph)
    
    for chain in chains:
        chain_start = chain[0]
        chain_end = chain[-1]
        
        for f in chain:
            chain_steps = []
            for i, step_f in enumerate(chain):
                step = ChainStep(
                    finding_id=f"{i}:{step_f.url}",
                    rule_id=step_f.rule_id,
                    url=step_f.url,
                    action="credential_access" if find_credentials(step_f) else "initial_access",
                    result="success",
                )
                chain_steps.append(step)
            f.chain = chain_steps
    
    return chains


def compute_enhanced_risk(
    finding: Finding,
    chain_bonus: int = 15,
    credential_bonus: int = 20,
    sensitive_artifact_bonus: int = 10,
) -> int:
    chain_len = len(finding.chain) if finding.chain else 0
    has_cred = find_credentials(finding)
    has_sensitive = find_sensitive_artifacts(finding)
    
    return finding.compute_risk_score(
        chain_bonus=chain_bonus * chain_len,
        credential_bonus=credential_bonus if has_cred else 0,
        sensitive_artifact_bonus=sensitive_artifact_bonus if has_sensitive else 0,
    )
