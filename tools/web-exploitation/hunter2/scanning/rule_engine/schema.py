# scanning/rule_schema.py
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


class RuleMetadata:
    def __init__(self, rule: Dict[str, Any]):
        self.rule = rule
        self._info = rule.get("info") or {}
    
    @property
    def id(self) -> str:
        return str(self.rule.get("id") or self.rule.get("_file") or "rule")
    
    @property
    def title(self) -> str:
        return str(self._info.get("name") or self.id)
    
    @property
    def severity(self) -> str:
        return str(self._info.get("severity") or "medium").lower()
    
    @property
    def confidence(self) -> str:
        return str(self._info.get("confidence") or "medium").lower()
    
    @property
    def category(self) -> str:
        return str(self._info.get("category") or "miscellaneous")
    
    @property
    def remediation(self) -> str:
        return str(self._info.get("remediation") or "")
    
    @property
    def references(self) -> List[str]:
        return list(self._info.get("references") or [])
    
    @property
    def cwe(self) -> Optional[str]:
        return self._info.get("cwe")
    
    @property
    def owasp(self) -> Optional[str]:
        return self._info.get("owasp")
    
    @property
    def tags(self) -> List[str]:
        return list(self._info.get("tags") or self.rule.get("tags") or [])
    
    @property
    def preconditions(self) -> List[str]:
        return list(self._info.get("preconditions") or [])
    
    @property
    def safe_check(self) -> Optional[str]:
        return self._info.get("safe_check")
    
    @property
    def verify_check(self) -> Optional[str]:
        return self._info.get("verify_check")
    
    @property
    def evidence_type(self) -> Optional[str]:
        return self._info.get("evidence_type")
    
    @property
    def description(self) -> str:
        return str(self._info.get("description") or "")
    
    @property
    def exploitability(self) -> Optional[str]:
        return self._info.get("exploitability")


def get_rule_id(rule: Dict[str, Any]) -> str:
    return str(rule.get("id") or rule.get("_file") or "rule")


def get_rule_info(rule: Dict[str, Any]) -> Dict[str, Any]:
    return dict(rule.get("info") or {})


def get_rule_tags(rule: Dict[str, Any]) -> List[str]:
    return list(rule.get("tags") or [])


def get_rule_remediation(rule: Dict[str, Any]) -> str:
    info = get_rule_info(rule)
    return str(info.get("remediation") or "")


def get_method_and_paths(rule: Dict[str, Any]) -> Tuple[str, List[str]]:
    req = rule.get("request") or {}
    method = (req.get("method") or rule.get("method") or "GET").upper()

    paths = req.get("paths")
    if paths is None:
        paths = rule.get("paths")
    if paths is None:
        paths = []
    return method, list(paths or [])


def create_finding_from_rule(rule: Dict[str, Any], url: str, evidence: Any) -> Dict[str, Any]:
    md = RuleMetadata(rule)
    return {
        "id": f"finding-{md.id}-{hash(url) % 100000}",
        "rule_id": md.id,
        "title": md.title,
        "name": md.title,
        "category": md.category,
        "severity": md.severity,
        "confidence": md.confidence,
        "url": url,
        "verification_state": "observed",
        "cwe": md.cwe,
        "owasp": md.owasp,
        "remediation": md.remediation,
        "references": md.references,
        "tags": md.tags,
        "preconditions": md.preconditions,
        "safe_check": md.safe_check,
        "verify_check": md.verify_check,
        "evidence_type": md.evidence_type,
        "exploitability": md.exploitability,
        "evidence": evidence,
    }