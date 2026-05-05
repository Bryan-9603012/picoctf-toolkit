# postprocess/suppression.py
"""
Suppression / Exception Workflow

Handle suppressed findings with:
- Expiry dates
- Reasons
- Owners
- Tracking for audit
"""

from __future__ import annotations
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json
import os
from datetime import timezone


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


@dataclass
class Suppression:
    """A suppression entry"""
    id: str
    rule_id: str
    url_pattern: str
    reason: str
    owner: str
    created_at: str
    expires_at: Optional[str] = None
    severity_filter: Optional[str] = None  # "high", "critical", etc.
    

@dataclass
class SuppressionResult:
    """Result of applying suppressions"""
    suppressed: List[Any] = field(default_factory=list)
    remaining: List[Any] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)


class SuppressionStore:
    """Manage suppressions"""
    
    def __init__(self, suppression_file: str = "suppressions.json"):
        self.suppression_file = suppression_file
        self.suppressions: Dict[str, Suppression] = {}
        self._load()
    
    def _load(self) -> None:
        """Load suppressions from file"""
        if not os.path.exists(self.suppression_file):
            return
        
        try:
            with open(self.suppression_file, 'r') as f:
                data = json.load(f)
            
            for s in data.get('suppressions', []):
                key = f"{s['rule_id']}::{s['url_pattern']}"
                self.suppressions[key] = Suppression(
                    id=s['id'],
                    rule_id=s['rule_id'],
                    url_pattern=s['url_pattern'],
                    reason=s['reason'],
                    owner=s['owner'],
                    created_at=s['created_at'],
                    expires_at=s.get('expires_at'),
                    severity_filter=s.get('severity_filter'),
                )
        except (json.JSONDecodeError, KeyError) as e:
            print(f"[!] Error loading suppressions: {e}")
    
    def _save(self) -> None:
        """Save suppressions to file"""
        data = {
            "suppressions": [
                {
                    "id": s.id,
                    "rule_id": s.rule_id,
                    "url_pattern": s.url_pattern,
                    "reason": s.reason,
                    "owner": s.owner,
                    "created_at": s.created_at,
                    "expires_at": s.expires_at,
                    "severity_filter": s.severity_filter,
                }
                for s in self.suppressions.values()
            ]
        }
        
        with open(self.suppression_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def add(
        self,
        rule_id: str,
        url_pattern: str,
        reason: str,
        owner: str,
        expires_days: Optional[int] = None,
        severity_filter: Optional[str] = None,
    ) -> str:
        """Add a new suppression"""
        suppression_id = f"sup-{len(self.suppressions) + 1:04d}"
        
        expires_at = None
        if expires_days:
            exp_date = _utcnow() + timedelta(days=expires_days)
            expires_at = exp_date.isoformat() + "Z"
        
        key = f"{rule_id}::{url_pattern}"
        self.suppressions[key] = Suppression(
            id=suppression_id,
            rule_id=rule_id,
            url_pattern=url_pattern,
            reason=reason,
            owner=owner,
            created_at=_utcnow().isoformat().replace("+00:00", "Z"),
            expires_at=expires_at,
            severity_filter=severity_filter,
        )
        
        self._save()
        return suppression_id
    
    def remove(self, rule_id: str, url_pattern: str) -> bool:
        """Remove a suppression"""
        key = f"{rule_id}::{url_pattern}"
        if key in self.suppressions:
            del self.suppressions[key]
            self._save()
            return True
        return False
    
    def is_suppressed(
        self,
        rule_id: str,
        url: str,
        severity: str = None,
    ) -> Optional[Suppression]:
        """Check if a finding is suppressed"""
        for sup in self.suppressions.values():
            # Check rule_id match
            if sup.rule_id != rule_id and sup.rule_id != "*":
                continue
            
            # Check URL pattern match
            import re
            try:
                alt_url = url if url.endswith("/") else (url + "/")
                if not re.match(sup.url_pattern, url) and not re.match(sup.url_pattern, alt_url):
                    continue
            except re.error:
                if sup.url_pattern not in {url, url.rstrip("/"), url + "/"}:
                    continue
            
            # Check severity filter
            if sup.severity_filter:
                severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                finding_rank = severity_order.get(severity, 0)
                filter_rank = severity_order.get(sup.severity_filter, 0)
                if finding_rank < filter_rank:
                    continue
            
            # Check expiry
            if sup.expires_at:
                exp_date = _parse_dt(sup.expires_at)
                if exp_date < _utcnow():
                    continue
            
            return sup
        
        return None
    
    def list_suppressions(self) -> List[Dict[str, Any]]:
        """List all suppressions"""
        return [
            {
                "id": s.id,
                "rule_id": s.rule_id,
                "url_pattern": s.url_pattern,
                "reason": s.reason,
                "owner": s.owner,
                "created_at": s.created_at,
                "expires_at": s.expires_at,
                "severity_filter": s.severity_filter,
            }
            for s in self.suppressions.values()
        ]
    
    def clean_expired(self) -> int:
        """Remove expired suppressions"""
        now = _utcnow()
        expired_keys = []
        
        for key, sup in self.suppressions.items():
            if sup.expires_at:
                exp_date = _parse_dt(sup.expires_at)
                if exp_date < now:
                    expired_keys.append(key)
        
        for key in expired_keys:
            del self.suppressions[key]
        
        if expired_keys:
            self._save()
        
        return len(expired_keys)


def apply_suppressions(
    findings: List[Any],
    suppression_file: str = "suppressions.json",
) -> SuppressionResult:
    """Apply suppressions to findings"""
    
    store = SuppressionStore(suppression_file)
    
    result = SuppressionResult()
    
    for f in findings:
        sup = store.is_suppressed(
            f.rule_id,
            f.url,
            f.severity,
        )
        
        if sup:
            result.suppressed.append(f)
        else:
            result.remaining.append(f)
    
    result.stats = {
        "total": len(findings),
        "suppressed": len(result.suppressed),
        "remaining": len(result.remaining),
    }
    
    return result


def add_suppression(
    rule_id: str,
    url_pattern: str,
    reason: str,
    owner: str,
    expires_days: Optional[int] = None,
    severity_filter: Optional[str] = None,
    suppression_file: str = "suppressions.json",
) -> str:
    """Add a new suppression via CLI"""
    store = SuppressionStore(suppression_file)
    return store.add(
        rule_id=rule_id,
        url_pattern=url_pattern,
        reason=reason,
        owner=owner,
        expires_days=expires_days,
        severity_filter=severity_filter,
    )


def list_suppressions_cli(suppression_file: str = "suppressions.json") -> None:
    """List suppressions via CLI"""
    store = SuppressionStore(suppression_file)
    suppressions = store.list_suppressions()
    
    if not suppressions:
        print("No suppressions found.")
        return
    
    print("\n=== Suppressions ===")
    for s in suppressions:
        print(f"\n[{s['id']}] {s['rule_id']}")
        print(f"  URL Pattern: {s['url_pattern']}")
        print(f"  Reason: {s['reason']}")
        print(f"  Owner: {s['owner']}")
        print(f"  Created: {s['created_at']}")
        if s['expires_at']:
            print(f"  Expires: {s['expires_at']}")
        if s['severity_filter']:
            print(f"  Severity Filter: {s['severity_filter']}")