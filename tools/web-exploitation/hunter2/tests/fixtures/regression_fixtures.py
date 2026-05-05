# tests/fixtures/regression_fixtures.py
"""
Regression Test Fixtures

Sample data for regression testing:
- Finding snapshots
- Baseline reports
- Expected outputs
"""

from datetime import datetime
from typing import List, Dict, Any


def get_sample_findings() -> List[Dict[str, Any]]:
    """Sample findings for regression testing"""
    return [
        {
            "id": "finding-001",
            "rule_id": "git-directory-exposure",
            "url": "http://example.com/.git/config",
            "title": "Exposed .git Metadata",
            "severity": "high",
            "confidence": "high",
            "verification_state": "verified",
            "scan_id": "scan-regression-001",
            "discovered_at": "2026-04-11T10:00:00Z",
            "verified_at": "2026-04-11T10:05:00Z",
            "cwe": "552",
            "owasp": "A01:2021-Broken Access Control",
            "matches": ["[core]", "ref: refs/heads/"],
            "remediation": "Block access to /.git via web server config",
        },
        {
            "id": "finding-002",
            "rule_id": "env-config-exposure",
            "url": "http://example.com/.env",
            "title": "Exposed Environment File",
            "severity": "high",
            "confidence": "high",
            "verification_state": "observed",
            "scan_id": "scan-regression-001",
            "discovered_at": "2026-04-11T10:01:00Z",
            "cwe": "552",
            "owasp": "A03:2017-Sensitive Data Exposure",
            "matches": ["DATABASE_URL=postgres://..."],
            "remediation": "Remove .env from web root",
        },
        {
            "id": "finding-003",
            "rule_id": "backup-artifact-exposure",
            "url": "http://example.com/backup.zip",
            "title": "Exposed Backup Archive",
            "severity": "critical",
            "confidence": "high",
            "verification_state": "exploited",
            "scan_id": "scan-regression-001",
            "discovered_at": "2026-04-11T10:02:00Z",
            "verified_at": "2026-04-11T10:06:00Z",
            "cwe": "552",
            "owasp": "A01:2021-Broken Access Control",
            "exploitability": "critical",
            "matches": ["PK\x03\x04"],
            "remediation": "Remove backup files from web root",
        },
    ]


def get_baseline_report() -> Dict[str, Any]:
    """Sample baseline report for delta regression"""
    return {
        "metadata": {
            "target": "http://example.com",
            "scan_id": "scan-baseline-001",
            "generated_at": "2026-04-01T00:00:00Z",
            "policy": "balanced",
            "environment": "staging",
        },
        "findings": [
            {
                "id": "finding-001",
                "rule_id": "git-directory-exposure",
                "url": "http://example.com/.git/config",
                "severity": "high",
                "verification_state": "verified",
            },
            {
                "id": "finding-002",
                "rule_id": "env-config-exposure",
                "url": "http://example.com/.env",
                "severity": "medium",
                "verification_state": "observed",
            },
        ],
    }


def get_current_report() -> Dict[str, Any]:
    """Sample current report for delta regression"""
    findings = [f for f in get_sample_findings() if f["rule_id"] != "env-config-exposure"]
    return {
        "metadata": {
            "target": "http://example.com",
            "scan_id": "scan-regression-001",
            "generated_at": "2026-04-11T00:00:00Z",
            "policy": "balanced",
            "environment": "staging",
        },
        "findings": findings,
    }


def get_expected_delta() -> Dict[str, Any]:
    """Expected delta between baseline and current"""
    return {
        "new_findings": [
            {
                "rule_id": "backup-artifact-exposure",
                "url": "http://example.com/backup.zip",
                "severity": "critical",
                "delta_type": "new",
            }
        ],
        "resolved_findings": [
            {
                "rule_id": "env-config-exposure",
                "url": "http://example.com/.env",
                "severity": "medium",
            }
        ],
        "changed_findings": [
            {
                "rule_id": "git-directory-exposure",
                "url": "http://example.com/.git/config",
                "current_severity": "high",
                "previous_severity": "high",
                "current_verification": "verified",
                "previous_verification": "observed",
            }
        ],
    }


def get_suppression_list() -> List[Dict[str, Any]]:
    """Sample suppression list"""
    return [
        {
            "id": "sup-0001",
            "rule_id": "git-directory-exposure",
            "url_pattern": "http://example.com/.git/.*",
            "reason": "False positive - internal repo",
            "owner": "security_team",
            "created_at": "2026-04-01T00:00:00Z",
            "expires_at": None,
            "severity_filter": None,
        },
        {
            "id": "sup-0002",
            "rule_id": "*",
            "url_pattern": "http://example.com/health",
            "reason": "Health check endpoint",
            "owner": "platform_team",
            "created_at": "2026-04-01T00:00:00Z",
            "expires_at": "2026-05-01T00:00:00Z",
            "severity_filter": None,
        },
    ]


def get_severity_breakdown() -> Dict[str, int]:
    """Expected severity breakdown"""
    return {
        "critical": 1,
        "high": 2,
        "medium": 0,
        "low": 0,
        "info": 0,
    }


def get_verification_breakdown() -> Dict[str, int]:
    """Expected verification state breakdown"""
    return {
        "observed": 1,
        "suspected": 0,
        "verified": 1,
        "exploited": 1,
    }