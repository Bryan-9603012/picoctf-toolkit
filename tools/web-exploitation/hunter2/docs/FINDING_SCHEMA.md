# Finding Schema

## Overview

This document defines the complete Finding JSON schema used throughout Hunter-2. All components must adhere to this schema to ensure consistency.

## Top-Level Finding Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique finding identifier (format: `finding-{rule_id}-{hash}`) |
| `rule_id` | string | Yes | ID of rule that generated this finding |
| `title` | string | Yes | Human-readable title (from rule metadata) |
| `name` | string | No | Alias for title (backward compatibility) |
| `category` | string | Yes | Classification category |
| `severity` | string | Yes | Severity level (info/low/medium/high/critical) |
| `confidence` | string | Yes | Confidence level (low/medium/high) |
| `verification_state` | string | Yes | Verification status (observed/suspected/verified/exploited) |
| `url` | string | Yes | Affected URL |
| `affected_asset` | string | No | Full asset identifier (host/path) |

### Enumeration Values

```python
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
VERIFICATION_STATES = ["observed", "suspected", "verified", "exploited"]
CONFIDENCE_LEVELS = ["low", "medium", "high"]
```

## Vulnerability Classification

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `cwe` | string | No | CWE ID (e.g., "552") |
| `owasp` | string | No | OWASP category (e.g., "A01:2021") |

## Evidence

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `evidence` | object | Yes | Evidence object (see Evidence Schema) |

### Evidence Schema

```json
{
  "method": "GET",
  "url": "http://example.com/.git/config",
  "status": 200,
  "headers": {"Content-Type": "text/plain"},
  "content_length": 1024,
  "elapsed_ms": 45,
  "snippet": "[core]",
  "artifact": "loot/git_config.bin",
  "scope_reason": "in-scope",
  "request_body": null,
  "response_body": "[core]\nrepositoryformatversion = 0",
  "response_headers": {"Content-Type": "text/plain"},
  "matched_pattern": "(?m)^\\[core\\]$",
  "timestamp": "2026-04-11T10:30:00Z"
}
```

## Detection Details

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `matches` | array | No | List of matched patterns |
| `tags` | array | No | Tags from rule |
| `preconditions` | array | No | Required preconditions for detection |

## Remediation

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `remediation` | string | No | Remediation guidance |
| `references` | array | No | Reference URLs |
| `remediation_draft` | string | No | AI-generated draft remediation |

## Rule Execution Metadata

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `safe_check` | string | No | Safe check expression |
| `verify_check` | string | No | Verification check expression |
| `evidence_type` | string | No | Type of evidence expected |
| `exploitability` | string | No | Exploitability assessment |

## Extracted Data

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `extracted_data` | object | No | Key-value pairs of extracted data |
| `chain` | array | No | Chaining steps (see ChainStep) |
| `related_artifacts` | array | No | List of artifact IDs |

## Risk Assessment

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `risk_score` | integer | No | Computed risk score |
| `variables` | object | No | Rule variables |

## CTF-Specific

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `clues` | array | No | CTF clues |

## Traceability

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `scan_id` | string | No | Parent scan session ID |
| `discovered_at` | datetime | No | Discovery timestamp |
| `verified_at` | datetime | No | Verification timestamp |
| `source_rule_pack` | string | No | Origin rule pack name |

## Exploitation Details

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `exploitability` | string | No | Exploitability assessment |
| `reproduction_steps` | array | No | Steps to reproduce |
| `exploit_chain` | array | No | Chain of exploitation |

## Complete Example

```json
{
  "id": "finding-git-exposure-12345",
  "rule_id": "git-directory-exposure",
  "title": "Exposed .git Metadata",
  "category": "Source Control Exposure",
  "severity": "high",
  "confidence": "high",
  "verification_state": "verified",
  "url": "http://example.com/.git/config",
  "affected_asset": "http://example.com/.git/config",
  "cwe": "552",
  "owasp": "A01:2021-Broken Access Control",
  "evidence": {
    "method": "GET",
    "url": "http://example.com/.git/config",
    "status": 200,
    "headers": {"Content-Type": "text/plain"},
    "content_length": 1024,
    "elapsed_ms": 45,
    "snippet": "[core]",
    "artifact": "loot/artifacts/http/art-001.json",
    "scope_reason": "in-scope",
    "matched_pattern": "(?m)^\\[core\\]$",
    "timestamp": "2026-04-11T10:30:00Z"
  },
  "matches": ["(?m)^\\[core\\]$"],
  "tags": ["git", "source", "misconfig"],
  "remediation": "Block access to /.git via web server config",
  "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
  "preconditions": [],
  "evidence_type": "http-response",
  "exploitability": "medium",
  "extracted_data": {},
  "chain": [],
  "related_artifacts": ["art-001", "art-002"],
  "risk_score": 80,
  "variables": {},
  "clues": [],
  "scan_id": "scan-20260411-001",
  "discovered_at": "2026-04-11T10:30:00Z",
  "verified_at": "2026-04-11T10:31:00Z",
  "source_rule_pack": "web-misconfig"
}
```

## Field Naming Conventions

| Convention | Example | Purpose |
|------------|---------|---------|
| snake_case | `verification_state` | All field names |
| _id suffix | `artifact_id`, `scan_id` | Identifiers |
| _at suffix | `discovered_at`, `verified_at` | Timestamps |
| singular | `matches` (list) | Arrays of items |
| verb_noun | `reproduction_steps` | Actions |

## Naming Unification Rules

| Avoid | Use Instead |
|-------|-------------|
| `proof` | `evidence` |
| `data` | `extracted_data` |
| `file` | `artifact` |
| `result` | `finding` |