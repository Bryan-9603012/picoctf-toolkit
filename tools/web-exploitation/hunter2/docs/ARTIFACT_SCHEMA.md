# Artifact Schema

## Overview

Artifacts are the evidence collected during scanning. Each artifact must be traceable, auditable, and replayable.

## Minimal Required Fields (All Artifact Types)

Every artifact must include these core fields:

| Field | Type | Description |
|-------|------|-------------|
| `artifact_id` | string | Unique identifier (format: `art-{timestamp}-{seq}`) |
| `finding_id` | string | Link to parent finding |
| `scan_id` | string | Link to parent scan session |
| `type` | string | Artifact type from table below |
| `timestamp` | ISO 8601 | When artifact was created |
| `hash` | string | SHA256 of original content (for integrity) |

## Artifact Types

| Type | Description | Storage |
|------|-------------|---------|
| `http_request` | Single HTTP request | JSON |
| `http_response` | Single HTTP response | JSON |
| `http_exchange` | Request/response pair | JSON |
| `match_snapshot` | Regex match result | JSON |
| `extracted_data` | Credentials, secrets, tokens | Encrypted JSON |
| `reproduction_step` | Exploitation replay steps | JSON |

## HTTP Exchange Structure

This is the most important artifact type. Must include:

```json
{
  "artifact_id": "art-001",
  "finding_id": "finding-001", 
  "scan_id": "scan-20260411-001",
  "type": "http_exchange",
  "timestamp": "2026-04-11T10:30:00Z",
  "hash": "sha256:abc123...",
  
  "request": {
    "method": "GET",
    "path": "/.git/config",
    "url": "http://example.com/.git/config",
    "headers": {
      "User-Agent": "Hunter-2/1.0",
      "Authorization": "Bearer ***"
    },
    "body": null
  },
  
  "response": {
    "status": 200,
    "status_text": "OK",
    "headers": {
      "Content-Type": "text/plain",
      "Content-Length": "1024"
    },
    "body_snippet": "[core]\n\trepositoryformatversion = 0",
    "content_length": 1024
  },
  
  "matched_patterns": [
    "(?m)^\\[core\\]$"
  ],
  
  "metadata": {
    "elapsed_ms": 45,
    "scope_reason": "in-scope",
    "rule_id": "git-exposure"
  }
}
```

### Required HTTP Exchange Fields

| Field | Description |
|-------|-------------|
| `request.method` | HTTP method (GET, POST, etc.) |
| `request.path` | Request path |
| `request.url` | Full URL |
| `request.headers` | Request headers as dict |
| `request.body` | Request body (if present) |
| `response.status` | HTTP status code |
| `response.headers` | Response headers as dict |
| `response.body_snippet` | First 2KB of response (for large files) |
| `matched_patterns` | List of regex patterns that matched |
| `metadata.elapsed_ms` | Request duration in milliseconds |

## Extracted Data Structure

For credentials, secrets, tokens:

```json
{
  "artifact_id": "art-002",
  "finding_id": "finding-002",
  "scan_id": "scan-20260411-001", 
  "type": "extracted_data",
  "timestamp": "2026-04-11T10:35:00Z",
  "hash": "sha256:def456...",
  
  "data_type": "credential",
  "classification": "api_key",
  "value_preview": "sk_live_***",
  "source_url": "http://example.com/config",
  "source_pattern": "api_key.*?(sk_live_[a-zA-Z0-9]+)",
  
  "metadata": {
    "rule_id": "secret-exposure",
    "confidence": "high",
    "encrypted": true
  }
}
```

## Reproduction Step Structure

For exploitation replay:

```json
{
  "artifact_id": "art-003",
  "finding_id": "finding-003",
  "scan_id": "scan-20260411-001",
  "type": "reproduction_step", 
  "timestamp": "2026-04-11T10:40:00Z",
  
  "step_number": 1,
  "description": "Obtain admin session via SQL injection",
  "request": {...},
  "response": {...},
  "success": true,
  "impact": "Privilege escalation to admin"
}
```

## Artifact Storage

### Directory Structure
```
loot/
├── artifacts/
│   ├── http/
│   │   ├── 2026-04-11/
│   │   │   ├── art-001.json
│   │   │   └── art-002.json
│   ├── files/
│   │   ├── 2026-04-11/
│   │   │   ├── backup.zip
│   │   │   └── heapdump.hprof
│   └── credentials/
│       └── encrypted/
│           └── cred-001.json.enc
└── index.json
```

### Index File
```json
{
  "generated_at": "2026-04-11T10:30:00Z",
  "scan_id": "scan-20260411-001",
  "total_artifacts": 42,
  "artifacts": [
    {
      "artifact_id": "art-001",
      "type": "http_exchange",
      "hash": "sha256:abc123",
      "finding_ids": ["finding-001", "finding-002"]
    }
  ]
}
```

## Replay Capability

Each HTTP exchange artifact must support replay:
1. Load artifact JSON
2. Reconstruct request
3. Execute with same headers/cookies
4. Compare response (for verification)

## Audit Trail

Artifacts should support:
- **Origin**: Which rule/chain created it
- **Timeline**: When collected, processed, analyzed
- **Integrity**: Hash verification
- **Access**: Who/when accessed (for compliance)