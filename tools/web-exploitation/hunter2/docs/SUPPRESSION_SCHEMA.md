# Suppression Schema

## Overview

Suppressions allow security teams to exclude specific findings from reports based on rule ID, URL pattern, or severity. This is essential for managing false positives and acknowledged risks in enterprise environments.

## Suppression File Format

Location: `suppressions.json` (configurable via `--suppressions`)

```json
{
  "suppressions": [
    {
      "id": "sup-0001",
      "rule_id": "rule-001",
      "url_pattern": "http://example.com/api/*",
      "reason": "False positive - internal endpoint",
      "owner": "security_team",
      "created_at": "2024-04-11T12:00:00Z",
      "expires_at": null,
      "severity_filter": "high"
    }
  ]
}
```

## Schema Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique suppression identifier (auto-generated) |
| `rule_id` | string | Yes | Rule ID to suppress. Use `*` for wildcard (any rule) |
| `url_pattern` | string | Yes | Regex pattern to match target URL |
| `reason` | string | Yes | Justification for suppression |
| `owner` | string | Yes | Team/person responsible for suppression |
| `created_at` | string | Yes | ISO 8601 timestamp |
| `expires_at` | string | No | Expiration timestamp. Null = never expires |
| `severity_filter` | string | No | Minimum severity to suppress (e.g., "high" suppresses high+critical) |

## Matching Logic

Suppressions are evaluated in this order:

1. **Rule ID Match**: Exact match or wildcard `*` matches any rule
2. **URL Pattern Match**: Regex full-match against target URL
3. **Severity Filter**: If set, finding severity must be >= filter level
4. **Expiry Check**: If `expires_at` set and in past, suppression is invalid

### Matching Algorithm

```
For each suppression:
  1. If rule_id != '*' AND rule_id != finding.rule_id → skip
  2. If url_pattern doesn't match finding.url → skip
  3. If severity_filter set AND finding.severity < filter → skip
  4. If expires_at set AND expires_at < now → skip (suppression expired)
  5. If all checks pass → finding is suppressed
```

### Severity Order

```
info (0) < low (1) < medium (2) < high (3) < critical (4)
```

- `severity_filter: "high"` → suppresses high (3), critical (4)
- `severity_filter: "medium"` → suppresses medium (2), low (1), info (0), high (3), critical (4)

## Expiry Semantics

- **Null expires_at**: Never expires, valid indefinitely
- **Past expires_at**: Suppression is invalid and ignored
- **Future expires_at**: Valid until the specified date/time
- **clean_expired()**: Called to auto-remove expired suppressions on scan

## Interaction with --hide-suppressed

| Scenario | Behavior |
|----------|----------|
| Scan without `--hide-suppressed` | Suppressed findings shown in report with "suppressed" flag |
| Scan with `--hide-suppressed` | Suppressed findings excluded from report output |
| Delta with baseline + suppressions | Delta compares only non-suppressed findings |
| Suppressed finding remains in JSON | Full finding data preserved in JSON for traceability |

**Important**: Suppressed findings are NOT deleted—they are moved to `result.suppressed` list and can be included in JSON output for audit purposes while being hidden from human-readable reports.

## Complete JSON Examples

### Example 1: Basic suppression (no expiry)
```json
{
  "suppressions": [
    {
      "id": "sup-0001",
      "rule_id": "git-exposure",
      "url_pattern": "http://example.com/.git/*",
      "reason": "Public repository, no sensitive data",
      "owner": "dev_team",
      "created_at": "2026-04-11T10:00:00Z",
      "expires_at": null,
      "severity_filter": null
    }
  ]
}
```

### Example 2: Time-boxed suppression with severity filter
```json
{
  "suppressions": [
    {
      "id": "sup-0002",
      "rule_id": "*",
      "url_pattern": "http://staging.example.com/.*",
      "reason": "Known issues in staging, remediation planned May 2026",
      "owner": "security_team",
      "created_at": "2026-04-11T10:00:00Z",
      "expires_at": "2026-05-01T00:00:00Z",
      "severity_filter": "high"
    }
  ]
}
```

### Example 3: Wildcard rule with specific URL
```json
{
  "suppressions": [
    {
      "id": "sup-0003",
      "rule_id": "*",
      "url_pattern": "http://example.com/health",
      "reason": "Health check endpoint, always returns 200",
      "owner": "platform_team",
      "created_at": "2026-04-11T10:00:00Z",
      "expires_at": null,
      "severity_filter": null
    }
  ]
}
```

## CLI Integration

```bash
# Add suppression (30-day expiry, high+ only)
hunter add-suppression --rule-id "rule-001" \
    --url-pattern "http://example.com/test/*" \
    --reason "False positive in staging" \
    --owner "security_team" \
    --expires-days 30 \
    --severity-filter "high"

# List suppressions
hunter list-suppressions

# Run scan with suppressions
hunter scan http://example.com/ --suppressions suppressions.json --hide-suppressed

# Scan with baseline comparison and suppressions
hunter scan http://example.com/ \
    --baseline baseline.json \
    --suppressions suppressions.json \
    --hide-suppressed \
    --new-only
```

## Audit Trail

All suppression operations are logged to console with:
- Suppression ID
- Rule ID & URL pattern
- Owner & reason
- Expiry date
- Match count (how many findings were suppressed)

## Use Cases

1. **Known False Positives**: Suppress findings for endpoints that always trigger certain rules
2. **Acknowledged Risks**: Allow findings to exist but hide from reports until remediated
3. **Time-boxed Exceptions**: Temporary suppressions for planned remediation
4. **Environment-specific**: Suppress findings only in dev/staging environments