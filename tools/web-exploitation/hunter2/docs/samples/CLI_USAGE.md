# CLI Usage Examples

## Basic Usage

### CTF Mode
```bash
hunter http://target --mode ctf
```

### Web Mode with Crawling
```bash
hunter https://target --mode web --crawl --discover
```

### Through Proxy (Burp)
```bash
hunter https://target --mode web --proxy http://127.0.0.1:8080 --insecure
```

## Policy & Environment

### Scan with Policy
```bash
# Safe mode - minimal impact
hunter http://target --policy safe

# Balanced mode - default
hunter http://target --policy balanced

# Aggressive mode - full testing
hunter http://target --policy aggressive
```

### Specify Environment
```bash
hunter http://target --env dev
hunter http://target --env staging
hunter http://target --env prod
```

## Baseline & Delta

### First Scan (Create Baseline)
```bash
hunter http://target --report baseline-scan
# Output: baseline-scan.json, baseline-scan.md
```

### Second Scan with Comparison
```bash
hunter http://target \
  --baseline baseline-scan.json \
  --new-only
```

### Detailed Delta Report
```bash
hunter http://target \
  --baseline baseline-scan.json \
  --report current-scan
# Output includes: current-scan-delta.json
```

## Suppressions

### Run with Suppressions
```bash
hunter http://target \
  --suppressions suppressions.json
```

### Hide Suppressed Findings
```bash
hunter http://target \
  --suppressions suppressions.json \
  --hide-suppressed
```

### Create Suppression
```json
{
  "suppressions": [
    {
      "id": "sup-0001",
      "rule_id": "git-directory-exposure",
      "url_pattern": "http://example.com/.git/.*",
      "reason": "Public repository, no sensitive data",
      "owner": "security_team",
      "created_at": "2026-04-11T00:00:00Z",
      "expires_at": null,
      "severity_filter": null
    }
  ]
}
```

## CI/CD Integration

### Fail on Severity
```bash
# Exit code 2 if any critical finding
hunter http://target --fail-on critical

# Exit code 2 if high or critical
hunter http://target --fail-on high
```

### Fail on Verified Only
```bash
hunter http://target --fail-on high --fail-verified-only
```

### Fail on Exploited Only
```bash
hunter http://target --fail-on critical --fail-exploited-only
```

### Fail on New Findings Only
```bash
hunter http://target \
  --baseline baseline-scan.json \
  --fail-on-new high
```

### Fail on Changed Severity
```bash
hunter http://target \
  --baseline baseline-scan.json \
  --fail-on-changed critical
```

### Fail on Any Delta
```bash
hunter http://target \
  --baseline baseline-scan.json \
  --fail-on-delta-only
```

## Full Governance Pipeline

```bash
hunter http://target \
  --policy balanced \
  --env staging \
  --baseline baseline-scan.json \
  --suppressions suppressions.json \
  --hide-suppressed \
  --new-only \
  --fail-on-new high \
  --html
```

This command:
- Uses balanced policy
- Targets staging environment
- Compares with baseline
- Applies suppressions
- Hides suppressed findings
- Shows only new findings
- Fails if new high+ findings found
- Generates HTML report

## Low-Noise Configuration

For sensitive targets:
```bash
hunter http://target \
  --mode ctf \
  --qps 0.5 \
  --threads 1 \
  --retries 5 \
  --timeout 20 \
  --max-requests 40
```

## Rule Packs

### Specify Pack
```bash
hunter http://target --pack ctf
hunter http://target --pack web-misconfig
hunter http://target --pack spring
hunter http://target --pack auto  # Auto-detect
```

### Multiple Packs
```bash
hunter http://target --pack ctf,web-misconfig
```

## Output Options

### Generate HTML
```bash
hunter http://target --html
```

### Custom Output Directory
```bash
hunter http://target --outdir results
```

### Custom Report Name
```bash
hunter http://target --report my-report
# Outputs: my-report.json, my-report.md
```

## Help

```bash
hunter --help
```