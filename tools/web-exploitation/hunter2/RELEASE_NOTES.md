# Release Notes - Hunter-2 v1.0.0

## Release Date
2026-04-11

## Version Overview
Hunter-2 v1.0.0 is the first stable release of the enterprise-grade security scanner.

## What's New

### Enterprise Features (v1.1-v1.3)

#### Finding Lifecycle
- State machine: `observed` → `suspected` → `verified` → `exploited`
- No state skipping allowed (progressive escalation)
- Manual override with audit trail
- Verification state displayed in all reports

#### Policy Matrix
- **safe**: Minimal impact, no fuzzing, limited requests (max 50)
- **balanced**: Default, fuzzing enabled, 150 max requests
- **aggressive**: Full testing, unlimited chaining, no request cap

#### Baseline Comparison
- Delta reporting: new, resolved, changed findings
- `--baseline` for comparison scan
- `--new-only` to show only new findings

#### Suppression Workflow
- JSON-based suppression file
- Rule ID, URL pattern, severity filter matching
- Expiry dates with auto-cleanup
- Owner/reason tracking for audit

### CI/Gate Integration

| Flag | Description |
|------|-------------|
| `--fail-on <severity>` | Exit 2 if findings at/above severity |
| `--fail-on-new <severity>` | Only fail on NEW findings |
| `--fail-on-changed <severity>` | Only fail on severity changes |
| `--fail-on-delta-only` | Fail if any delta exists |
| `--fail-verified-only` | Only fail on verified/exploited |
| `--fail-exploited-only` | Only fail on exploited |

### Smart Enhancement (v2)

#### Finding Correlation
- Automatic exploitation chain detection
- Credential detection in evidence/extracted_data
- Sensitive artifact path detection
- Enhanced risk scoring with bonuses

#### Exploitability Scoring
- Multi-factor scoring: access, complexity, impact
- Chain bonus, credential bonus, verification bonus
- Ranking by exploitability score
- Exploitability rating (critical/high/medium/low/info)

### Report Enhancements

#### HTML Report
- Summary cards (severity breakdown)
- Verification status breakdown
- Baseline comparison block
- Per-finding verification badge

#### JSON Report
- Full enterprise metadata
- Traceability fields (scan_id, discovered_at, verified_at)
- Exploitability scores

## Installation

### From Source
```bash
git clone https://github.com/hunter-team/hunter-2.git
cd hunter-2
pip install -e .
```

### From PyPI (coming soon)
```bash
pip install hunter-2
```

## Quick Start

### Basic Scan
```bash
hunter http://target
```

### With Policy
```bash
hunter http://target --policy balanced --env staging
```

### With Baseline
```bash
hunter http://target --baseline baseline.json --new-only --fail-on-new high
```

### Full Governance Pipeline
```bash
hunter http://target \
  --policy balanced \
  --env staging \
  --baseline baseline.json \
  --suppressions suppressions.json \
  --hide-suppressed \
  --new-only \
  --fail-on-new high \
  --html
```

## Breaking Changes

None - this is the first stable release.

## Known Limitations

- Passive secret detection may produce false positives
- Large responses (e.g., heapdumps) may disconnect some CTF targets
- Linux/WSL only (Windows support planned)

## Roadmap

### v1.1 (Planned)
- SARIF export for GitHub/GitLab integration
- Source-aware mode (route inference)
- Planner-based chaining

### v1.2 (Planned)
- AI-assisted triage
- Remediation suggestion ranking

---

For full documentation, see [README.md](README.md)
For CLI examples, see [docs/samples/CLI_USAGE.md](docs/samples/CLI_USAGE.md)