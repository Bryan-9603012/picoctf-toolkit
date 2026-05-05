# Hunter-2

Hunter-2 is an **enterprise-grade rule-based web security scanner** with verification, baseline comparison, suppression workflow, and CI integration.

It combines:

- target enumeration & crawling
- rule-based vulnerability detection
- verification state machine (observed → suspected → verified → exploited)
- baseline/delta comparison
- suppression workflow
- exploitability scoring
- correlation & chaining
- source-aware mode
- AI planning
- Markdown / JSON / HTML reporting

Hunter-2 is designed for both **personal pentesting** and **enterprise security programs**.

---

# Version

**Current: v1.0.0** (Production Ready)

See [RELEASE_NOTES.md](RELEASE_NOTES.md) for changelog.

---

# Architecture

Hunter-2 follows a **layered architecture** for security scanning:

```
┌─────────────────────────────────────────────────────────────┐
│                     CLI (hunter/cli.py)                    │
│  - Argument parsing                                         │
│  - Config aggregation                                        │
│  - Exit code logic                                          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Core (core/)                             │
│  - models.py: Finding, Evidence, Target, ScanConfig        │
│  - schema_validator.py: Finding/Artifact/Cofig validation  │
│  - artifact_manager.py: Artifact collection & storage       │
└─────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ Enumeration     │ │ Scanning       │ │ Fingerprinting  │
│ enumeration/    │ │ scanning/      │ │ fingerprint/    │
│ - Seed paths    │ │ - Rule engine  │ │ - Tech detect   │
│ - Crawling      │ │ - Fuzzing      │ │ - WAF detection │
│ - Discovery     │ │ - Passive scan │ │                 │
└─────────────────┘ └─────────────────┘ └─────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                 Post-process (postprocess/)                 │
│  - deduplication                                            │
│  - risk scoring                                              │
│  - verification state machine (verifier.py)                │
│  - baseline comparison (baseline.py)                        │
│  - suppression filtering (suppression.py)                   │
│  - artifact analysis                                        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   Reports (reports/)                        │
│  - JSON (machine-readable)                                  │
│  - Markdown (human-readable)                                │
│  - HTML (dashboard style)                                   │
│  - SARIF (CI integration)                                   │
└─────────────────────────────────────────────────────────────┘
```

## Enterprise Features

Hunter-2 includes enterprise-grade features:

| Feature | Description |
|---------|-------------|
| **Finding Lifecycle** | State machine: observed → suspected → verified → exploited |
| **Policy Matrix** | safe/balanced/aggressive behavior profiles |
| **Baseline Comparison** | Delta reporting: new/resolved/changed |
| **Suppressions** | Exception workflow with expiry & audit |
| **CI/Gate Integration** | Exit codes: --fail-on, --fail-on-new, --fail-on-changed |
| **Verification** | Auto-escalation with manual override support |
| **Traceability** | scan_id, discovered_at, verified_at, audit logs |

---

# Features

## Rule-Based Scanning

Hunter uses YAML rule packs for detection.

Current rule packs include:

- `ctf`
- `web-misconfig`
- `spring`

Examples of supported checks:

- heapdump exposure
- `.env` exposure
- `.git` exposure
- backup file exposure
- Spring actuator exposure

---

## Target Enumeration

Hunter can discover targets before scanning:

- seed paths
- common path discovery
- HTML crawling
- JS resource collection

---

## Passive Secret Scanning

Hunter can scan responses for possible secrets such as:

- bearer tokens
- embedded credentials
- API-like tokens
- CTF flags

---

# Modes

## CTF Mode

For CTF targets and debug-style endpoints.

```bash
hunter http://target --mode ctf
```

## Web Mode

For general web testing.

```bash
hunter https://target --mode web --crawl --discover
```

## Stealth Mode

For lower-noise scanning.

```bash
hunter https://target --mode stealth
```

---

# Installation

## 1. Create virtual environment

```bash
py -3.13 -m venv .venv
```

## 2. Activate virtual environment

Windows PowerShell:

```powershell
.venv\Scripts\activate
```

## 3. Install dependencies

```bash
pip install -r requirements.txt
```

## 4. Install Hunter CLI

```bash
python -m pip install -e .
```

## 5. Verify installation

```bash
hunter --help
```

---

# Usage

### Basic CTF scan

```bash
hunter http://target --mode ctf
```

### Web scan with crawling and discovery

```bash
hunter https://target --mode web --crawl --discover
```

### Low-noise scan

```bash
hunter https://target --mode stealth
```

### Scan through Burp proxy

```bash
hunter https://target --mode web --proxy http://127.0.0.1:8080 --insecure
```

### Authenticated scan with cookie

```bash
hunter https://target --cookie "PHPSESSID=abc123"
```

### Authenticated scan with bearer token

```bash
hunter https://target --bearer "YOUR_TOKEN"
```

---

# Example Output

```text
[*] [heapdump-exposure] GET http://target/heapdump -> 200 ct=application/octet-stream len=11239797

🔥 FLAG FOUND
picoCTF{example_flag}

[+] Done. Findings=1
[+] Reports: report.md , report.json
```

---

# Reports

Hunter generates:

- `report.md`
- `report.json`

Reports include:

- finding summary
- severity
- matched evidence
- remediation hints
- affected URLs

---

# Project Structure

```
Hunter-2/
├─ hunter/
│  ├─ __init__.py
│  └─ cli.py
├─ config/
├─ core/
├─ enumeration/
├─ fingerprint/
├─ fingerprints/
├─ payloads/
├─ postprocess/
├─ reports/
├─ rules/
├─ scanning/
├─ loot/
├─ pyproject.toml
├─ requirements.txt
└─ README.md
```

---

# Rule Packs

Rules are stored in:

```
rules/packs/
```

Example:

```
rules/packs/ctf/
rules/packs/web-misconfig/
rules/packs/spring/
```

Each rule is written in YAML.

---

# Typical Workflows

### CTF workflow

```bash
hunter http://target --mode ctf
```

### Personal website check

```bash
hunter https://your-site.example --mode web --crawl --discover
```

### Testing through Burp

```bash
hunter https://target --mode web --proxy http://127.0.0.1:8080 --insecure
```

---

# Enterprise Workflows

### Scan with policy and environment

```bash
hunter http://target \
  --policy balanced \
  --env staging
```

### Baseline comparison (delta reporting)

```bash
# First scan (creates baseline)
hunter http://target --report baseline

# Later scan (compares with baseline)
hunter http://target --baseline baseline.json --new-only
```

### Suppression workflow

```bash
# Run scan with suppressions
hunter http://target \
  --suppressions suppressions.json \
  --hide-suppressed
```

### CI/CD Integration

```bash
# Fail if new critical/high findings
hunter http://target \
  --baseline baseline.json \
  --fail-on-new high

# Fail on any delta (new/changed/resolved)
hunter http://target \
  --baseline baseline.json \
  --fail-on-delta-only
```

### Full governance pipeline

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

---

# Notes

- Use Hunter only on targets you own or are explicitly authorized to test.
- Passive secret detection may produce false positives.
- Some CTF targets may disconnect when returning large responses (e.g., heapdumps).

Example low-noise configuration:

```bash
hunter http://target \
  --mode ctf \
  --qps 0.5 \
  --threads 1 \
  --retries 5 \
  --timeout 20 \
  --max-requests 40
```

---

# Support

- Documentation: See [docs/](docs/) for detailed docs
- CLI Examples: See [docs/samples/CLI_USAGE.md](docs/samples/CLI_USAGE.md)
- Installation: See [INSTALL.md](INSTALL.md)

# License

MIT License - See LICENSE file for details.

---

# Author

Bryan

A personal security tooling project focused on building a modular scanner for CTF and practical web security testing.