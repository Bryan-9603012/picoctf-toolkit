# Hunter-2 Installation Guide

## Requirements

- Python 3.10+
- Linux/WSL (macOS/Windows support planned)

## Installation Methods

### 1. From Source (Recommended)

```bash
# Clone repository
git clone https://github.com/hunter-team/hunter-2.git
cd hunter-2

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .

# Verify installation
hunter --help
```

### 2. Using uv (Faster)

```bash
# Install uv if not available
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create project
uv venv .venv
source .venv/bin/activate

# Install from pyproject.toml
uv pip install -e .
```

### 3. Using Docker (Coming Soon)

```bash
docker pull hunter2/hunter-2:latest
docker run hunter2/hunter-2 http://target
```

## Verify Installation

```bash
$ hunter --help
usage: hunter [-h] base [speed] ...

Hunter v2 - enterprise-grade rule-based pentest scanner

positional arguments:
  base                  Base URL, e.g. http://host:port
  speed                 Scan speed profile: fast | medium | slow

optional arguments:
  --policy POLICY       Scan policy: safe | balanced | aggressive
  --env ENV             Target environment: dev | staging | prod | unknown
  ...
```

## Quick Test

```bash
# Test with a safe target
hunter http://example.com --policy safe
```

## Configuration

### Using hunter.yaml

Create `hunter.yaml` in current directory or home:

```yaml
policy: balanced
env: staging
qps: 2.0
timeout: 12.0
fail-on: high
```

### Using CLI Args

All options can be passed via CLI:

```bash
hunter http://target --policy balanced --env staging
```

## Updating Hunter-2

```bash
cd hunter-2
git pull origin main
pip install -e .
```

## Uninstall

```bash
pip uninstall hunter-2
```

## Troubleshooting

### Module not found
```bash
# Reinstall
pip install -e .
```

### Permission errors
```bash
# Use virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Network timeouts
```bash
# Increase timeout and retries
hunter http://target --timeout 30 --retries 5
```

## Next Steps

- Read [README.md](../README.md) for features
- See [CLI_USAGE.md](../docs/samples/CLI_USAGE.md) for examples
- Check [RELEASE_NOTES.md](../RELEASE_NOTES.md) for what's new