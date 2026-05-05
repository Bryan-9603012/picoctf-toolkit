# ArtifactScope

ArtifactScope is a lightweight, security-oriented file triage and artifact analysis tool for CTF, DFIR learning, and suspicious file inspection.

## Features

- File metadata collection
- MD5 / SHA1 / SHA256 hashing
- Magic byte / signature-based type detection
- Extension mismatch detection
- Shannon entropy analysis
- ASCII strings extraction
- IOC-style extraction:
  - URLs
  - IP addresses
  - Email addresses
  - Base64-like strings
  - Suspicious commands / keywords
- Simple rule engine with severity and risk scoring
- Embedded artifact discovery and optional carving
- Partition-aware disk image triage with SleuthKit integration when available
- Deleted-file recovery and timeline helpers for `.img` / `.dd` CTF images
- Git artifact and Git history recovery helpers
- JSON and Markdown report output

## Project Structure

```text
ArtifactScope/
├─ artifactscope/
│  ├─ __init__.py
│  ├─ cli.py
│  ├─ analyzer.py
│  ├─ carver.py
│  ├─ ctf_handlers.py
│  ├─ disk_mount.py
│  ├─ disk_triage.py
│  ├─ entropy.py
│  ├─ fs_analyzer.py
│  ├─ git_analyzer.py
│  ├─ hashing.py
│  ├─ reporter.py
│  ├─ rules.py
│  ├─ signatures.py
│  ├─ stringscan.py
│  └─ utils.py
├─ rules/
│  └─ default_rules.yaml
├─ tests/
├─ requirements.txt
├─ main.py
└─ README.md
```

## Installation

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt
```

## Usage

### Quick analysis

```bash
python main.py sample.bin
```

### Enable strings scan and Markdown report

```bash
python main.py sample.bin --strings --report-md
```

### Enable carving and JSON report

```bash
python main.py sample.bin --carve --report-json
```

### Analyze a CTF disk image with forensic helpers

```bash
python main.py disk.img --strings --mount --git --report-json --report-md
```

### Analyze a directory recursively

```bash
python main.py samples --recursive --strings --report-md
```

## Output

By default, ArtifactScope prints a terminal summary.

Optional outputs:

- `--report-json`: writes JSON report
- `--report-md`: writes Markdown report
- `--carve`: writes carved files into `output/carved/`
- `--mount`: enables mount / TSK / icat fallback access for supported partitions
- `--git`: prioritizes Git recovery when Git artifacts are detected
- `--full-recover`: allows broader `tsk_recover` fallback when available

## Notes

- This is an educational MVP, not a replacement for Autopsy, FTK, Volatility, or YARA-based triage pipelines.
- Signature matching is intentionally lightweight and transparent.
- Carving is heuristic-based and best used as a triage aid.

## Recommended next upgrades

- ZIP unpack and nested analysis
- YARA integration
- More robust disk image support (`.img`, `.dd`)
- Timeline visualization
- Recursive archive analysis
- PE / ELF metadata parsing


## CTF image support

This build includes generic handlers for Sleuthkit Intro, Sleuthkit Apprentice, Timeline0/1, and DearDiary.

### WSL note: `--mount-git` timeout behavior

`--mount-git` may try privileged filesystem mounting. On WSL/Windows this can fail or time out if `sudo mount` cannot run non-interactively. ArtifactScope v5 now fails fast and continues to SleuthKit/icat fallback recovery instead of aborting the scan.

For SleuthKit Apprentice-style picoCTF images, try the safer command first:

```bash
python3 main.py "SleuthkitApprentice.img" --strings --report
```

Use `--mount-git` only when you specifically want mounted partition/Git repository recovery:

```bash
python3 main.py "SleuthkitApprentice.img" --strings --mount-git --report
```


## Recommended commands

General safe scan:

```bash
python3 main.py /path/to/image.img --strings --report
```

Deep forensic scan with fallback recovery:

```bash
python3 main.py /path/to/image.img --strings --mount-git --report
```

`--report` is an alias for `--report-json --report-md`. `--mount-git` is kept as a compatibility alias for the deeper partition recovery path. In WSL, privileged mount can fail or require passwordless sudo; ArtifactScope now treats mount failure as non-fatal and continues with SleuthKit / `tsk_recover` / `icat` fallbacks.

### v7 note: Unicode flag files

Some picoCTF disk images, including Sleuthkit Apprentice-style layouts, may store the real answer in a Unicode file such as `flag.uni.txt`. ArtifactScope now scans `icat` output as raw bytes and supports UTF-16LE/UTF-16BE/NUL-separated flag recovery, not just plain UTF-8 strings.
