# CTF Decode Helper

## Project Purpose

A semi-automated decode helper for CTF challenges. Takes a suspicious string, tries multiple keyless decoders, detects possible flags, scores results, and displays sorted output for human review.

## What This Tool Is / Is Not

**This tool is a decode helper** that generates candidate outputs for human review. It is not a fully automated CTF solver.

- **Is:** A quick way to try multiple common encodings on a suspicious string
- **Is:** A flag detector with scoring for readable outputs
- **Is Not:** An automated CTF challenge solver
- **Is:** A lightweight RSA helper for common picoCTF-style parameter cases
- **Is:** A script-pattern scanner that suggests a reverse path for encrypt.py-style files
- **Is Not:** A full cryptanalysis framework for AES or modern protocols
- **Is Not:** A web scanner or packet analyzer

## Features

- 9 keyless decoders: Base64, Hex, Binary, ASCII Decimal, A1Z26, ROT13, Reverse, URL Decode, Bytes Literal Extract
- Caesar brute force (shifts1-25, scored and sorted)
- Auto-detects CTF flags: `picoCTF{...}`, `flag{...}`, `CTF{...}`
- Confidence-ranked scoring: HIGH / MEDIUM / LOW / NOISE
- Decoder applicability scoring (0-100): each decoder evaluates how well it fits the input
- Transition policy: dynamically prioritizes decoders based on output characteristics
- Heuristic-guided multi-layer decode: intelligently explores only promising paths
- **Noise suppression**: Reduces base64-like Caesar noise, reverse penalty, and noise family clustering in Top Results
- **Display optimization**: Best Candidate shows Flag line, Top Results use summary format with Output Preview, Applicability Log simplified
- **Compact mode** (`--compact`): Quick view with Best Candidate + Top 3 summary
- Results sorted by confidence score (highest first)
- Markdown report export with Best Candidate section (optimized format)
- Interactive and CLI modes

## Installation

No dependencies required. Uses Python 3.9+ standard library only.

```bash
git clone <repo-url>
cd ctf-decode-helper
```

## Mode Overview

```text
--mode direct-decode   General encoding/classical decode mode (default)
--mode crypto-rsa      RSA parameter scanner and common attack helper
--mode script-reverse  Inspect encrypt.py / solve.py style scripts and suggest reverse flow
```

Backward-compatible aliases are still supported:

```text
--mode decode  -> direct-decode
--mode rsa     -> crypto-rsa
```

## Usage Examples

### Direct input
```bash
python main.py "cGljb0NURnt0ZXN0fQ=="
```

### Interactive mode
```bash
python main.py
# Enter text to decode: cGljb0NURnt0ZXN0fQ==
```

### Export reports
```bash
python3 main.py --report-md reports/result.md "cGljb0NURnt0ZXN0fQ=="
python3 main.py --report-json reports/result.json "cGljb0NURnt0ZXN0fQ=="
```

`--report` is kept as a backward-compatible Markdown report alias.

### File input
```bash
python3 main.py --file samples/base64.txt
python3 main.py --file samples/base64.txt --report reports/file-result.md
```

### Control number of displayed results
```bash
python3 main.py --top 5 "cvpbPGS{grfg}"   # show top 5
python3 main.py --top 0 "cvpbPGS{grfg}"   # show all results
```

### Recursive / multi-layer decode mode

For challenges with nested encodings (e.g. Base64 of a bytes literal containing Base64 of a Caesar-shifted flag):

```bash
python3 main.py --file samples/interencdec-enc_flag.txt --recursive --depth 4 --max-branch 4 --top 10
python3 main.py --file samples/interencdec-enc_flag.txt --recursive --depth 4 --max-branch 4 --top 10 --report reports/interencdec-recursive.md
```

- `--recursive`: Enable heuristic-guided multi-layer decode mode
- `--depth N`: Maximum recursion depth (default: 3)
- `--max-branch N`: Maximum decoders to expand per layer (default: 5)
- Flag-finding chains are automatically boosted in score and ranked first
- Each decoder computes an applicability score (0-100) for the current input
- Transition policy dynamically prioritizes decoders based on output type
- Only high-applicability decoders are expanded, avoiding combinatorial explosion

#### Debug mode

Use `--show-applicability` to see how each layer evaluates decoder applicability:

```bash
python3 main.py --file samples/interencdec-enc_flag.txt --recursive --depth 4 --max-branch 4 --show-applicability --top 10
```


### RSA helper mode

```bash
python3 main.py --mode crypto-rsa --file samples/small-trouble-message.txt --report-md reports/rsa-auto-demo.md
python3 main.py --mode crypto-rsa --n <n> --e <e> --c <c>
```

Current RSA helper behavior:

- Extracts `n`, `e`, `c`, and optional `p`, `q`, `phi`, `d`, `dp`, `dq`, `qinv` from text files
- Supports indexed multi-ciphertext fields such as `n1/e1/c1`, `n2/e2/c2`, `e1/c1`, `e2/c2` with shared `n`
- Uses direct `d` when present
- Uses `p/q` to compute `phi` and recover `d`
- Checks common modulus attack for same-`n`, different-`e` ciphertext pairs
- Checks broadcast attack for same small `e` across multiple coprime moduli
- Checks `e=3` low-exponent cube-root case
- Checks Fermat factorization when `p` and `q` are close
- Checks small-n factorization with trial division and Pollard Rho fallback for toy/CTF-sized cases
- Runs Wiener attack for small private exponent challenges such as Small Trouble
- Does not fabricate flags; it only reports flags actually present in recovered plaintext

RSA validation samples:

```bash
python3 main.py --mode crypto-rsa --file samples/rsa_fermat_test.txt
python3 main.py --mode crypto-rsa --file samples/rsa_common_modulus_test.txt
python3 main.py --mode crypto-rsa --file samples/rsa_broadcast_test.txt
python3 main.py --mode crypto-rsa --file samples/rsa_small_n_factor_test.txt
```

### Script reverse mode

```bash
python3 main.py --mode script-reverse --file encrypt.py --report-md reports/script-reverse.md
```

This mode does not execute the challenge script. It statically scans for patterns such as:

- `pow(m, e, n)`
- `bytes_to_long()` / `long_to_bytes()`
- `getPrime()`
- `inverse()`
- XOR / `ord()` / `chr()` / Base64 / `random.seed()`

It then outputs detected signals, likely challenge type, and a suggested reverse plan.

## Real Case Workflow

For step-by-step instructions on how to use the tool against real picoCTF challenges, see [docs/real-case-workflow.md](docs/real-case-workflow.md).

Quick example:
```bash
python3 main.py --report reports/real-case-13.md --top 10 "cvpbPGS{grfg}"
```

## Supported Decoders

| Decoder | Description |
|---|---|
| BASE64 | Standard Base64 with auto-padding |
| HEX | Hexadecimal to ASCII |
| BINARY | Binary (8-bit groups) to ASCII |
| ASCII_DECIMAL | Space-separated decimal (0-255) to ASCII |
| A1Z26 | A1Z26 cipher: 1=A, 2=B, ..., 26=Z (supports {, }, _) |
| ROT13 | ROT13 cipher (a-z, A-Z) |
| REVERSE | Reverse the string |
| URL_DECODE | URL percent-encoding |
| BYTES_LITERAL_EXTRACT | Extract content from Python bytes literal (`b'...'` or `b"..."`) |
| CAESAR_SHIFT_1-25 | Caesar brute force (all 25 shifts, scored and sorted) |

## Example Output

### Single-pass mode

```
==================================================
 CTF Decode Helper
==================================================

[INPUT]
cGljb0NURnt0ZXN0fQ==

[TOP RESULTS]

--------------------------------------------------
[1] BASE64
Status: success
Score: 1120
Confidence: HIGH
Flags:
  - picoCTF{test}

Output:
picoCTF{test}
```

### Recursive mode (interencdec)

```
==================================================
 CTF Decode Helper
==================================================

[Recursive / Depth 4 / Max-Branch 5]
[INPUT]
YidkM0JxZGtw...

[BEST CANDIDATE]

Flag: picoCTF{caesar_d3cr9pt3d_78250afc}
Score: 1170
Confidence: HIGH
Chain:
BASE64 -> BYTES_LITERAL_EXTRACT -> BASE64 -> CAESAR_SHIFT_19

[OUTPUT]
picoCTF{caesar_d3cr9pt3d_78250afc}

[TOP RESULTS]

--------------------------------------------------
[1] CAESAR_SHIFT_19
Score: 1170 | Confidence: HIGH
Chain: BASE64 -> BYTES_LITERAL_EXTRACT -> BASE64 -> CAESAR_SHIFT_19
Flags:
  - picoCTF{caesar_d3cr9pt3d_78250afc}
Output Preview:
picoCTF{caesar_d3cr9pt3d_78250afc}

--------------------------------------------------
[2] BASE64
Score: 140 | Confidence: MEDIUM
Chain: BASE64
Output Preview:
b'd3BqdkpBTXtqaGx6aHlfazNq...'

--------------------------------------------------
[3] BYTES_LITERAL_EXTRACT
Score: 140 | Confidence: MEDIUM
Chain: BASE64 -> BYTES_LITERAL_EXTRACT
Output Preview:
d3BqdkpBTXtqaGx6aHlfazNq...'
```

## Project Structure

```
ctf-decode-helper/
├── main.py                 # CLI entry point
├── README.md               # This file
├── requirements.txt        # Dependencies (empty, stdlib only)
├── MEMORY.md               # Long-term project context
├── WORKLOG.md              # What was done
├── NEXT.md                 # Next steps
├── DECISIONS.md            # Architecture decisions
├── src/
│   ├── __init__.py
│   ├── models.py           # DecodeResult dataclass
│   ├── decoder_engine.py   # Run all decoders, sort results
│   ├── decoders.py         # Individual decoder functions
│   ├── detector.py         # Flag detection and scoring
│   ├── reporter.py         # Markdown report generation
│   └── utils.py            # Terminal output helpers
├── samples/                # Sample input files
├── reports/                # Generated reports
├── tests/                  # Unit tests
└── docs/                   # Documentation
```

## Limitations

- No support for AES, RSA, or other key-based crypto
- No image, packet, or web analysis
- Scoring is heuristic-based; may produce false positives
- Reversed flags are not auto-detected (REVERSE decoder shows output, but flag detector requires human recognition)
- Applicability scoring uses simple pattern matching; may miss edge cases
- See [docs/search-policy.md](docs/search-policy.md) for details on how applicability and transition policy work

## Validation

### v0.5.2 Showcase

Full feature showcase with real challenge examples and noise suppression details:
- [reports/v0.5.2-showcase.md](reports/v0.5.2-showcase.md)

### Internal Validation (Synthetic)

Synthetic picoCTF-style test cases covering all supported encodings:
- [reports/internal-validation-log.md](reports/internal-validation-log.md)
- 12 cases: Base64, Hex, Binary, ROT13, URL, ASCII Decimal, Reverse, and feature tests
- Status: All PASS or expected PARTIAL

### Real picoCTF Challenge Validation

Validation against actual picoCTF challenges:
- [reports/real-pico-validation-log.md](reports/real-pico-validation-log.md)
- 4 targets: 13, interencdec, The Numbers, Mod 26
- Status: 4/4 solved (3 direct, 1 recursive with interencdec)
- Current status: 74 tests passing, noise cleanup complete, Best Candidate correct

## Future Work

- Morse code decoder
- Base32 / Base85 support
- XOR with key (single-byte brute force) - only after real challenge validation requires it
- Vigenere cipher
- Crypto Mode (AES, RSA, etc.)
- Improved readability scoring
- PicoCTF API integration for auto-fetching challenges
- Result dedup by identical decoded outputs and semantic equivalence
- JSON report output
- Fine-tune applicability scoring based on more real challenge data
