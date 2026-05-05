# MEMORY.md - ctf-decode-helper

## Project Purpose
Semi-automated decode helper for CTF challenges. Takes a suspicious string, tries multiple keyless decoders, detects possible flags, scores results, and displays sorted output.

## What this tool is
- A decode helper that generates candidate outputs for human review
- Supports keyless encodings: Base64, Hex, Binary, ASCII decimal, ROT13, Reverse, URL Decode
- Auto-detects CTF flags (picoCTF{}, flag{}, CTF{})
- Scores results by readability and keyword detection
- Exports markdown reports

## What this tool is NOT
- Not a fully automated CTF solver
- Not a crypto attack tool (no AES, RSA, etc.)
- Not a web scanner or packet analyzer

## Coding Style
- Python standard library only for v0.1
- Clean module boundaries
- Defensive error handling; decoders must never crash the tool
- Dataclass for unified result format (DecodeResult)
- CLI-first design

## Scoring System
- picoCTF{...} found: +100
- flag{...} found: +80
- CTF{...} found: +70
- High readability: +20
- Contains keywords (ctf, flag, secret, key, token, etc.): +20
- High garbage ratio: penalty
- Output too short: small penalty
