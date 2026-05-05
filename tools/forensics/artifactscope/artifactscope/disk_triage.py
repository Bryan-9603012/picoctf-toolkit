#!/usr/bin/env python3
"""
disk_triage.py

A general-purpose disk image triage tool for CTF / forensic disk image challenges.

Features:
- Basic image metadata (size, MD5, SHA256, estimated entropy)
- Search for picoCTF-style and generic CTF flag patterns directly in raw bytes
- Extract printable strings to a text file
- Search for common forensic clues in strings:
  - Git artifacts
  - SSH keys
  - AWS keys
  - Private key headers
  - URLs, emails, IPv4
  - archive / document / script / config hints
- Produce a concise Markdown report

Usage:
    py -3.13 disk_triage.py disk.img
    py -3.13 disk_triage.py disk.img --max-strings 500000
"""

from __future__ import annotations

import argparse
import hashlib
import math
import re
from collections import Counter
from pathlib import Path
from typing import Iterable


ASCII_STRING_RE = re.compile(rb"[ -~]{4,}")

RAW_FLAG_PATTERNS = [
    re.compile(rb"picoCTF\{[^}\r\n]{1,300}\}"),
    re.compile(rb"flag\{[^}\r\n]{1,300}\}", re.IGNORECASE),
    re.compile(rb"ctf\{[^}\r\n]{1,300}\}", re.IGNORECASE),
]

STRING_PATTERNS = {
    "flag_like": [
        re.compile(r"picoCTF\{[^}\r\n]{1,300}\}"),
        re.compile(r"flag\{[^}\r\n]{1,300}\}", re.IGNORECASE),
        re.compile(r"ctf\{[^}\r\n]{1,300}\}", re.IGNORECASE),
    ],
    "git": [
        re.compile(r"\.git"),
        re.compile(r"refs/heads"),
        re.compile(r"ref: refs/"),
        re.compile(r"objects/[0-9a-f]{2}/[0-9a-f]{38}"),
        re.compile(r"packed-refs"),
        re.compile(r"COMMIT_EDITMSG"),
    ],
    "keys_and_secrets": [
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        re.compile(r"ssh-rsa "),
        re.compile(r"ssh-ed25519 "),
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        re.compile(r"(token|secret|password|passwd|apikey|api_key)\s*[:=]\s*\S+", re.IGNORECASE),
    ],
    "network_and_identity": [
        re.compile(r"https?://\S+"),
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    ],
    "interesting_files": [
        re.compile(r"\.(zip|7z|rar|tar|gz|tgz|bz2)\b", re.IGNORECASE),
        re.compile(r"\.(docx?|xlsx?|pptx?|pdf)\b", re.IGNORECASE),
        re.compile(r"\.(sqlite|db|kdbx)\b", re.IGNORECASE),
        re.compile(r"\.(bash_history|zsh_history|viminfo)\b", re.IGNORECASE),
        re.compile(r"\.(py|sh|ps1|bat|php|js)\b", re.IGNORECASE),
        re.compile(r"/etc/passwd"),
        re.compile(r"/etc/shadow"),
        re.compile(r"authorized_keys"),
        re.compile(r"id_rsa"),
    ],
}


def md5_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.md5()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def estimate_entropy(path: Path, sample_size: int = 4 * 1024 * 1024) -> float:
    total_size = path.stat().st_size
    with path.open("rb") as f:
        data = f.read(min(sample_size, total_size))
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def extract_strings(data: bytes, max_strings: int) -> list[str]:
    out: list[str] = []
    for match in ASCII_STRING_RE.finditer(data):
        out.append(match.group().decode("ascii", errors="ignore"))
        if len(out) >= max_strings:
            break
    return out


def search_raw_flags(data: bytes) -> list[str]:
    hits = set()
    for pattern in RAW_FLAG_PATTERNS:
        for m in pattern.finditer(data):
            hits.add(m.group().decode("latin-1", errors="replace"))
    return sorted(hits)


def search_string_patterns(strings: Iterable[str]) -> dict[str, list[str]]:
    results: dict[str, list[str]] = {}
    strings_list = list(strings)
    for category, patterns in STRING_PATTERNS.items():
        matched: list[str] = []
        seen = set()
        for pattern in patterns:
            for s in strings_list:
                if pattern.search(s) and s not in seen:
                    matched.append(s)
                    seen.add(s)
                    if len(matched) >= 80:
                        break
            if len(matched) >= 80:
                break
        if matched:
            results[category] = matched
    return results


def write_report(
    image: Path,
    out_dir: Path,
    size: int,
    md5: str,
    sha256: str,
    entropy: float,
    raw_flag_hits: list[str],
    string_pattern_hits: dict[str, list[str]],
) -> Path:
    report_path = out_dir / "report.md"
    with report_path.open("w", encoding="utf-8") as rep:
        rep.write("# Disk Image Triage Report\n\n")
        rep.write(f"- Image: `{image}`\n")
        rep.write(f"- Size: `{size}` bytes\n")
        rep.write(f"- MD5: `{md5}`\n")
        rep.write(f"- SHA256: `{sha256}`\n")
        rep.write(f"- Estimated entropy (first 4 MiB): `{entropy:.3f}`\n\n")

        rep.write("## Direct Flag Candidates in Raw Bytes\n\n")
        if raw_flag_hits:
            for item in raw_flag_hits:
                rep.write(f"- `{item}`\n")
        else:
            rep.write("- None found directly in raw bytes.\n")
        rep.write("\n")

        rep.write("## Interesting Pattern Hits in Extracted Strings\n\n")
        if string_pattern_hits:
            for category, hits in string_pattern_hits.items():
                rep.write(f"### {category}\n\n")
                for item in hits[:40]:
                    cleaned = item.replace("`", "'")
                    rep.write(f"- `{cleaned[:300]}`\n")
                rep.write("\n")
        else:
            rep.write("- No notable pattern hits found.\n")
        rep.write("\n")

        rep.write("## Suggested Next Steps\n\n")
        if raw_flag_hits:
            rep.write("- Validate the direct flag candidate first.\n")
        else:
            rep.write("- Review `strings.txt` and the pattern hits above.\n")
            rep.write("- If Git-like hits exist, inspect repository-related artifacts.\n")
            rep.write("- If keys/secrets or config paths exist, pivot into those files.\n")
            rep.write("- If nothing useful appears, move to filesystem-aware tooling such as mmls, fls, icat, binwalk, or Autopsy.\n")
    return report_path


def main() -> int:
    parser = argparse.ArgumentParser(description="General-purpose disk image triage tool")
    parser.add_argument("image", type=Path, help="Path to disk image, raw blob, or forensic file")
    parser.add_argument("--max-strings", type=int, default=200000, help="Maximum number of printable strings to extract")
    args = parser.parse_args()

    image = args.image
    if not image.exists():
        print(f"[!] File not found: {image}")
        return 1

    out_dir = Path("output_triage")
    out_dir.mkdir(exist_ok=True)

    print(f"[*] Reading image: {image}")
    data = image.read_bytes()

    print("[*] Computing metadata...")
    size = image.stat().st_size
    md5 = md5_file(image)
    sha256 = sha256_file(image)
    entropy = estimate_entropy(image)

    print("[*] Searching raw bytes for direct flag patterns...")
    raw_flag_hits = search_raw_flags(data)

    print("[*] Extracting printable strings...")
    strings = extract_strings(data, args.max_strings)
    strings_path = out_dir / "strings.txt"
    strings_path.write_text("\n".join(strings), encoding="utf-8", errors="ignore")

    print("[*] Searching extracted strings for forensic clues...")
    string_pattern_hits = search_string_patterns(strings)

    report_path = write_report(
        image=image,
        out_dir=out_dir,
        size=size,
        md5=md5,
        sha256=sha256,
        entropy=entropy,
        raw_flag_hits=raw_flag_hits,
        string_pattern_hits=string_pattern_hits,
    )

    print("[+] Done.")
    print(f"[+] Strings written to: {strings_path}")
    print(f"[+] Report written to:  {report_path}")
    if raw_flag_hits:
        print("[+] Direct flag candidate(s):")
        for hit in raw_flag_hits:
            print(f"    {hit}")
    else:
        print("[*] No direct flag candidate found. Review output_triage/report.md and output_triage/strings.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
