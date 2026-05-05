from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
BASE64_RE = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")

SUSPICIOUS_TERMS = [
    "powershell",
    "cmd.exe",
    "/bin/sh",
    "/bin/bash",
    "wget",
    "curl",
    "nc ",
    "ncat",
    "netcat",
    "eval(",
    "exec(",
    "system(",
    "token",
    "password",
    "secret",
    "flag",
    "base64",
]

GIT_PATTERNS = [
    ".git",
    ".git/HEAD",
    ".git/index",
    ".git/config",
    ".git/refs",
    "refs/heads",
    "refs/tags",
    "refs/remotes",
    "HEAD",
    "commit ",
    "Author: ",
    "Date: ",
    "git-svn-id",
    "gitdir:",
    "objects/",
    "packed-refs",
    "tree ",
    "blob ",
]

GIT_INDICATOR_STRINGS = [
    ".git/HEAD",
    ".git/index",
    ".git/config",
    ".git/refs/heads",
    "refs/heads/",
    "refs/tags/",
    "packed-refs",
    "objects/",
    "gitdir:",
]

GIT_FILES = [
    ".git/HEAD",
    ".git/index",
    ".git/config",
    ".git/objects",
    ".git/refs/heads",
    ".git/hooks",
    ".git/logs",
]

FLAG_PATTERNS = [
    "picoCTF{",
    "flag{",
    "CTF{",
    "actf{",
    "dctf{",
]

FLAG_REGEXES = [
    r"picoCTF\{[^}\r\n]{1,100}\}",
    r"flag\{[^}\r\n]{1,100}\}",
    r"ACTF\{[^}\r\n]{1,100}\}",
    r"DCTF\{[^}\r\n]{1,100}\}",
]

CONTENT_SCAN_PATTERNS = [
    "picoCTF{",
    "pico",
    "flag{",
    "secret",
    "password",
    "key",
    "ssh",
    "id_rsa",
]

BINARY_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".elf", ".bin", ".dat", ".db", ".sqlite",
}


def _is_binary_file(file_path: Path) -> bool:
    return file_path.suffix.lower() in BINARY_EXTENSIONS or file_path.stat().st_size > 5 * 1024 * 1024


def _run_strings(file_path: Path, timeout: int = 30) -> Tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["strings", str(file_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode == 0, proc.stdout
    except Exception:
        return False, ""


def extract_ascii_strings(data: bytes, min_length: int = 4, max_results: int = 500) -> List[str]:
    pattern = re.compile(rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}")
    strings = [m.decode("utf-8", errors="replace") for m in pattern.findall(data)]
    return strings[:max_results]


def analyze_strings(data: bytes, max_results: int = 500) -> Dict[str, object]:
    strings = extract_ascii_strings(data, max_results=max_results)
    joined = "\n".join(strings)

    urls = _unique(URL_RE.findall(joined))
    emails = _unique(EMAIL_RE.findall(joined))
    ips = _unique([ip for ip in IP_RE.findall(joined) if _valid_ipv4(ip)])
    base64_like = _unique(BASE64_RE.findall(joined))
    suspicious = _unique([s for s in strings if any(term.lower() in s.lower() for term in SUSPICIOUS_TERMS)])

    suspicious_details = []
    for s in strings:
        offset = data.find(s.encode("utf-8", errors="replace"))
        if offset == -1:
            continue
        match_lower = s.lower()
        for term in SUSPICIOUS_TERMS:
            if term.lower() in match_lower:
                start_ctx = max(0, offset - 20)
                end_ctx = min(len(data), offset + len(s) + 20)
                context = data[start_ctx:end_ctx].decode("utf-8", errors="replace")
                suspicious_details.append({
                    "pattern": term,
                    "string": s[:100],
                    "offset": offset,
                    "context": context,
                    "source": "string_scan",
                })
                break

    return {
        "sample_strings": strings[:50],
        "urls": urls[:50],
        "emails": emails[:50],
        "ips": ips[:50],
        "base64_like": base64_like[:50],
        "suspicious_strings": suspicious[:50],
        "suspicious_details": suspicious_details[:20],
    }


def _unique(items: List[str]) -> List[str]:
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _valid_ipv4(ip: str) -> bool:
    try:
        parts = [int(p) for p in ip.split(".")]
    except ValueError:
        return False
    return len(parts) == 4 and all(0 <= p <= 255 for p in parts)


def detect_git_artifacts(strings: List[str], sample_strings: List[str], raw_git_indicators: Optional[List[object]] = None) -> Dict[str, object]:
    all_text = "\n".join(sample_strings) + "\n" + "\n".join(strings)

    found_git_files = []
    for pattern in GIT_FILES:
        if pattern in all_text or pattern.replace("/", "\\") in all_text:
            found_git_files.append(pattern)

    found_indicators = []
    for indicator in GIT_INDICATOR_STRINGS:
        windows_indicator = indicator.replace("/", "\\")
        if indicator in all_text or windows_indicator in all_text:
            found_indicators.append(indicator)

    found_git_refs = []
    refs_pattern = re.compile(r"refs/(heads|tags|remotes)/[^\s]+")
    for s in strings:
        for m in refs_pattern.findall(s):
            found_git_refs.append(s)

    found_commits = []
    commit_hash = re.compile(r"[0-9a-f]{40}|\b[0-9a-f]{7,40}\b")
    for s in strings:
        if commit_hash.match(s) and len(s) <= 50:
            found_commits.append(s[:50])

    has_config = False
    has_branch_ref = False
    has_logs = False
    has_objects = False
    has_pico_flag = False

    for gf in found_git_files:
        if "config" in gf:
            has_config = True
        if "refs/heads" in gf:
            has_branch_ref = True
        if "logs" in gf:
            has_logs = True
        if "objects" in gf:
            has_objects = True

    if raw_git_indicators:
        for ind in raw_git_indicators:
            marker = ind.get("marker", "")
            if "config" in marker:
                has_config = True
            if "branch" in marker.lower():
                has_branch_ref = True
            if "logs" in marker:
                has_logs = True
            if "objects" in marker:
                has_objects = True

    for s in strings:
        if "picoCTF{" in s or "flag{" in s.lower():
            has_pico_flag = True

    raw_count = len(raw_git_indicators) if raw_git_indicators else 0
    total_indicators = len(found_git_files) + len(found_indicators) + raw_count

    if has_pico_flag and total_indicators > 0:
        confidence = "critical"
    elif has_logs or has_objects:
        confidence = "high"
    elif (has_config and has_branch_ref) or total_indicators >= 3:
        confidence = "medium"
    elif total_indicators >= 1:
        confidence = "low"
    else:
        confidence = "none"

    return {
        "git_files": _unique(found_git_files),
        "git_related_strings": _unique(found_indicators),
        "git_refs": _unique(found_git_refs)[:20],
        "commit_hashes": _unique(found_commits)[:20],
        "confidence": confidence,
        "indicator_count": total_indicators,
    }


def detect_flag_patterns(strings: List[str], all_text: str = "") -> List[Dict[str, str]]:
    flags = []
    seen = set()

    for regex_pattern in FLAG_REGEXES:
        regex = re.compile(regex_pattern, re.IGNORECASE)
        for match in regex.finditer(all_text):
            flag_str = match.group(0)
            if flag_str not in seen and len(flag_str) < 100:
                flags.append({
                    "pattern": regex_pattern,
                    "match": flag_str,
                })
                seen.add(flag_str)

    for pattern_str in FLAG_PATTERNS:
        pattern_lower = pattern_str.lower()
        for source_text in list(strings) + ([all_text] if all_text else []):
            source_lower = source_text.lower()
            search_start = 0
            while True:
                idx = source_lower.find(pattern_lower, search_start)
                if idx == -1:
                    break

                # Avoid counting the generic CTF{...} substring inside picoCTF{...}.
                if pattern_lower == "ctf{" and idx >= 4 and source_lower[idx - 4:idx] == "pico":
                    search_start = idx + len(pattern_str)
                    continue

                closing = source_text.find("}", idx)
                if closing != -1 and closing - idx <= 120:
                    candidate = source_text[idx:closing + 1]
                else:
                    candidate = source_text[idx:idx + 120].splitlines()[0]

                if candidate and candidate not in seen:
                    flags.append({
                        "pattern": pattern_str,
                        "match": candidate,
                    })
                    seen.add(candidate)

                search_start = idx + len(pattern_str)

    return flags[:50]


def content_scan_extracted(
    extracted_dir: Path,
    partitions: Optional[List[Dict[str, object]]] = None,
) -> List[Dict[str, object]]:
    results: List[Dict[str, object]] = []

    if not extracted_dir.exists() or not extracted_dir.is_dir():
        return results

    for file_path in extracted_dir.rglob("*"):
        if not file_path.is_file():
            continue

        source_path = str(file_path)
        partition = "unknown"
        inode = None

        if partitions:
            try:
                stat = file_path.stat()
                file_size = stat.st_size
                for p in partitions:
                    p_start = int(p.get("offset_bytes", 0) or 0)
                    p_size = int(p.get("size_bytes", 0) or 0)
                    if p_start <= file_size <= p_start + p_size:
                        partition = f"p{p.get('partition', '?')}"
                        break
            except Exception:
                pass

        is_binary = _is_binary_file(file_path)
        scan_text = ""

        try:
            if is_binary:
                success, scan_text = _run_strings(file_path)
                if not success:
                    try:
                        scan_text = file_path.read_text(errors="replace")[:10000]
                    except Exception:
                        continue
            else:
                scan_text = file_path.read_text(errors="replace")
        except Exception:
            continue

        if not scan_text or not scan_text.strip():
            continue

        strings_list = extract_ascii_strings(scan_text.encode("utf-8", errors="replace"), max_results=200)

        for pattern in CONTENT_SCAN_PATTERNS:
            pattern_lower = pattern.lower()
            text_lower = scan_text.lower()

            for match_idx in _find_overlapping(text_lower, pattern_lower):
                start_ctx = max(0, match_idx - 30)
                end_ctx = min(len(scan_text), match_idx + len(pattern) + 30)
                context = scan_text[start_ctx:end_ctx]

                results.append({
                    "source_file": source_path,
                    "partition": partition,
                    "inode": inode,
                    "matched_pattern": pattern,
                    "context": context[:200],
                    "offset": match_idx,
                })

        for s in strings_list:
            s_lower = s.lower()
            for pattern in CONTENT_SCAN_PATTERNS:
                if pattern.lower() in s_lower:
                    results.append({
                        "source_file": source_path,
                        "partition": partition,
                        "inode": inode,
                        "matched_pattern": pattern,
                        "context": s[:200],
                        "offset": 0,
                    })
                    break

    return results[:100]


def _find_overlapping(text: str, pattern: str) -> List[int]:
    positions = []
    start = 0
    while True:
        idx = text.find(pattern, start)
        if idx == -1:
            break
        positions.append(idx)
        start = idx + 1
    return positions
