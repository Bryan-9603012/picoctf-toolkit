# postprocess/ctf.py
from __future__ import annotations

import base64
import re
from typing import Any, Dict, List, Optional, Tuple

from core.models import Finding


FLAG_PATTERNS = [
    (re.compile(r"picoCTF\{[^}]+\}", re.IGNORECASE), "picoCTF"),
    (re.compile(r"flag\{[^}]+\}", re.IGNORECASE), "flag"),
    (re.compile(r"CTF\{[^}]+\}", re.IGNORECASE), "CTF"),
    (re.compile(r"\{[A-Za-z0-9_-]{31,}\}", re.IGNORECASE), "generic"),
]

ENCODED_FLAG_PATTERNS = [
    (re.compile(r"[A-Za-z0-9+/]{20,}={0,2}"), "base64"),
    (re.compile(r"[0-9a-f]{20,}"), "hex"),
]

HIDDEN_PATTERNS = [
    (re.compile(r"<input[^>]+type\s*=\s*['\"]hidden['\"]", re.I), "hidden_input"),
    (re.compile(r"<!--[^-]*-->", re.I), "html_comment"),
    (re.compile(r"//\s*[^\n]+", re.I), "js_comment"),
    (re.compile(r"#\s*[^\n]+", re.I), "comment"),
    (re.compile(r"<!--[^-]*-->", re.I), "html_comment"),
]

SUSPICIOUS_EXTENSIONS = [
    ".bak", ".backup", ".old", ".tmp", ".swp",
    ".git", ".svn", ".DS_Store",
    ".tar", ".gz", ".zip", ".7z",
    ".sql", ".db", ".sqlite",
    ".env", ".config", ".conf",
    ".pdf", ".doc", ".docx",
]

HINT_PATTERNS = [
    (re.compile(r"(hint|clue|tip|try|look|search|find)[:\s]+[^\n]{5,50}", re.I), "hint_text"),
    (re.compile(r"(admin|root|backup|database|secret|hidden|private|api)", re.I), "keyword_hint"),
]


def extract_ctf_clues(finding: Finding) -> List[str]:
    clues = []
    
    if finding.evidence and finding.evidence.snippet:
        snippet = finding.evidence.snippet
        
        for pattern, label in HIDDEN_PATTERNS:
            matches = pattern.findall(snippet)
            for m in matches[:3]:
                clues.append(f"hidden_{label}: {m[:80]}")
        
        for pattern, label in HINT_PATTERNS:
            matches = pattern.findall(snippet)
            for m in matches[:3]:
                clues.append(f"hint: {m[:80]}")
        
        for ext in SUSPICIOUS_EXTENSIONS:
            if ext in snippet.lower():
                clues.append(f"suspicious_extension: {ext}")
    
    for kw in ["hidden", "admin", "secret", "backup", "debug"]:
        if kw in finding.url.lower():
            clues.append(f"path_keyword: {kw}")
    
    return clues


def extract_flags(finding: Finding) -> List[Dict[str, Any]]:
    results = []
    
    if not finding.evidence or not finding.evidence.snippet:
        return results
    
    snippet = finding.evidence.snippet
    
    for pattern, flag_type in FLAG_PATTERNS:
        matches = pattern.findall(snippet)
        for match in matches:
            results.append({
                "flag": match,
                "type": flag_type,
                "source": "snippet",
                "url": finding.url,
                "confidence": "high",
            })
    
    for pattern, enc_type in ENCODED_FLAG_PATTERNS:
        candidates = pattern.findall(snippet)
        for cand in candidates[:5]:
            decoded = try_decode(cand, enc_type)
            if decoded and is_likely_flag(decoded):
                results.append({
                    "flag": decoded,
                    "type": f"decoded_{enc_type}",
                    "original": cand,
                    "source": "decoded",
                    "url": finding.url,
                    "confidence": "medium",
                })
    
    return results


def try_decode(text: str, enc_type: str) -> Optional[str]:
    if enc_type == "base64":
        try:
            return base64.b64decode(text).decode("utf-8", errors="ignore")
        except:
            pass
    elif enc_type == "hex":
        try:
            return bytes.fromhex(text).decode("utf-8", errors="ignore")
        except:
            pass
    return None


def is_likely_flag(text: str) -> bool:
    text = text.strip()
    if len(text) < 10 or len(text) > 100:
        return False
    text_lower = text.lower()
    if any(f in text_lower for f in ["picoctf", "flag{", "ctf{"]):
        return True
    return False


def extract_all_ctf_data(findings: List[Finding]) -> Tuple[List[str], List[str]]:
    all_flags = []
    all_clues = []
    
    for f in findings:
        flags = extract_flags(f)
        for flag_info in flags:
            all_flags.append(flag_info["flag"])
        
        clues = extract_ctf_clues(f)
        all_clues.extend(clues)
        
        if hasattr(f, "clues"):
            f.clues.extend(clues)
    
    seen_flags = set()
    unique_flags = []
    for flag in all_flags:
        if flag not in seen_flags:
            seen_flags.add(flag)
            unique_flags.append(flag)
    
    seen_clues = set()
    unique_clues = []
    for clue in all_clues:
        if clue not in seen_clues:
            seen_clues.add(clue)
            unique_clues.append(clue)
    
    return unique_flags, unique_clues
