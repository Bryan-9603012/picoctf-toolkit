# core/secrets.py
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class SecretHit:
    kind: str
    value: str


RXES: List[Tuple[str, re.Pattern]] = [
    ("picoctf_flag", re.compile(r"picoCTF\{[^}]+\}", re.IGNORECASE)),
    ("jwt", re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("api_key_generic", re.compile(r"(?i)\b(api[_-]?key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{12,})")),
    ("bearer", re.compile(r"(?i)\bBearer\s+([A-Za-z0-9\-._~+/]+=*)")),
]


def scan_text(text: str, *, max_hits: int = 20) -> List[SecretHit]:
    if not text:
        return []
    hits: List[SecretHit] = []
    for kind, rx in RXES:
        for m in rx.finditer(text):
            if len(hits) >= max_hits:
                return hits
            if kind == "api_key_generic":
                val = m.group(2)
            elif m.groups():
                val = m.group(1)
            else:
                val = m.group(0)
            val = val.strip()
            if len(val) > 200:
                val = val[:200] + "…"
            hits.append(SecretHit(kind=kind, value=val))
    return hits


def content_type_allows(ct: str) -> bool:
    ct = (ct or "").lower()
    return (
        ("text/" in ct)
        or ("application/json" in ct)
        or ("application/javascript" in ct)
        or ("application/xml" in ct)
        or ("application/xhtml" in ct)
    )