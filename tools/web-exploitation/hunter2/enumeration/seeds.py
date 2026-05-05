# enumeration/seeds.py
from __future__ import annotations

from typing import List


def read_seeds_file(path: str) -> List[str]:
    if not path:
        return []
    out: List[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                out.append(s)
    except Exception:
        return []
    return out


def normalize_seeds(seeds: List[str]) -> List[str]:
    out: List[str] = []
    for s in seeds or []:
        s = str(s).strip()
        if not s:
            continue
        if not s.startswith("/"):
            s = "/" + s
        out.append(s)
    return sorted(set(out))