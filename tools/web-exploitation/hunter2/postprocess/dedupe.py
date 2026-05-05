# postprocess/dedupe.py
from __future__ import annotations

from typing import Dict, List
from core.models import Finding


def _is_chain_like(f: Finding) -> bool:
    n = (getattr(f, "name", "") or "").lower()
    c = (getattr(f, "category", "") or "").lower()
    t = " ".join(getattr(f, "tags", []) or []).lower()
    return ("chain" in n) or ("chain" in c) or ("chain" in t)


def dedupe_findings_prefer_chain(findings: List[Finding]) -> List[Finding]:
    best: Dict[str, Finding] = {}
    for f in findings:
        url = f.url
        if url not in best:
            best[url] = f
            continue

        cur = best[url]
        cur_chain = _is_chain_like(cur)
        new_chain = _is_chain_like(f)

        if new_chain and not cur_chain:
            best[url] = f
            continue
        if cur_chain and not new_chain:
            continue

        if getattr(f, "risk_score", 0) > getattr(cur, "risk_score", 0):
            best[url] = f
            continue

        cur_ev = getattr(cur, "evidence", None)
        new_ev = getattr(f, "evidence", None)
        cur_strength = int(bool(getattr(cur_ev, "artifact", None))) + int(bool(getattr(cur_ev, "snippet", None))) + int(bool(getattr(cur, "matches", [])))
        new_strength = int(bool(getattr(new_ev, "artifact", None))) + int(bool(getattr(new_ev, "snippet", None))) + int(bool(getattr(f, "matches", [])))
        if new_strength > cur_strength:
            best[url] = f

    return list(best.values())