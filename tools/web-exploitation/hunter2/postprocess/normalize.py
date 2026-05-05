# postprocess/normalize.py
from __future__ import annotations

from typing import List

from core.models import Finding
from core.utils import normalize_url


def normalize_findings(findings: List[Finding]) -> List[Finding]:
    """
    Normalize fields for consistent dedupe/report:
    - normalize URL
    - normalize tags to lower
    - trim matches length
    """
    out: List[Finding] = []
    for f in findings:
        try:
            f.url = normalize_url(f.url)
        except Exception:
            pass

        # tags normalize
        if f.tags:
            f.tags = sorted({str(t).strip().lower() for t in f.tags if str(t).strip()})

        # matches trim
        if f.matches:
            f.matches = [str(m)[:300] for m in f.matches[:50]]

        # evidence snippet trim
        if f.evidence and f.evidence.snippet:
            f.evidence.snippet = str(f.evidence.snippet)[:3000]

        out.append(f)
    return out