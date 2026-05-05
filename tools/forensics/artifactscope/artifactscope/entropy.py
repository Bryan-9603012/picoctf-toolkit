from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def classify_entropy(score: float) -> str:
    if score < 3.5:
        return "low"
    if score < 6.5:
        return "medium"
    if score < 7.5:
        return "high"
    return "very_high"
