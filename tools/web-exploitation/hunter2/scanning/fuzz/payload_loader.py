# scanning/fuzz/payload_loader.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List
import os


@dataclass
class PayloadSet:
    name: str
    items: List[str]


def load_payloads(payload_dir: str) -> Dict[str, PayloadSet]:
    db: Dict[str, PayloadSet] = {}
    if not os.path.isdir(payload_dir):
        return db

    for fn in sorted(os.listdir(payload_dir)):
        if not fn.endswith(".txt"):
            continue
        name = fn[:-4]
        path = os.path.join(payload_dir, fn)
        items: List[str] = []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                items.append(line)
        db[name] = PayloadSet(name=name, items=items)
    return db