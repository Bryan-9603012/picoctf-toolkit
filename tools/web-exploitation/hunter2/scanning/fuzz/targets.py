# scanning/fuzz/targets.py
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class FuzzTarget:
    template_path: str   # e.g. "/download?file=FUZZ"
    payload_set: str     # e.g. "lfi"
    method: str = "GET"