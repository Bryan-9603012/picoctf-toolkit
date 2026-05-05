from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict


def _hash_file(path: Path, algorithm: str, chunk_size: int = 65536) -> str:
    h = hashlib.new(algorithm)
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def compute_hashes(path: Path) -> Dict[str, str]:
    return {
        "md5": _hash_file(path, "md5"),
        "sha1": _hash_file(path, "sha1"),
        "sha256": _hash_file(path, "sha256"),
    }
