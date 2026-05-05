from __future__ import annotations

from pathlib import Path
from typing import Iterable


def human_size(size: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size)
    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            return f"{value:.2f} {unit}"
        value /= 1024.0
    return f"{size} B"


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def safe_read_bytes(path: Path) -> bytes:
    return path.read_bytes()


def iter_files(target: Path, recursive: bool = False) -> Iterable[Path]:
    if target.is_file():
        yield target
        return

    pattern = "**/*" if recursive else "*"
    for item in target.glob(pattern):
        if item.is_file():
            yield item
