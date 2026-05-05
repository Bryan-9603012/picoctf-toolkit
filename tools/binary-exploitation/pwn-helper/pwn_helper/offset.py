
from __future__ import annotations
from pwn_helper.utils import which

def find_offset(binary: str, length: int = 400):
    if which("gdb") is None:
        raise RuntimeError("gdb not found")
    return {
        "status": "manual-needed",
        "message": "自動 offset 對所有題型不穩，建議用 cyclic + core/gdb。此工具先提供模式入口。",
        "pattern_length": length,
    }
