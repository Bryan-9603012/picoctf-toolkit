from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional


SIGNATURES: List[Dict[str, object]] = [
    {"name": "PNG image", "type": "png", "offset": 0, "magic": b"\x89PNG\r\n\x1a\n", "extensions": [".png"]},
    {"name": "JPEG image", "type": "jpg", "offset": 0, "magic": b"\xff\xd8\xff", "extensions": [".jpg", ".jpeg"]},
    {"name": "GIF image", "type": "gif", "offset": 0, "magic": b"GIF8", "extensions": [".gif"]},
    {"name": "PDF document", "type": "pdf", "offset": 0, "magic": b"%PDF", "extensions": [".pdf"]},
    {"name": "ZIP archive", "type": "zip", "offset": 0, "magic": b"PK\x03\x04", "extensions": [".zip", ".jar", ".docx", ".xlsx", ".pptx", ".apk"]},
    {"name": "ELF executable", "type": "elf", "offset": 0, "magic": b"\x7fELF", "extensions": [".elf", ""]},
    {"name": "PE executable", "type": "pe", "offset": 0, "magic": b"MZ", "extensions": [".exe", ".dll", ".sys"]},
    {"name": "7-Zip archive", "type": "7z", "offset": 0, "magic": b"\x37\x7a\xbc\xaf\x27\x1c", "extensions": [".7z"]},
    {"name": "RAR archive", "type": "rar", "offset": 0, "magic": b"Rar!\x1a\x07", "extensions": [".rar"]},
    {"name": "BMP image", "type": "bmp", "offset": 0, "magic": b"BM", "extensions": [".bmp"]},
    {"name": "SQLite database", "type": "sqlite", "offset": 0, "magic": b"SQLite format 3\x00", "extensions": [".db", ".sqlite", ".sqlite3"]},
]


def detect_signature(data: bytes, path: Optional[Path] = None) -> Dict[str, object]:
    matched: Optional[Dict[str, object]] = None
    for sig in SIGNATURES:
        offset = int(sig["offset"])
        magic = sig["magic"]
        if data[offset:offset + len(magic)] == magic:
            matched = sig
            break

    suffix = path.suffix.lower() if path else ""
    if matched:
        expected_extensions = matched.get("extensions", [])
        ext_matches = suffix in expected_extensions if suffix else ("" in expected_extensions)
        return {
            "detected": True,
            "name": matched["name"],
            "type": matched["type"],
            "expected_extensions": expected_extensions,
            "extension_matches": ext_matches,
            "file_extension": suffix,
        }

    text_like = _looks_like_text(data)
    return {
        "detected": False,
        "name": "Plain text / unknown binary" if text_like else "Unknown binary",
        "type": "txt" if text_like else "unknown",
        "expected_extensions": [".txt"] if text_like else [],
        "extension_matches": suffix == ".txt" if text_like else False,
        "file_extension": suffix,
    }


def _looks_like_text(data: bytes, threshold: float = 0.95, sample_size: int = 4096) -> bool:
    chunk = data[:sample_size]
    if not chunk:
        return True
    printable = 0
    for b in chunk:
        if 32 <= b <= 126 or b in (9, 10, 13):
            printable += 1
    return (printable / len(chunk)) >= threshold
