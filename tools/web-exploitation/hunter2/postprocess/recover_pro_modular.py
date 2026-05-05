#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

MAX_READ_DEFAULT = 100 * 1024 * 1024  # 100 MB
HEADER_PREVIEW_SIZE = 64
TAIL_PREVIEW_SIZE = 64


@dataclass
class SignatureSpec:
    name: str
    header: Optional[bytes]
    footers: List[bytes]
    markers: List[bytes]
    ext: str
    description: str
    repair_header: bool = True
    repair_footer: bool = False


@dataclass
class Candidate:
    name: str
    score: int
    confidence: str
    reasons: List[str] = field(default_factory=list)
    subtype: Optional[str] = None


SIGNATURES: Dict[str, SignatureSpec] = {
    "PNG": SignatureSpec(
        name="PNG",
        header=b"\x89PNG\r\n\x1a\n",
        footers=[b"IEND\xaeB`\x82"],
        markers=[b"IHDR", b"IDAT", b"IEND", b"PLTE", b"tEXt", b"pHYs"],
        ext=".png",
        description="PNG image",
        repair_header=True,
        repair_footer=True,
    ),
    "JPEG": SignatureSpec(
        name="JPEG",
        header=b"\xff\xd8\xff",
        footers=[b"\xff\xd9"],
        markers=[b"JFIF", b"Exif", b"\xff\xdb", b"\xff\xc0", b"\xff\xc4", b"\xff\xda"],
        ext=".jpg",
        description="JPEG image",
        repair_header=True,
        repair_footer=True,
    ),
    "GIF87a": SignatureSpec(
        name="GIF87a",
        header=b"GIF87a",
        footers=[b"\x00;"],
        markers=[b"GIF87a"],
        ext=".gif",
        description="GIF87a image",
        repair_header=True,
        repair_footer=False,
    ),
    "GIF89a": SignatureSpec(
        name="GIF89a",
        header=b"GIF89a",
        footers=[b"\x00;"],
        markers=[b"GIF89a", b"NETSCAPE2.0"],
        ext=".gif",
        description="GIF89a image",
        repair_header=True,
        repair_footer=False,
    ),
    "PDF": SignatureSpec(
        name="PDF",
        header=b"%PDF-",
        footers=[b"%%EOF"],
        markers=[b"%PDF", b"obj", b"stream", b"endobj", b"xref", b"/Catalog", b"/Pages"],
        ext=".pdf",
        description="PDF document",
        repair_header=True,
        repair_footer=True,
    ),
    "ZIP": SignatureSpec(
        name="ZIP",
        header=b"PK\x03\x04",
        footers=[],
        markers=[b"PK", b"[Content_Types].xml", b"word/", b"xl/", b"ppt/", b"AndroidManifest.xml", b"classes.dex"],
        ext=".zip",
        description="ZIP archive",
        repair_header=True,
        repair_footer=False,
    ),
    "RAR": SignatureSpec(
        name="RAR",
        header=b"Rar!\x1a\x07\x00",
        footers=[],
        markers=[b"Rar!"],
        ext=".rar",
        description="RAR archive",
        repair_header=True,
        repair_footer=False,
    ),
    "7Z": SignatureSpec(
        name="7Z",
        header=b"7z\xbc\xaf\x27\x1c",
        footers=[],
        markers=[b"7z\xbc\xaf\x27\x1c"],
        ext=".7z",
        description="7z archive",
        repair_header=True,
        repair_footer=False,
    ),
    "ELF": SignatureSpec(
        name="ELF",
        header=b"\x7fELF",
        footers=[],
        markers=[b".text", b".data", b".rodata", b"GLIBC", b"/lib", b"/lib64"],
        ext=".elf",
        description="ELF executable",
        repair_header=True,
        repair_footer=False,
    ),
    "PE": SignatureSpec(
        name="PE",
        header=b"MZ",
        footers=[],
        markers=[b"This program cannot be run in DOS mode", b"PE\x00\x00", b".text", b".rdata", b".idata"],
        ext=".exe",
        description="Windows PE executable",
        repair_header=True,
        repair_footer=False,
    ),
    "WEBP": SignatureSpec(
        name="WEBP",
        header=b"RIFF",
        footers=[],
        markers=[b"RIFF", b"WEBP", b"VP8 ", b"VP8L", b"VP8X"],
        ext=".webp",
        description="WebP image",
        repair_header=False,
        repair_footer=False,
    ),
    "WAV": SignatureSpec(
        name="WAV",
        header=b"RIFF",
        footers=[],
        markers=[b"RIFF", b"WAVE", b"fmt "],
        ext=".wav",
        description="WAV audio",
        repair_header=False,
        repair_footer=False,
    ),
    "AVI": SignatureSpec(
        name="AVI",
        header=b"RIFF",
        footers=[],
        markers=[b"RIFF", b"AVI ", b"LIST"],
        ext=".avi",
        description="AVI video",
        repair_header=False,
        repair_footer=False,
    ),
    "MP3": SignatureSpec(
        name="MP3",
        header=b"ID3",
        footers=[],
        markers=[b"ID3"],
        ext=".mp3",
        description="MP3 audio",
        repair_header=True,
        repair_footer=False,
    ),
    "MP4": SignatureSpec(
        name="MP4",
        header=None,
        footers=[],
        markers=[b"ftyp", b"isom", b"mp42", b"moov", b"mdat"],
        ext=".mp4",
        description="MP4 video",
        repair_header=False,
        repair_footer=False,
    ),
    "AVIF": SignatureSpec(
        name="AVIF",
        header=None,
        footers=[],
        markers=[b"ftypavif", b"ftypavis", b"avif", b"mif1"],
        ext=".avif",
        description="AVIF image",
        repair_header=False,
        repair_footer=False,
    ),
}

ZIP_SUBTYPES: Dict[str, Tuple[List[bytes], str]] = {
    "DOCX": ([b"[Content_Types].xml", b"word/"], ".docx"),
    "XLSX": ([b"[Content_Types].xml", b"xl/"], ".xlsx"),
    "PPTX": ([b"[Content_Types].xml", b"ppt/"], ".pptx"),
    "APK": ([b"AndroidManifest.xml", b"classes.dex"], ".apk"),
    "JAR": ([b"META-INF/MANIFEST.MF"], ".jar"),
    "ODT": ([b"mimetypeapplication/vnd.oasis.opendocument.text", b"content.xml"], ".odt"),
}


def safe_read(path: Path, max_read: int) -> bytes:
    with path.open("rb") as f:
        return f.read(max_read)


def to_hex_line(data: bytes, n: int) -> str:
    return " ".join(f"{b:02X}" for b in data[:n])


def ascii_preview(data: bytes, n: int) -> str:
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in data[:n])


def estimate_confidence(score: int) -> str:
    if score >= 90:
        return "High"
    if score >= 55:
        return "Medium"
    if score >= 25:
        return "Low"
    return "Very Low"


def score_candidate(spec: SignatureSpec, data: bytes) -> Candidate:
    score = 0
    reasons: List[str] = []

    if spec.header:
        if data.startswith(spec.header):
            score += 55
            reasons.append(f"header matched: {spec.header!r}")
        elif spec.header in data[:32]:
            score += 12
            reasons.append(f"header bytes found near start: {spec.header!r}")

    for footer in spec.footers:
        if footer in data[-4096:] or footer in data:
            score += 22
            reasons.append(f"footer found: {footer!r}")
            break

    marker_hits = 0
    for marker in spec.markers:
        if marker in data:
            marker_hits += 1
            reasons.append(f"marker found: {marker!r}")

    score += marker_hits * 9

    if spec.name == "WEBP" and data.startswith(b"RIFF") and b"WEBP" in data[:64]:
        score += 35
        reasons.append("RIFF + WEBP confirmed")

    if spec.name == "WAV" and data.startswith(b"RIFF") and b"WAVE" in data[:128]:
        score += 20
        reasons.append("RIFF + WAVE confirmed")

    if spec.name == "AVI" and data.startswith(b"RIFF") and (b"AVI " in data[:128] or b"AVI " in data):
        score += 20
        reasons.append("RIFF + AVI confirmed")

    if spec.name == "AVIF" and (b"ftypavif" in data[:64] or b"ftypavis" in data[:64]):
        score += 40
        reasons.append("ISO BMFF AVIF brand confirmed")

    if spec.name == "PDF" and (b"%PDF" in data[:1024] or b"/Catalog" in data or b"xref" in data):
        score += 10
    if spec.name == "ZIP" and b"PK" in data:
        score += 10

    return Candidate(name=spec.name, score=score, confidence=estimate_confidence(score), reasons=reasons)


def detect_zip_subtypes(data: bytes) -> List[Candidate]:
    results: List[Candidate] = []
    for name, (markers, _) in ZIP_SUBTYPES.items():
        hits = [m for m in markers if m in data]
        if hits:
            score = len(hits) * 25
            reasons = [f"ZIP subtype marker found: {m!r}" for m in hits]
            results.append(Candidate(name="ZIP", subtype=name, score=score, confidence=estimate_confidence(score), reasons=reasons))
    results.sort(key=lambda c: c.score, reverse=True)
    return results


def analyze_bytes(data: bytes) -> List[Candidate]:
    candidates = [score_candidate(spec, data) for spec in SIGNATURES.values()]
    candidates = [c for c in candidates if c.score > 0]
    candidates.sort(key=lambda c: c.score, reverse=True)

    zip_subs = detect_zip_subtypes(data)
    if zip_subs:
        for c in candidates:
            if c.name == "ZIP":
                best_sub = zip_subs[0]
                c.subtype = best_sub.subtype
                c.score += best_sub.score
                c.confidence = estimate_confidence(c.score)
                c.reasons.extend(best_sub.reasons)
                break
    return candidates


def choose_best(candidates: List[Candidate]) -> Optional[Candidate]:
    return candidates[0] if candidates else None


def subtype_extension(best: Candidate) -> str:
    if best.subtype and best.subtype in ZIP_SUBTYPES:
        return ZIP_SUBTYPES[best.subtype][1]
    return SIGNATURES[best.name].ext


def repair_header(data: bytes, best: Candidate) -> Tuple[bytes, Optional[str]]:
    spec = SIGNATURES[best.name]
    if not spec.header or not spec.repair_header:
        return data, None

    header = spec.header
    if best.name == "PDF":
        desired = b"%PDF-1.7\n"
        if data.startswith(b"%PDF-"):
            return data, None
        repaired = desired + data[len(desired):] if len(data) >= len(desired) else desired + data
        return repaired, f"replaced start with {desired!r}"

    if data.startswith(header):
        return data, None

    repaired = header + data[len(header):] if len(data) >= len(header) else header
    return repaired, f"replaced first {len(header)} bytes with {header!r}"


def repair_footer(data: bytes, best: Candidate) -> Tuple[bytes, Optional[str]]:
    spec = SIGNATURES[best.name]
    if not spec.footers or not spec.repair_footer:
        return data, None

    footer = spec.footers[0]
    if footer in data[-4096:] or data.endswith(footer):
        return data, None

    if best.name == "PNG":
        if b"IHDR" in data and b"IDAT" in data:
            return data + footer, f"appended PNG footer {footer!r}"
        return data, None

    if best.name == "JPEG":
        if b"JFIF" in data or b"Exif" in data or b"\xff\xda" in data:
            return data + footer, f"appended JPEG footer {footer!r}"
        return data, None

    if best.name == "PDF":
        if b"%PDF" in data[:1024] or b"obj" in data:
            suffix = b"\n%%EOF\n"
            if data.endswith(b"%%EOF") or data.endswith(b"%%EOF\n"):
                return data, None
            return data + suffix, "appended PDF EOF marker"
        return data, None

    return data, None


def validate_zip(path: Path) -> Tuple[bool, str]:
    try:
        with zipfile.ZipFile(path, "r") as zf:
            bad = zf.testzip()
            if bad is None:
                return True, "ZIP structure validated"
            return False, f"ZIP structure damaged at member: {bad}"
    except Exception as e:
        return False, f"ZIP validation failed: {e}"


def validate_pdf_bytes(data: bytes) -> Tuple[bool, str]:
    if not data.startswith(b"%PDF-"):
        return False, "PDF header missing"
    if b"%%EOF" not in data[-8192:] and b"%%EOF" not in data:
        return False, "PDF EOF marker missing"
    if b"obj" not in data or b"endobj" not in data:
        return False, "PDF objects incomplete or missing"
    return True, "PDF basic structure looks plausible"


def validate_png_bytes(data: bytes) -> Tuple[bool, str]:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return False, "PNG header missing"
    if b"IHDR" not in data or b"IDAT" not in data or b"IEND" not in data:
        return False, "PNG chunk structure incomplete"
    return True, "PNG basic structure looks plausible"


def validate_gif_bytes(data: bytes) -> Tuple[bool, str]:
    if not (data.startswith(b"GIF87a") or data.startswith(b"GIF89a")):
        return False, "GIF header missing"
    if b"\x00;" not in data[-8:] and not data.endswith(b";"):
        return False, "GIF trailer not found"
    return True, "GIF basic structure looks plausible"


def validate_jpeg_bytes(data: bytes) -> Tuple[bool, str]:
    if not data.startswith(b"\xff\xd8\xff"):
        return False, "JPEG header missing"
    if not data.endswith(b"\xff\xd9"):
        return False, "JPEG footer missing"
    if b"JFIF" not in data and b"Exif" not in data and b"\xff\xda" not in data:
        return False, "JPEG markers not convincing"
    return True, "JPEG basic structure looks plausible"


def validate_pe_bytes(data: bytes) -> Tuple[bool, str]:
    if not data.startswith(b"MZ"):
        return False, "MZ header missing"
    if data.find(b"PE\x00\x00") == -1:
        return False, "PE signature not found"
    return True, "PE signature found"


def validate_elf_bytes(data: bytes) -> Tuple[bool, str]:
    if not data.startswith(b"\x7fELF"):
        return False, "ELF header missing"
    if len(data) < 16:
        return False, "ELF too short"
    return True, "ELF header looks plausible"


def validate_with_pillow(path: Path) -> Tuple[bool, str]:
    try:
        from PIL import Image  # type: ignore
        with Image.open(path) as img:
            img.verify()
        return True, "Pillow verification succeeded"
    except Exception as e:
        return False, f"Pillow verification failed: {e}"


def validate_repaired(path: Path, best: Candidate, data: bytes) -> List[str]:
    msgs: List[str] = []
    if best.name == "ZIP":
        ok, msg = validate_zip(path)
        msgs.append(f"[{'OK' if ok else 'FAIL'}] {msg}")
        return msgs

    validators: Dict[str, Callable[[bytes], Tuple[bool, str]]] = {
        "PDF": validate_pdf_bytes,
        "PNG": validate_png_bytes,
        "GIF87a": validate_gif_bytes,
        "GIF89a": validate_gif_bytes,
        "JPEG": validate_jpeg_bytes,
        "PE": validate_pe_bytes,
        "ELF": validate_elf_bytes,
    }

    if best.name in validators:
        ok, msg = validators[best.name](data)
        msgs.append(f"[{'OK' if ok else 'FAIL'}] {msg}")
    if best.name in {"PNG", "JPEG", "GIF87a", "GIF89a"}:
        ok, msg = validate_with_pillow(path)
        msgs.append(f"[{'OK' if ok else 'FAIL'}] {msg}")
    return msgs


def make_output_path(src: Path, ext: str, output_dir: Optional[Path] = None) -> Path:
    base_dir = output_dir if output_dir is not None else src.parent
    return base_dir / f"{src.stem}_repaired{ext}"


def write_report(report_path: Path, report: dict) -> None:
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


def build_report(
    src: Path,
    data: bytes,
    candidates: List[Candidate],
    best: Optional[Candidate],
    actions: List[str],
    out_path: Optional[Path],
    validations: List[str],
) -> dict:
    guessed_ext = None
    if best is not None:
        guessed_ext = subtype_extension(best)

    original_ext = src.suffix.lower()
    extension_mismatch = bool(guessed_ext and original_ext and guessed_ext != original_ext)

    suspicious_score = 0
    if extension_mismatch:
        suspicious_score += 30
    if actions:
        suspicious_score += 25
    if any("[FAIL]" in v for v in validations):
        suspicious_score += 35

    return {
        "source_file": str(src),
        "bytes_analyzed": len(data),
        "header_hex_preview": to_hex_line(data, min(HEADER_PREVIEW_SIZE, len(data))),
        "header_ascii_preview": ascii_preview(data, min(HEADER_PREVIEW_SIZE, len(data))),
        "tail_hex_preview": to_hex_line(data[-TAIL_PREVIEW_SIZE:], min(TAIL_PREVIEW_SIZE, len(data))),
        "original_extension": original_ext or "",
        "suggested_extension": guessed_ext or "",
        "extension_mismatch": extension_mismatch,
        "suspicious_score": suspicious_score,
        "repair_recommended": bool(
                                    best
                                    and best.confidence in {"Medium", "High"}
                                    and best.name in {"JPEG", "PNG", "PDF", "GIF87a", "GIF89a", "ZIP"}
                ),
        "candidates": [
            {
                "name": c.name,
                "subtype": c.subtype,
                "score": c.score,
                "confidence": c.confidence,
                "reasons": c.reasons[:12],
            }
            for c in candidates[:8]
        ],
        "best_guess": None if not best else {
            "name": best.name,
            "subtype": best.subtype,
            "score": best.score,
            "confidence": best.confidence,
        },
        "repair_actions": actions,
        "output_file": None if not out_path else str(out_path),
        "validations": validations,
    }


def analyze_file(
    src: Path | str,
    *,
    max_read: int = MAX_READ_DEFAULT,
    no_write: bool = False,
    report_json: bool = False,
    output_dir: Optional[Path | str] = None,
) -> dict:
    src = Path(src)
    if not src.is_file():
        raise FileNotFoundError(f"File not found: {src}")

    data = safe_read(src, max_read)
    if not data:
        raise ValueError("File is empty.")

    candidates = analyze_bytes(data)
    best = choose_best(candidates)
    actions: List[str] = []
    validations: List[str] = []
    out_path: Optional[Path] = None

    repairable_types = {"JPEG", "PNG", "PDF", "GIF87a", "GIF89a", "ZIP"}

    if best is not None and best.confidence in {"Medium", "High"} and best.name in repairable_types:
        repaired = data
        repaired, action = repair_header(repaired, best)
        if action:
            actions.append(action)
        repaired, action = repair_footer(repaired, best)
        if action:
            actions.append(action)

        resolved_output_dir = Path(output_dir) if output_dir is not None else None
        if not no_write:
            if resolved_output_dir is not None:
                resolved_output_dir.mkdir(parents=True, exist_ok=True)
            ext = subtype_extension(best)
            out_path = make_output_path(src, ext, resolved_output_dir)
            out_path.write_bytes(repaired)
            validations = validate_repaired(out_path, best, repaired)

    report = build_report(src, data, candidates, best, actions, out_path, validations)

    if report_json:
        base_dir = Path(output_dir) if output_dir is not None else src.parent
        base_dir.mkdir(parents=True, exist_ok=True)
        report_path = base_dir / f"{src.stem}_report.json"
        write_report(report_path, report)
        report["report_file"] = str(report_path)

    return report


def print_cli_report(report: dict) -> None:
    print("=" * 78)
    print("Forensic File Recovery Analyzer")
    print("=" * 78)
    print(f"[+] File              : {report['source_file']}")
    print(f"[+] Bytes analyzed    : {report['bytes_analyzed']}")
    print()
    print("[+] Header hex preview:")
    print(report["header_hex_preview"])
    print()
    print("[+] Header ASCII preview:")
    print(report["header_ascii_preview"])
    print()
    print("[+] Tail hex preview:")
    print(report["tail_hex_preview"])
    print()

    candidates = report.get("candidates", [])
    if not candidates:
        print("[!] No convincing file type detected.")
        return

    print("[+] Candidate types:")
    for idx, c in enumerate(candidates[:8], start=1):
        suffix = f" ({c['subtype']})" if c.get("subtype") else ""
        print(f"  {idx}. {c['name']}{suffix:<10} score={c['score']:<3} confidence={c['confidence']}")
        for r in c.get("reasons", [])[:6]:
            print(f"     - {r}")
        if len(c.get("reasons", [])) > 6:
            print(f"     - ... {len(c['reasons']) - 6} more indicators")
        print()

    best = report.get("best_guess")
    if best:
        label = best['name'] + (f" ({best['subtype']})" if best.get("subtype") else "")
        print(f"[+] Best guess        : {label}")
        print(f"[+] Confidence        : {best['confidence']}")
        print(f"[+] Extension mismatch: {report.get('extension_mismatch')}")
        print(f"[+] Suspicious score  : {report.get('suspicious_score')}")
        print(f"[+] Repair recommend? : {report.get('repair_recommended')}")
        print()

    actions = report.get("repair_actions", [])
    if actions:
        print("[+] Repair actions:")
        for action in actions:
            print(f"  - {action}")
    else:
        print("[+] Repair actions: none needed or not recommended")

    print()
    print("[+] Validation:")
    validations = report.get("validations", [])
    if validations:
        for msg in validations:
            print(f"  - {msg}")
    else:
        print("  - No validation run")

    if report.get("output_file"):
        print(f"[+] Repaired file saved: {report['output_file']}")
    if report.get("report_file"):
        print(f"[+] JSON report saved : {report['report_file']}")

    print()
    print("[+] Notes:")
    print("  - 這支工具偏向『推測 + 保守修補』，不是萬能檔案修復器。")
    print("  - 若檔案中段被覆寫、截斷、加密或碎片化，修好檔頭也可能打不開。")
    print("  - 對 ZIP-based 類型，驗證結果通常最有參考價值。")


def main() -> int:
    parser = argparse.ArgumentParser(description="Recover likely file type, repair header/footer, and validate.")
    parser.add_argument("file", help="input file path")
    parser.add_argument("--max-read", type=int, default=MAX_READ_DEFAULT, help="maximum bytes to read")
    parser.add_argument("--no-write", action="store_true", help="analyze only, do not write repaired file")
    parser.add_argument("--report-json", action="store_true", help="write JSON report")
    parser.add_argument("--output-dir", help="directory for repaired file / JSON report")
    args = parser.parse_args()

    try:
        report = analyze_file(
            args.file,
            max_read=args.max_read,
            no_write=args.no_write,
            report_json=args.report_json,
            output_dir=args.output_dir,
        )
    except Exception as e:
        print(f"[!] {e}")
        return 1

    print_cli_report(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())