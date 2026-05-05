from __future__ import annotations

import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .utils import ensure_dir


@dataclass
class CarvePattern:
    name: str
    extension: str
    start_magic: bytes
    end_magic: bytes | None


ZIP_CENTRAL_DIR = b"PK\x01\x02"
ZIP_EOCD = b"PK\x05\x06"
ZIP_EOCD64 = b"PK\x06\x06"
ZIP_EOCD64_LOCATOR = b"PK\x06\x07"

PATTERNS = [
    CarvePattern("PNG image", ".png", b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82"),
    CarvePattern("JPEG image", ".jpg", b"\xff\xd8\xff", b"\xff\xd9"),
    CarvePattern("PDF document", ".pdf", b"%PDF", b"%%EOF"),
    CarvePattern("ZIP archive", ".zip", b"PK\x03\x04", b"PK\x05\x06"),
    CarvePattern("ELF executable", ".elf", b"\x7fELF", None),
    CarvePattern("PE executable", ".exe", b"MZ", None),
]


def discover_embedded(data: bytes) -> List[dict]:
    findings: List[dict] = []
    for pattern in PATTERNS:
        start = 0
        while True:
            idx = data.find(pattern.start_magic, start)
            if idx == -1:
                break

            end_offset = None
            if pattern.end_magic:
                end_idx = data.find(pattern.end_magic, idx + len(pattern.start_magic))
                if end_idx != -1:
                    end_offset = end_idx + len(pattern.end_magic)

            item = {
                "name": pattern.name,
                "extension": pattern.extension,
                "offset": idx,
                "end_offset": end_offset,
            }

            if pattern.name == "ZIP archive":
                zip_info = estimate_zip_end(data, idx)
                item["zip_end"] = zip_info.get("estimated_end")
                item["zip_parse_status"] = zip_info.get("status")
                item["zip_parse_reason"] = zip_info.get("reason")
                item["central_dir_found"] = zip_info.get("central_dir_found", False)
                item["eocd_found"] = zip_info.get("eocd_found", False)

            findings.append(item)
            start = idx + 1
    findings.sort(key=lambda x: x["offset"])
    return findings


def carve_embedded(data: bytes, out_dir: Path, source_name: str) -> List[dict]:
    ensure_dir(out_dir)
    findings = discover_embedded(data)
    carved = []

    for idx, item in enumerate(findings, start=1):
        start = item["offset"]

        if item.get("zip_end"):
            end = item["zip_end"]
        elif item.get("end_offset"):
            end = item["end_offset"]
        else:
            end = min(len(data), start + 1024 * 1024)

        chunk = data[start:end]
        out_name = f"{Path(source_name).stem}_carved_{idx:03d}{item['extension']}"
        out_path = out_dir / out_name
        out_path.write_bytes(chunk)

        reidentified = reidentify_carved(chunk, item["extension"])

        carved_item = {
            **item,
            "output_path": str(out_path),
            "size": len(chunk),
            "reidentified": reidentified,
        }

        if item["extension"] == ".zip":
            parse_result = validate_zip_parse(chunk)
            carved_item["zip_parse_validation"] = parse_result
            carved_item["zip_parse_status"] = parse_result["status"]
            carved_item["zip_parse_status_detail"] = parse_result["status_detail"]

            zip_contents = list_zip_contents(out_path)
            if zip_contents:
                carved_item["zip_contents"] = zip_contents
                leads = analyze_zip_high_priority_leads(out_path)
                if leads:
                    carved_item["high_priority_leads"] = leads

                carved_item["archive_indicators"] = detect_archive_indicators(zip_contents)

            if parse_result["can_parse"] and item.get("zip_parse_status") == "success":
                carved_item["zip_parse_status"] = "validated"
                carved_item["zip_parse_status_detail"] = "valid"
                extracted_dir = extract_zip_archive(out_path, item["offset"])
                if extracted_dir:
                    carved_item["extracted_path"] = str(extracted_dir)

                    extracted_indicators = scan_extracted_for_indicators(extracted_dir)
                    if extracted_indicators:
                        carved_item["extracted_indicators"] = extracted_indicators

                    if extracted_indicators.get("has_git"):
                        git_info = analyze_extracted_git(extracted_dir)
                        if git_info:
                            carved_item["git_analysis"] = git_info

        carved.append(carved_item)

    return carved


def reidentify_carved(data: bytes, expected_ext: str) -> dict:
    from .signatures import detect_signature, SIGNATURES
    from pathlib import PurePath

    sig = detect_signature(data)
    if sig["detected"] and sig["type"] != "unknown":
        return sig

    for s in SIGNATURES:
        magic = s["magic"]
        if len(data) >= len(magic) and data[:len(magic)] == magic:
            return {
                "detected": True,
                "name": s["name"],
                "type": s["type"],
                "expected_extensions": s.get("extensions", []),
                "extension_matches": expected_ext in s.get("extensions", [expected_ext]),
                "file_extension": expected_ext,
            }

    text_like = _looks_like_text(data)
    return {
        "detected": False,
        "name": "Plain text" if text_like else "Unknown binary",
        "type": "txt" if text_like else "unknown",
        "expected_extensions": [".txt"] if text_like else [],
        "extension_matches": expected_ext == ".txt" if text_like else False,
        "file_extension": expected_ext,
    }


def _looks_like_text(data: bytes, sample_size: int = 8192) -> bool:
    if len(data) < 32:
        return False
    sample = data[:sample_size]
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(sample) > 0.85


def list_zip_contents(zip_path: Path) -> Optional[dict]:
    try:
        result = subprocess.run(
            ["unzip", "-l", str(zip_path)],
            capture_output=True,
            text=False,
            timeout=30,
        )
        if result.returncode != 0:
            return None

        output_lines = result.stdout.decode("utf-8", errors="replace").splitlines()
        files = []
        for line in output_lines[3:]:
            line = line.strip()
            if not line or line.startswith("Archive:"):
                continue
            if line.startswith("---"):
                break
            parts = line.split()
            if len(parts) >= 4:
                try:
                    size = int(parts[3].replace(",", ""))
                    path = " ".join(parts[4:]) if len(parts) > 4 else parts[0]
                    if path and path != "None":
                        files.append({"path": path, "size": size})
                except (ValueError, IndexError):
                    continue

        files.sort(key=lambda x: x.get("path", ""))
        return {"files": files, "count": len(files)}
    except Exception as e:
        print(f"list_zip_contents error: {e}")
        return None


HIGH_PRIORITY_EXTENSIONS = {
    ".py": "Python script",
    ".js": "JavaScript",
    ".sh": "Shell script",
    ".rb": "Ruby script",
    ".php": "PHP script",
    ".c": "C source",
    ".cpp": "C++ source",
    ".go": "Go source",
    ".rs": "Rust source",
    ".java": "Java source",
    ".jar": "Java archive",
    ".key": "SSH/GPG key",
    ".pem": "Certificate",
    ".pub": "Public key",
    ".git": "Git repository",
    "flag": "Flag file",
    "picoCTF": "CTF flag",
}


def analyze_zip_high_priority_leads(zip_path: Path) -> list:
    contents = list_zip_contents(zip_path)
    if not contents:
        return []

    leads = []
    for f in contents.get("files", []):
        path = f.get("path", "")
        name = path.lower()

        for ext, desc in HIGH_PRIORITY_EXTENSIONS.items():
            if name.endswith(ext) or ext in name:
                leads.append({
                    "path": path,
                    "type": desc,
                    "size": f.get("size", 0),
                })
                break
        if "git" in name and ("head" in name or "config" in name):
            leads.append({
                "path": path,
                "type": "Git metadata",
                "size": f.get("size", 0),
            })

    return leads


def extract_git_from_zip(zip_path: Path) -> Optional[dict]:
    try:
        with tempfile.TemporaryDirectory() as tmp:
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(tmp)

            git_dir = Path(tmp) / ".git"
            if not git_dir.exists():
                return None

            head = git_dir / "HEAD"
            if not head.exists():
                return None

            result = {
                "is_git_repo": True,
                "current_branch": None,
                "branches": [],
                "tags": [],
                "commits": [],
                "flag_search": [],
            }

            head_content = head.read_text(errors="replace").strip()
            if head_content.startswith("ref: refs/heads/"):
                result["current_branch"] = head_content.replace("ref: refs/heads/", "")
            elif len(head_content) == 40:
                result["current_branch"] = head_content[:8]

            refs_file = git_dir / "packed-refs"
            if refs_file.exists():
                refs_content = refs_file.read_text(errors="replace")
                for line in refs_content.splitlines():
                    if line.startswith("ref: refs/heads/"):
                        result["branches"].append(line.replace("ref: refs/heads/", ""))
                    elif line.startswith("ref: refs/tags/"):
                        result["tags"].append(line.replace("ref: refs/tags/", ""))

            head_refs = git_dir / "refs" / "heads"
            if head_refs.exists():
                for b in head_refs.rglob("*"):
                    if b.is_file():
                        result["branches"].append(b.name)

            return result
    except Exception:
        return None


def estimate_zip_end(data: bytes, start_offset: int) -> dict:
    result = {
        "estimated_end": None,
        "status": "unknown",
        "reason": None,
        "status_detail": "unknown",
        "central_dir_found": False,
        "eocd_found": False,
        "validation_errors": [],
    }

    search_window = 10 * 1024 * 1024
    search_start = start_offset
    search_end = min(len(data), start_offset + search_window)

    eocd_idx = data.find(ZIP_EOCD, search_start, search_end)
    if eocd_idx == -1:
        result["status"] = "failed"
        result["reason"] = "EOCD not found"
        result["status_detail"] = "signature-only"
        return result

    result["eocd_found"] = True
    result["eocd_offset"] = eocd_idx

    try:
        cd_offset = int.from_bytes(data[eocd_idx + 12:eocd_idx + 16], "little")
        cd_size = int.from_bytes(data[eocd_idx + 16:eocd_idx + 20], "little")
        comment_size = int.from_bytes(data[eocd_idx + 20:eocd_idx + 22], "little")
        eocd_size = 22 + comment_size

        if cd_offset < start_offset or cd_offset > search_end:
            result["validation_errors"].append("CD offset out of range")
        if cd_size > 100 * 1024 * 1024:
            result["validation_errors"].append("CD size unreasonably large")

        result["central_dir_offset"] = cd_offset
        result["central_dir_size"] = cd_size

        full_end = eocd_idx + eocd_size
        result["estimated_end"] = full_end

        cd_idx = data.find(ZIP_CENTRAL_DIR, search_start, search_end)
        if cd_idx != -1:
            result["central_dir_found"] = True

        if result["validation_errors"]:
            result["status"] = "partial"
            result["reason"] = "; ".join(result["validation_errors"])
            result["status_detail"] = "corrupted-but-structured"
        else:
            result["status"] = "success"
            result["status_detail"] = "needs_parse_test"

        return result
    except Exception as e:
        result["status"] = "partial"
        result["reason"] = f"EOCD parse error: {e}"
        result["status_detail"] = "corrupted-but-structured"
        result["estimated_end"] = eocd_idx + 22
        return result


def validate_zip_parse(chunk: bytes) -> dict:
    result = {
        "can_parse": False,
        "status": "unknown",
        "status_detail": "unknown",
        "file_count": 0,
        "files": [],
        "errors": [],
    }

    if len(chunk) < 22:
        result["status"] = "failed"
        result["status_detail"] = "too_small"
        result["errors"].append("chunk too small for ZIP")
        return result

    try:
        import zipfile
        import io
        with io.BytesIO(chunk) as bio:
            with zipfile.ZipFile(bio, "r") as zf:
                files = zf.namelist()
                result["can_parse"] = True
                result["file_count"] = len(files)
                result["files"] = files[:50]
                result["status"] = "validated"
                result["status_detail"] = "valid"
    except zipfile.BadZipFile as e:
        result["errors"].append(f"BadZipFile: {e}")
        result["status"] = "failed"
        if "bad offset" in str(e).lower():
            result["status_detail"] = "corrupted-but-structured"
        else:
            result["status_detail"] = "signature-only"
    except Exception as e:
        result["errors"].append(f"Parse error: {e}")
        result["status"] = "failed"
        result["status_detail"] = "signature-only"

    return result


def parse_zip_end_detailed(data: bytes, start_offset: int, max_search: int = 10 * 1024 * 1024) -> dict:
    result = estimate_zip_end(data, start_offset)

    if result["status"] in ("success", "partial"):
        return result

    cd_search_start = start_offset + 1
    cd_search_end = min(len(data), start_offset + max_search)

    cd_idx = data.find(ZIP_CENTRAL_DIR, cd_search_start, cd_search_end)
    if cd_idx != -1:
        result["central_dir_found"] = True
        result["status"] = "partial"
        result["reason"] = "central dir found, EOCD not found"

    return result


def detect_archive_indicators(zip_contents: dict) -> dict:
    indicators = []
    files = zip_contents.get("files", [])
    for f in files:
        path = f.get("path", "").lower()
        if ".git" in path or "head" in path or "config" in path:
            indicators.append({"type": "git", "path": f.get("path")})
        elif "flag" in path or "secret" in path or "picoctf" in path:
            indicators.append({"type": "flag", "path": f.get("path")})
        elif path.endswith((".md", ".txt", ".json", ".xml", ".yaml", ".yml")):
            indicators.append({"type": "text", "path": f.get("path")})
    return {"indicators": indicators, "count": len(indicators)}


def extract_zip_archive(zip_path: Path, offset: int) -> Optional[Path]:
    try:
        extract_dir = zip_path.parent / "extracted" / f"zip_{offset}"
        extract_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(extract_dir)
        return extract_dir
    except Exception as e:
        print(f"extract_zip_archive error: {e}")
        return None


def scan_extracted_for_indicators(extracted_dir: Path) -> dict:
    result = {
        "has_git": False,
        "git_paths": [],
        "readable_files": [],
        "flag_files": [],
    }

    for p in extracted_dir.rglob("*"):
        if not p.is_file():
            continue
        name = p.name.lower()
        path_str = str(p)

        if ".git" in name or p.name == "HEAD" or p.name == "config":
            result["has_git"] = True
            result["git_paths"].append(path_str)

        if "flag" in name or "secret" in name or "picoctf" in name:
            result["flag_files"].append(path_str)

        if name.endswith((".md", ".txt", ".json", ".yaml", ".yml", ".xml", ".py", ".js", ".sh")):
            result["readable_files"].append(path_str)

    return result


def analyze_extracted_git(repo_path: Path) -> Optional[dict]:
    result = {
        "is_git_repo": False,
        "current_branch": None,
        "branches": [],
        "tags": [],
        "recent_commits": [],
        "flag_hits": [],
    }

    git_dir = repo_path / ".git"
    if not git_dir.exists():
        return None

    result["is_git_repo"] = True

    head = git_dir / "HEAD"
    if head.exists():
        content = head.read_text(errors="replace").strip()
        if content.startswith("ref: refs/heads/"):
            result["current_branch"] = content.replace("ref: refs/heads/", "")
        elif len(content) == 40:
            result["current_branch"] = content[:8]

    refs_file = git_dir / "packed-refs"
    if refs_file.exists():
        for line in refs_file.read_text(errors="replace").splitlines():
            if line.startswith("ref: refs/heads/"):
                result["branches"].append(line.replace("ref: refs/heads/", ""))
            elif line.startswith("ref: refs/tags/"):
                result["tags"].append(line.replace("ref: refs/tags/", ""))

    head_refs = git_dir / "refs" / "heads"
    if head_refs.exists():
        for b in head_refs.rglob("*"):
            if b.is_file():
                result["branches"].append(b.name)

    index_file = git_dir / "index"
    if index_file.exists():
        try:
            import subprocess
            proc = subprocess.run(
                ["git", "ls-files"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0:
                for line in proc.stdout.splitlines()[:100]:
                    if "flag" in line.lower() or "secret" in line.lower() or "picoctf" in line.lower():
                        result["flag_hits"].append(line)
        except:
            pass

    return result
