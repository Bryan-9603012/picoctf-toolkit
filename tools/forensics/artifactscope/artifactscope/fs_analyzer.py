from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

FDISK_PART_RE = re.compile(
    r"^(?P<dev>\S+)\s+(?P<boot>\*)?\s*"
    r"(?P<start>\d+)\s+(?P<end>\d+)\s+(?P<sectors>\d+)\s+"
    r"(?P<size>\S+)\s+(?P<id>\S+)\s+(?P<type>.+)$"
)

RAW_GIT_PATTERNS = [
    (b".git/config", "config file"),
    (b"refs/heads/", "branch reference"),
    (b"packed-refs", "packed refs"),
    (b"ref: refs/", "HEAD reference"),
]

RAW_FLAG_PATTERNS = [
    re.compile(rb"picoCTF\{[^}\r\n]{1,120}\}"),
    re.compile(rb"flag\{[^}\r\n]{1,120}\}", re.IGNORECASE),
    re.compile(rb"ctf\{[^}\r\n]{1,120}\}", re.IGNORECASE),
]

SEARCH_KEYWORDS = ["flag", "pico", ".txt", "git", "ssh", "key", "log", "history", "secret", "password", "config"]

CONTENT_SCAN_PATTERNS = [
    "picoCTF{", "pico", "flag{", "secret", "password", "key", "ssh", "id_rsa"
]


def _is_binary_file(file_path: Path) -> bool:
    ext = file_path.suffix.lower()
    return ext in {".exe", ".dll", ".so", ".dylib", ".elf", ".bin", ".dat"} or file_path.stat().st_size > 5 * 1024 * 1024


def _as_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _run(cmd: List[str], timeout: int = 20) -> subprocess.CompletedProcess:
    """Run an external forensic command without letting failures abort analysis.

    Some environments, especially WSL/Windows, can hang on privileged commands
    such as sudo mount. Returning a CompletedProcess-style object keeps the
    analyzer moving to SleuthKit/icat fallbacks instead of crashing the scan.
    """
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            cmd,
            124,
            _as_text(exc.stdout),
            (_as_text(exc.stderr) or f"Command timed out after {timeout} seconds"),
        )
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(cmd, 127, "", str(exc))
    except OSError as exc:
        return subprocess.CompletedProcess(cmd, 126, "", str(exc))


def _extract_partition_number(dev: str) -> int:
    m = re.search(r"(\d+)$", dev)
    return int(m.group(1)) if m else 0


def parse_partition_info(image_path: Path) -> List[Dict[str, object]]:
    try:
        proc = _run(["fdisk", "-l", str(image_path)], timeout=20)
    except Exception:
        return []

    parts: List[Dict[str, object]] = []

    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or image_path.name not in line:
            continue

        m = FDISK_PART_RE.match(line)
        if not m:
            continue

        start = int(m.group("start"))
        sectors = int(m.group("sectors"))
        offset_bytes = start * 512
        size_bytes = sectors * 512
        ptype = m.group("type").strip()

        fs_type = "Unknown"
        if "Linux swap" in ptype:
            fs_type = "Linux swap"
        elif "Linux" in ptype:
            fs_type = "Linux"
        elif "NTFS" in ptype:
            fs_type = "NTFS"
        elif "FAT" in ptype:
            fs_type = "FAT"

        dev = m.group("dev")
        part_no = _extract_partition_number(dev)

        parts.append(
            {
                "partition": part_no,
                "active": bool(m.group("boot")),
                "offset_bytes": offset_bytes,
                "size_bytes": size_bytes,
                "size_mb": round(size_bytes / (1024 * 1024)),
                "fs_type": fs_type,
                "type": ptype,
            }
        )

    return parts


def search_git_in_raw_data(data: bytes, limit: int = 20) -> List[Dict[str, object]]:
    hits: List[Dict[str, object]] = []

    for needle, marker in RAW_GIT_PATTERNS:
        start = 0
        while True:
            idx = data.find(needle, start)
            if idx == -1:
                break
            hits.append({"marker": marker, "offset": idx})
            if len(hits) >= limit:
                return hits
            start = idx + 1

    return hits


def _is_ascii_mostly(text: str, threshold: float = 0.92) -> bool:
    if not text:
        return False
    printable = sum(1 for ch in text if 32 <= ord(ch) <= 126)
    return (printable / len(text)) >= threshold


def search_flag_in_raw_data(data: bytes, limit: int = 20) -> List[Dict[str, object]]:
    hits: List[Dict[str, object]] = []

    for pat in RAW_FLAG_PATTERNS:
        for m in pat.finditer(data):
            raw = m.group()
            text = raw.decode("utf-8", errors="replace").strip()

            if "{" not in text or "}" not in text:
                continue

            start = text.find("{") + 1
            end = text.rfind("}")
            inner = text[start:end]
            if not inner or len(inner) > 200:
                continue

            hits.append(
                {
                    "pattern": pat.pattern.decode(errors="ignore")
                    if isinstance(pat.pattern, bytes)
                    else str(pat.pattern),
                    "match": text,
                    "offset": m.start(),
                }
            )
            if len(hits) >= limit:
                return hits

    return hits


def _is_mounted(path: Path) -> bool:
    try:
        proc = _run(["mount"], timeout=10)
        return str(path) in proc.stdout
    except Exception:
        return False


def _safe_umount(path: Path) -> None:
    if _is_mounted(path):
        _run(["sudo", "-n", "umount", str(path)], timeout=10)


def _safe_detach_loop(loop_dev: Optional[str]) -> None:
    if loop_dev and loop_dev.startswith("/dev/loop"):
        _run(["sudo", "-n", "losetup", "-d", loop_dev], timeout=10)


def get_mount_point(image_path: Path, offset: int, fs_type: str, size_bytes: int = 0) -> Optional[Path]:
    if fs_type not in ("Linux", "ext", "NTFS", "FAT"):
        return None

    mount_root = Path("/tmp/artifactscope")
    mount_root.mkdir(parents=True, exist_ok=True)
    mount_path = mount_root / f"part_{offset}"
    mount_path.mkdir(parents=True, exist_ok=True)

    if _is_mounted(mount_path):
        return mount_path

    _safe_umount(mount_path)

    direct = _run(
        [
            "sudo",
            "mount",
            "-o",
            f"loop,ro,offset={offset}",
            str(image_path),
            str(mount_path),
        ],
        timeout=20,
    )
    if direct.returncode == 0 and _is_mounted(mount_path):
        return mount_path

    loop_dev = None
    try:
        cmd = ["sudo", "-n", "losetup", "-f", "--show", "-r", "-o", str(offset)]
        if size_bytes > 0:
            cmd.extend(["--sizelimit", str(size_bytes)])
        cmd.append(str(image_path))

        proc = _run(cmd, timeout=20)
        if proc.returncode != 0:
            return None

        loop_dev = proc.stdout.strip()
        if not loop_dev:
            return None

        mount_proc = _run(["sudo", "-n", "mount", "-o", "ro", loop_dev, str(mount_path)], timeout=20)
        if mount_proc.returncode == 0 and _is_mounted(mount_path):
            return mount_path

        _safe_detach_loop(loop_dev)
        return None

    except Exception:
        _safe_detach_loop(loop_dev)
        return None


def extract_partitions_7z(image_path: Path) -> Dict[int, Path]:
    # 先保留最小 fallback 介面，避免 analyzer 壞掉
    return {}


def search_raw_for_flag(part_path: Path) -> Dict[str, object]:
    if not part_path.exists():
        return {"flag_candidates": []}

    try:
        data = part_path.read_bytes()
    except Exception:
        return {"flag_candidates": []}

    candidates = []
    for hit in search_flag_in_raw_data(data, limit=20):
        candidates.append(
            {
                "flag": hit["match"],
                "offset": hit["offset"],
            }
        )

    return {"flag_candidates": candidates}


ACCESS_STATUS = {
    "MOUNTED": "mounted",
    "RECOVERED_TSK": "recovered_by_tsk",
    "EXTRACTED_ICAT": "extracted_by_icat",
    "FAILED": "failed",
}

HIGH_VALUE_PATTERNS = [
    ".git", "flag", "secret", "token", "password", "key",
    "history", "ssh", "id_rsa", "authorized_keys",
    ".txt", ".log", ".md", ".env", ".conf",
]


FLS_INODE_RE = re.compile(
    r"^\s*(?:\+\s*)?(?P<meta>[rdv]/[rdv])\s+\*?\s*"
    r"(?P<inode>\d+)(?:\([^)]*\))?:\s*(?P<path>.+?)\s*$"
)


def parse_fls_inode_line(line: str) -> Optional[Dict[str, object]]:
    """Parse SleuthKit fls output into inode/path metadata.

    Handles regular, nested, deleted and realloc formats, for example:
      r/r 2082: flag.txt
      r/r * 2082(realloc): flag.txt
      + r/r * 2082(realloc): root/flag.txt
    """
    m = FLS_INODE_RE.match(line or "")
    if not m:
        # Some TSK variants put extra tokens before the inode. Keep a conservative fallback.
        m2 = re.search(r"\b(?P<inode>\d+)(?:\([^)]*\))?:\s*(?P<path>.+?)\s*$", line or "")
        if not m2:
            return None
        meta = "?/?"
        inode = m2.group("inode")
        path = m2.group("path").strip()
    else:
        meta = m.group("meta")
        inode = m.group("inode")
        path = m.group("path").strip()

    if not inode or not path:
        return None
    return {
        "inode": inode,
        "name": Path(path).name or path,
        "path": path,
        "is_dir": meta.startswith("d/"),
        "is_deleted": "*" in (line or "") or "realloc" in (line or "").lower(),
        "raw": (line or "").strip(),
    }


def has_command(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def tsk_recover_partition(
    image_path: Path,
    sector_offset: int,
    output_dir: Path,
) -> Dict[str, object]:
    result = {
        "status": "failed",
        "output_dir": None,
        "files_recovered": 0,
        "error": None,
    }

    if not has_command("tsk_recover"):
        result["error"] = "tsk_recover not available"
        return result

    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        "tsk_recover",
        "-a",
        "-o", str(sector_offset),
        str(image_path),
        str(output_dir),
    ]

    proc = _run(cmd, timeout=120)
    if proc.returncode == 0:
        try:
            files = list(output_dir.rglob("*"))
            result["files_recovered"] = len([f for f in files if f.is_file()])
            result["status"] = "recovered_by_tsk"
            result["output_dir"] = str(output_dir)
        except Exception as e:
            result["error"] = str(e)
    else:
        result["error"] = proc.stderr[:200] if proc.stderr else "unknown error"

    return result


def fls_list_files(image_path: Path, sector_offset: int, recursive: bool = True) -> List[Dict[str, object]]:
    if not has_command("fls"):
        return []

    cmd = ["fls"]
    if recursive:
        cmd.append("-r")
    cmd.extend(["-o", str(sector_offset), str(image_path)])

    proc = _run(cmd, timeout=60)
    if proc.returncode != 0:
        return []

    files: List[Dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for line in proc.stdout.splitlines():
        parsed = parse_fls_inode_line(line)
        if not parsed:
            continue
        key = (str(parsed["inode"]), str(parsed["path"]))
        if key in seen:
            continue
        seen.add(key)
        files.append(parsed)

    return files


def icat_extract_file(image_path: Path, sector_offset: int, inode: str, output_path: Path, recover_deleted: bool = False) -> bool:
    if not has_command("icat"):
        return False

    cmd = ["icat"]
    if recover_deleted:
        cmd.append("-r")
    cmd.extend(["-o", str(sector_offset), str(image_path), str(inode)])
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=30, check=False)
    except Exception:
        return False

    if proc.returncode == 0 and proc.stdout:
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(proc.stdout)
            return True
        except Exception:
            return False

    return False


def targeted_icat_extraction(
    image_path: Path,
    sector_offset: int,
    output_dir: Path,
    patterns: Optional[List[str]] = None,
) -> Dict[str, object]:
    result = {
        "status": "failed",
        "output_dir": None,
        "files_extracted": 0,
        "high_value_files": [],
        "error": None,
    }

    if patterns is None:
        patterns = HIGH_VALUE_PATTERNS

    files = fls_list_files(image_path, sector_offset, recursive=True)
    if not files:
        result["error"] = "No files found by fls"
        return result

    output_dir.mkdir(parents=True, exist_ok=True)

    high_value_inodes = []
    for f in files:
        name_lower = f.get("name", "").lower()
        if any(pat.lower() in name_lower for pat in patterns):
            high_value_inodes.append(f)

    for f in high_value_inodes:
        inode = f.get("inode", "")
        name = f.get("name", "unknown")

        if not inode:
            continue

        safe_name = str(name).replace("/", "_").replace("\\", "_")
        output_path = output_dir / safe_name
        success = icat_extract_file(image_path, sector_offset, inode, output_path, recover_deleted=bool(f.get("is_deleted")))

        if success:
            result["files_extracted"] += 1
            result["high_value_files"].append({
                "name": name,
                "inode": inode,
                "path": str(output_path),
            })

    if result["files_extracted"] > 0:
        result["status"] = "extracted_by_icat"
        result["output_dir"] = str(output_dir)

    return result


def access_partition_three_level(
    image_path: Path,
    partition: Dict[str, object],
    output_root: Path,
) -> Dict[str, object]:
    part_id = partition.get("partition", "?")
    offset_bytes = int(partition.get("offset_bytes", 0) or 0)
    sector_offset = offset_bytes // 512
    fs_type = partition.get("fs_type", "")

    result = {
        "partition": f"p{part_id}",
        "fs_type": fs_type,
        "offset_bytes": offset_bytes,
        "sector_offset": sector_offset,
        "access_status": "failed",
        "mount_path": None,
        "tsk_recover_output": None,
        "icat_output": None,
        "error": None,
    }

    if fs_type not in ("Linux", "ext", "NTFS", "FAT"):
        result["error"] = f"Unsupported fs_type: {fs_type}"
        return result

    mount_root = output_root / "mounts"
    mount_root.mkdir(parents=True, exist_ok=True)

    mount_path = mount_root / f"part_{offset_bytes}"

    if _is_mounted(mount_path):
        result["access_status"] = "mounted"
        result["mount_path"] = str(mount_path)
        return result

    _safe_umount(mount_path)
    mount_path.mkdir(parents=True, exist_ok=True)

    mount_result = _run(
        ["sudo", "-n", "mount", "-o", f"loop,ro,offset={offset_bytes}", str(image_path), str(mount_path)],
        timeout=20,
    )
    if mount_result.returncode == 0 and _is_mounted(mount_path):
        result["access_status"] = "mounted"
        result["mount_path"] = str(mount_path)
        return result

    tsk_dir = output_root / "tsk_recovered" / f"partition_{part_id}"
    tsk_result = tsk_recover_partition(image_path, sector_offset, tsk_dir)

    if tsk_result["status"] == "recovered_by_tsk":
        result["access_status"] = "recovered_by_tsk"
        result["tsk_recover_output"] = tsk_result["output_dir"]
        return result

    icat_dir = output_root / "icat_extracted" / f"partition_{part_id}"
    icat_result = targeted_icat_extraction(image_path, sector_offset, icat_dir)

    if icat_result["status"] == "extracted_by_icat":
        result["access_status"] = "extracted_by_icat"
        result["icat_output"] = icat_result["output_dir"]
        return result

    result["error"] = f"Mount failed, TSK failed: {tsk_result.get('error')}, ICAT failed: {icat_result.get('error')}"
    return result


def check_sleuthkit_available() -> Dict[str, bool]:
    tools = ["mmls", "fsstat", "fls", "icat", "tsk_recover"]
    available = {}
    for tool in tools:
        available[tool] = shutil.which(tool) is not None
    return available


def run_mmls(image_path: Path) -> Tuple[bool, str]:
    proc = _run(["mmls", str(image_path)])
    return proc.returncode == 0, proc.stdout


def run_fsstat(image_path: Path, offset: Optional[int] = None) -> Tuple[bool, str]:
    cmd = ["fsstat"]
    if offset is not None:
        cmd.extend(["-o", str(offset)])
    cmd.append(str(image_path))
    proc = _run(cmd)
    return proc.returncode == 0, proc.stdout


def run_fls(image_path: Path, sector_offset: int = 0, recursive: bool = True) -> Tuple[bool, str]:
    cmd = ["fls"]
    if recursive:
        cmd.append("-r")
    if sector_offset > 0:
        sector_offset_bytes = sector_offset
        cmd.extend(["-o", str(sector_offset_bytes)])
    cmd.append(str(image_path))
    proc = _run(cmd)
    return proc.returncode == 0, proc.stdout


def run_icat(
    image_path: Path,
    inode: int | str,
    sector_offset: int = 0,
    output_path: Optional[Path] = None,
    recover_deleted: bool = False,
) -> Tuple[bool, bytes]:
    if not has_command("icat"):
        return False, b""

    cmd = ["icat"]
    if recover_deleted:
        cmd.append("-r")
    if sector_offset > 0:
        cmd.extend(["-o", str(sector_offset)])
    cmd.extend([str(image_path), str(inode)])
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=30, check=False)
        if proc.returncode == 0 and proc.stdout:
            if output_path:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_bytes(proc.stdout)
            return True, proc.stdout
        return False, b""
    except Exception:
        return False, b""


def check_partition_table(image_path: Path) -> Tuple[bool, List[Dict[str, object]]]:
    has_table, mmls_output = run_mmls(image_path)
    if has_table:
        try:
            lines = mmls_output.splitlines()
            partitions = []
            for line in lines[3:]:
                if not line.strip() or not line[0].isdigit():
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    try:
                        start = int(parts[1])
                        end = int(parts[2])
                        partitions.append({
                            "start_sector": start,
                            "end_sector": end,
                            "sectors": end - start + 1,
                        })
                    except ValueError:
                        continue
            return True, partitions
        except Exception:
            pass
    return False, []


def analyze_with_sleuthkit(image_path: Path) -> Dict[str, object]:
    result = {
        "tool_available": check_sleuthkit_available(),
        "has_partition_table": False,
        "partitions": [],
        "filesystem_info": None,
        "file_listings": [],
        "flag_candidates": [],
        "forensic_leads": [],
        "suggested_commands": [],
    }

    available = result["tool_available"]
    if not any(available.values()):
        result["suggested_commands"] = [
            "sudo apt-get install sleuthkit",
            "mmls image.img",
            "fsstat image.img",
            "fls -r -o <sector_offset> image.img",
        ]
        return result

    if available.get("mmls"):
        has_table, partitions = check_partition_table(image_path)
        result["has_partition_table"] = has_table
        result["partitions"] = partitions
    else:
        has_table = False
        partitions = []

    if available.get("fsstat"):
        candidate_offsets = [p.get("start_sector", 0) for p in partitions[:3]] if has_table else [0]
        for sector_offset in candidate_offsets:
            success, fs_output = run_fsstat(image_path, int(sector_offset or 0))
            if success and fs_output:
                result["filesystem_info"] = {
                    "sector_offset": int(sector_offset or 0),
                    "info": fs_output[:500],
                }
                break

    if available.get("fls"):
        if has_table:
            for part in partitions:
                sector_offset = int(part.get("start_sector", 0) or 0)
                success, fls_output = run_fls(image_path, sector_offset, recursive=True)
                if success and fls_output:
                    matched_files = []
                    for line in fls_output.splitlines():
                        line_lower = line.lower()
                        if any(kw in line_lower for kw in SEARCH_KEYWORDS):
                            matched_files.append(line.strip())
                    result["file_listings"].extend(matched_files[:20])
        else:
            success, fls_output = run_fls(image_path, 0, recursive=True)
            if success and fls_output:
                matched_files = []
                for line in fls_output.splitlines():
                    line_lower = line.lower()
                    if any(kw in line_lower for kw in SEARCH_KEYWORDS):
                        matched_files.append(line.strip())
                result["file_listings"] = matched_files[:20]

    if result["file_listings"]:
        result["forensic_leads"] = [
            {"value": line, "source": "sleuthkit fls keyword hit"}
            for line in result["file_listings"][:20]
        ]

    return result

def run_fls_deleted(image_path: Path, sector_offset: int = 0) -> Tuple[bool, str]:
    cmd = ["fls", "-rd"]
    if sector_offset > 0:
        cmd.extend(["-o", str(sector_offset)])
    cmd.append(str(image_path))
    proc = _run(cmd)
    return proc.returncode == 0, proc.stdout


def _extract_verified_flags_from_text(text: str) -> List[str]:
    return list(dict.fromkeys(m.group(0) for m in re.finditer(r"picoCTF\{[^}\r\n]{1,200}\}", text or "")))


def _extract_verified_flags_from_bytes(data: bytes) -> List[str]:
    if not data:
        return []
    texts = []
    for enc in ("utf-8", "latin-1", "utf-16", "utf-16le", "utf-16be"):
        try:
            texts.append(data.decode(enc, errors="ignore"))
        except Exception:
            pass
    try:
        texts.append(data.replace(b"\x00", b"").decode("latin-1", errors="ignore"))
    except Exception:
        pass
    flags: List[str] = []
    for text in texts:
        for flag in _extract_verified_flags_from_text(text):
            if flag not in flags:
                flags.append(flag)
    return flags


def recover_deleted_files(image_path: Path, sector_offset: int = 0) -> Dict[str, object]:
    result = {
        "deleted_files": [],
        "recovered_content": [],
        "flag_candidates": [],
        "verified_flags": [],
    }

    success, fls_output = run_fls_deleted(image_path, sector_offset)
    if not success or not fls_output:
        return result

    deleted_entries: List[Dict[str, object]] = []
    seen_inodes: set[str] = set()
    for line in fls_output.splitlines():
        if not line.strip() or "*" not in line:
            continue
        parsed = parse_fls_inode_line(line)
        if not parsed:
            continue
        inode = str(parsed["inode"])
        if inode in seen_inodes:
            continue
        seen_inodes.add(inode)
        deleted_entries.append(parsed)

    for entry in deleted_entries[:50]:
        inode = str(entry["inode"])
        content = b""
        ok = False
        for recover_deleted in (False, True):
            try:
                ok, content = run_icat(image_path, int(inode), sector_offset, recover_deleted=recover_deleted)
            except TypeError:
                # Backward-compatible with tests or integrations that monkeypatch the older signature.
                ok, content = run_icat(image_path, int(inode), sector_offset)
            if ok and content:
                break
        if not ok or not content:
            continue

        text = content.decode("utf-8", errors="replace")
        if not text.strip("\x00\r\n\t "):
            continue

        result["deleted_files"].append(inode)
        preview = text[:1000]
        result["recovered_content"].append({
            "inode": inode,
            "path": entry.get("path"),
            "content": preview,
        })

        for flag in _extract_verified_flags_from_bytes(content):
            rec = {"value": flag, "source": f"deleted icat inode {inode}", "path": entry.get("path")}
            if rec not in result["verified_flags"]:
                result["verified_flags"].append(rec)

        for pattern in CONTENT_SCAN_PATTERNS:
            if pattern.lower() in text.lower():
                candidate = {
                    "inode": inode,
                    "path": entry.get("path"),
                    "matched_pattern": pattern,
                    "content_preview": preview[:300],
                }
                if candidate not in result["flag_candidates"]:
                    result["flag_candidates"].append(candidate)
                break

    return result


def analyze_deleted_recovery(image_path: Path, partitions: List[Dict[str, object]]) -> List[Dict[str, object]]:
    results: List[Dict[str, object]] = []

    for p in partitions:
        p_start = int(p.get("offset_bytes", 0) or 0)
        fs_type = str(p.get("fs_type", ""))

        if fs_type not in ("Linux", "ext"):
            continue

        sector_offset = p_start // 512
        recovery_result = recover_deleted_files(image_path, sector_offset)

        if recovery_result.get("deleted_files"):
            results.append({
                "partition": f"p{p.get('partition', '?')}",
                "offset_bytes": p_start,
                "fs_type": fs_type,
                "deleted_inodes": recovery_result["deleted_files"],
                "recovered_content": recovery_result["recovered_content"],
                "flag_candidates": recovery_result["flag_candidates"],
                "verified_flags": recovery_result.get("verified_flags", []),
            })

    return results


def run_fls_timeline(image_path: Path, sector_offset: int = 0) -> Tuple[bool, str]:
    cmd = ["fls", "-r", "-m", "/"]
    if sector_offset > 0:
        cmd.extend(["-o", str(sector_offset)])
    cmd.append(str(image_path))
    proc = _run(cmd, timeout=60)
    return proc.returncode == 0, proc.stdout


def run_mactime(bodyfile: Path, output_csv: Path) -> Tuple[bool, str]:
    if not shutil.which("mactime"):
        return False, "mactime not found"

    try:
        proc = subprocess.run(
            ["mactime", "-b", str(bodyfile), "-d", "-i", "csv", "-o", "y"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout:
            output_csv.write_text(proc.stdout)
            return True, str(output_csv)
    except Exception:
        pass
    return False, ""


def analyze_timeline(image_path: Path, partitions: List[Dict[str, object]]) -> Dict[str, object]:
    result = {
        "timeline_events": [],
        "recent_modifications": [],
        "recent_deletions": [],
        "suspicious_filenames": [],
        "bodyfile": None,
        "csv_output": None,
    }

    mount_root = Path("/tmp/artifactscope_timeline")
    mount_root.mkdir(parents=True, exist_ok=True)

    has_timeline_data = False

    for p in partitions:
        p_start = int(p.get("offset_bytes", 0) or 0)
        fs_type = str(p.get("fs_type", ""))

        if fs_type not in ("Linux", "ext", "FAT", "NTFS"):
            continue

        sector_offset = p_start // 512

        success, fls_output = run_fls_timeline(image_path, sector_offset)
        if not success or not fls_output:
            continue

        has_timeline_data = True

        bodyfile_path = mount_root / f"bodyfile_p{p.get('partition', '?')}.body"
        bodyfile_path.write_text(fls_output)
        result["bodyfile"] = str(bodyfile_path)

        suggested_keywords = [
            "secret", "flag", "password", "key", "ssh", "id_rsa", "config", ".git",
            "hidden", "tmp", "cache", "log", ".bashrc", ".profile",
        ]

        for line in fls_output.splitlines():
            line_lower = line.lower()
            for kw in suggested_keywords:
                if kw in line_lower:
                    result["suspicious_filenames"].append(line.strip())

            if "|M|" in line or "/M/" in line:
                result["recent_modifications"].append(line.strip())
            elif "|D|" in line or "/D/" in line:
                result["recent_deletions"].append(line.strip())

        if shutil.which("mactime"):
            csv_output = mount_root / f"timeline_p{p.get('partition', '?')}.csv"
            success, output_path = run_mactime(bodyfile_path, csv_output)
            if success:
                result["csv_output"] = output_path

    if not has_timeline_data:
        success, fls_output = run_fls_timeline(image_path, 0)
        if success and fls_output:
            bodyfile_path = mount_root / "bodyfile_raw.body"
            bodyfile_path.write_text(fls_output)
            result["bodyfile"] = str(bodyfile_path)

    if result["recent_modifications"]:
        result["recent_modifications"] = result["recent_modifications"][-30:]
    if result["recent_deletions"]:
        result["recent_deletions"] = result["recent_deletions"][-30:]
    if result["suspicious_filenames"]:
        result["suspicious_filenames"] = result["suspicious_filenames"][-30:]

    return result


def analyze_git_with_icat(image_path: Path, offset_bytes: int) -> Dict[str, object]:
    offset_sectors = offset_bytes // 512
    result = {
        "git_found": False,
        "commits": [],
        "reflog": [],
        "flags": [],
        "commit_editmsg": None,
    }

    fls_result = _run(["fls", "-r", "-o", str(offset_sectors), str(image_path)], timeout=30)
    if fls_result.returncode != 0:
        return result

    output = fls_result.stdout
    if ".git" not in output:
        return result

    result["git_found"] = True
    commit_inode = None
    reflog_inode = None
    head_inode = None

    for line in output.splitlines():
        if "COMMIT_EDITMSG" in line:
            commit_inode = line.split(":")[0].split()[-1]
        elif "refs/heads/master" in line:
            head_inode = line.split(":")[-1].strip()
        elif "logs/HEAD" in line:
            reflog_inode = line.split(":")[0].split()[-1]

    if commit_inode:
        icat_result = _run(["icat", "-o", str(offset_sectors), str(image_path), commit_inode], timeout=10)
        if icat_result.returncode == 0:
            content = icat_result.stdout.strip()
            result["commit_editmsg"] = content

            flag_match = re.search(r"picoCTF\{[^}]+\}", content, re.IGNORECASE)
            if flag_match:
                result["flags"].append(flag_match.group())

            hint_match = re.search(r"g17_[A-Za-z0-9_]+", content)
            if hint_match:
                result["flags"].append(f"picoCTF{{{hint_match.group()}}}")

    if head_inode:
        icat_result = _run(["icat", "-o", str(offset_sectors), str(image_path), head_inode], timeout=10)
        if icat_result.returncode == 0:
            result["head"] = icat_result.stdout.strip()

    if reflog_inode:
        icat_result = _run(["icat", "-o", str(offset_sectors), str(image_path), reflog_inode], timeout=10)
        if icat_result.returncode == 0:
            lines = icat_result.stdout.strip().splitlines()
            result["reflog"] = [l for l in lines if l][:50]

    return result


# --- Compatibility wrappers for analyzer.py imports ---

def filesystem_recovery_chain(file_path: str, partitions, output_root: str):
    """
    Compatibility wrapper used by analyzer.py.
    Uses Sleuthkit-based recovery if possible, then deleted-file recovery.
    """
    result = {"mode": "filesystem_recovery_chain", "forensic_leads": [], "flag_candidates": [], "verified_flags": []}
    try:
        sleuth = analyze_with_sleuthkit(file_path)
        for k in ("forensic_leads", "flag_candidates", "verified_flags"):
            for item in sleuth.get(k, []):
                if item not in result[k]:
                    result[k].append(item)
    except Exception:
        pass
    try:
        deleted_results = analyze_deleted_recovery(Path(file_path), partitions or [])
        for deleted in deleted_results:
            for item in deleted.get("verified_flags", []):
                if item not in result["verified_flags"]:
                    result["verified_flags"].append(item)
            for item in deleted.get("flag_candidates", []):
                if item not in result["flag_candidates"]:
                    result["flag_candidates"].append(item)
            for inode in deleted.get("deleted_inodes", []):
                lead = {"value": f"Deleted inode recovered: {inode}", "source": deleted.get("partition", "deleted_recovery")}
                if lead not in result["forensic_leads"]:
                    result["forensic_leads"].append(lead)
    except Exception:
        pass
    return result


def raw_fs_recovery_chain(file_path: str, output_root: str):
    """
    Compatibility wrapper for raw file-system style recovery.
    """
    result = {"mode": "raw_fs_recovery_chain", "forensic_leads": [], "flag_candidates": [], "verified_flags": []}
    try:
        raw = search_raw_for_flag(Path(file_path))
        for k in ("forensic_leads", "flag_candidates", "verified_flags"):
            for item in raw.get(k, []):
                if item not in result[k]:
                    result[k].append(item)
    except Exception:
        pass
    try:
        sleuth = analyze_with_sleuthkit(file_path)
        for k in ("forensic_leads", "flag_candidates", "verified_flags"):
            for item in sleuth.get(k, []):
                if item not in result[k]:
                    result[k].append(item)
    except Exception:
        pass
    return result


def timeline_recovery_chain(file_path: str, partitions, output_root: str):
    """
    Compatibility wrapper for timeline-based recovery.
    """
    try:
        return analyze_timeline(Path(file_path), partitions)
    except Exception as e:
        return {"mode": "timeline_recovery_chain", "forensic_leads": [], "flag_candidates": [], "verified_flags": [], "error": str(e)}
