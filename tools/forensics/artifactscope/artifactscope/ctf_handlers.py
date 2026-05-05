from __future__ import annotations

import base64
import re
import subprocess
import shlex
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

FLAG_RE = re.compile(r"picoCTF\{[^}\n\r]{1,200}\}")
NAME_HINT_RE = re.compile(
    r"(flag|secret|note|diary|journal|timeline|innocuous|ssh|history|enc|key)",
    re.IGNORECASE,
)


def _safe_append(container: List[Dict[str, Any]], item: Dict[str, Any]) -> None:
    if item not in container:
        container.append(item)


def _run(cmd: Sequence[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(cmd),
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def _run_bytes(cmd: Sequence[str], timeout: int = 60) -> subprocess.CompletedProcess:
    """Run a command and preserve stdout as bytes.

    This matters for icat because deleted-file content can contain binary padding
    or partially damaged bytes; forcing text mode too early can hide useful
    fragments.
    """
    return subprocess.run(
        list(cmd),
        text=False,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def _add_unique(lst: list[dict], item: dict) -> None:
    if item not in lst:
        lst.append(item)


def extract_flags(text: str) -> List[str]:
    return list(dict.fromkeys(FLAG_RE.findall(text or "")))


def extract_flags_from_bytes(data: bytes) -> List[str]:
    """Extract picoCTF flags from raw bytes, including UTF-16 variants.

    Sleuthkit Apprentice stores the real answer in a Unicode text file
    (commonly flag.uni.txt). A plain UTF-8 decode sees NUL-separated
    characters and misses picoCTF{...}.
    """
    if not data:
        return []

    candidates: List[str] = []
    texts: List[str] = []

    for enc in ("utf-8", "latin-1", "utf-16", "utf-16le", "utf-16be"):
        try:
            texts.append(data.decode(enc, errors="ignore"))
        except Exception:
            pass

    # Also remove NUL bytes; this catches UTF-16LE ASCII text even when no BOM exists.
    try:
        texts.append(data.replace(b"\x00", b"").decode("latin-1", errors="ignore"))
    except Exception:
        pass

    # Byte-level regex for p\x00i\x00c... style data.
    nul_pattern = re.compile(
        rb"p\x00?i\x00?c\x00?o\x00?C\x00?T\x00?F\x00?\{(?:[^}\x00]\x00?){1,200}\x00?\}",
        re.IGNORECASE,
    )
    for m in nul_pattern.finditer(data):
        raw = m.group(0).replace(b"\x00", b"")
        try:
            texts.append(raw.decode("ascii", errors="ignore"))
        except Exception:
            pass

    for text in texts:
        for flag in extract_flags(text):
            if flag not in candidates:
                candidates.append(flag)
    return candidates


def extract_flag(text: str) -> str | None:
    flags = extract_flags(text)
    return flags[0] if flags else None


def _decode_bytes_lossy(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _printable_strings_from_bytes(data: bytes, min_len: int = 4) -> List[str]:
    try:
        text = data.decode("latin-1", errors="ignore")
    except Exception:
        text = str(data)
    return re.findall(r"[ -~]{%d,}" % min_len, text)


def decode_encoded_text(raw: str) -> dict:
    out = {"raw": raw, "encoding": None, "decoded": None, "normalized_flag": None}
    cleaned = "".join(ch for ch in raw if ch.isalnum() or ch in "+/=_-").replace("-", "+").replace("_", "/")
    if cleaned:
        if len(cleaned) % 4:
            cleaned += "=" * ((4 - len(cleaned) % 4) % 4)
        try:
            dec = base64.b64decode(cleaned, validate=False).decode("utf-8", errors="replace").strip()
            out["encoding"] = "base64"
            out["decoded"] = dec
        except Exception:
            pass
    if out["decoded"]:
        f = extract_flag(out["decoded"])
        if f:
            out["normalized_flag"] = f
        elif re.fullmatch(r"[A-Za-z0-9_!@#$%^&*().\-]{8,200}", out["decoded"]):
            out["normalized_flag"] = f"picoCTF{{{out['decoded']}}}"
    return out


def parse_mmls_output(text: str) -> list[dict]:
    parts = []
    for line in text.splitlines():
        m = re.match(r"^\s*\d+:\s+([\d:]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+)$", line)
        if m:
            slot, start, end, length, desc = m.groups()
            parts.append(
                {
                    "slot": slot,
                    "start_sector": int(start),
                    "end_sector": int(end),
                    "length_sectors": int(length),
                    "description": desc.strip(),
                }
            )
    return parts


def partition_metadata_handler(image_path: str) -> dict:
    cp = _run(["mmls", image_path], timeout=30)
    res = {
        "tool": "partition_metadata_handler",
        "status": "completed" if cp.returncode == 0 else "error",
        "answers": [],
        "forensic_leads": [],
        "partitions": [],
    }
    if cp.returncode != 0:
        res["error"] = cp.stderr.strip()
        return res
    parts = parse_mmls_output(cp.stdout)
    res["partitions"] = parts
    for p in parts:
        if "Linux (0x83)" in p["description"]:
            _add_unique(
                res["answers"],
                {
                    "kind": "linux_partition_length_sectors",
                    "value": p["length_sectors"],
                    "source": f"mmls:{p['slot']}",
                },
            )
    return res



def _strings_from_text(text: str, min_len: int = 4) -> List[str]:
    return re.findall(r"[ -~]{%d,}" % min_len, text or "")


def _normalize_possible_flag(text: str) -> Optional[str]:
    """Return a verified picoCTF-style flag if text contains one or a bare decoded token."""
    if not text:
        return None

    direct = extract_flag(text)
    if direct:
        return direct

    # Search printable strings separately. icat output may contain binary padding.
    for chunk in _strings_from_text(text):
        direct = extract_flag(chunk)
        if direct:
            return direct

    decoded = decode_encoded_text(text.strip())
    if decoded.get("normalized_flag"):
        return decoded["normalized_flag"]

    # Some CTF files store only the inside of picoCTF{...}.
    cleaned = text.strip().strip("\x00").strip()
    if re.fullmatch(r"[A-Za-z0-9_!@#$%^&*().\-]{8,200}", cleaned):
        return f"picoCTF{{{cleaned}}}"

    return None


def _normalize_possible_flag_bytes(data: bytes) -> Optional[str]:
    """Flag recovery helper for raw icat bytes.

    Tries direct text, UTF-16/Unicode text, printable strings, compacted
    fragments, and base64-like encoded text. This is intentionally
    conservative: it only returns a verified picoCTF{...} string or a clear
    bare-token file content.
    """
    if not data:
        return None

    byte_flags = extract_flags_from_bytes(data)
    if byte_flags:
        return byte_flags[0]

    text = _decode_bytes_lossy(data)
    flag = _normalize_possible_flag(text)
    if flag:
        return flag

    strings = _printable_strings_from_bytes(data)
    joined = "".join(strings)
    flag = extract_flag(joined)
    if flag:
        return flag

    compact = re.sub(r"\s+", "", joined)
    flag = extract_flag(compact)
    if flag:
        return flag

    # Try each printable chunk as base64/URL-safe-base64.
    for chunk in strings:
        dec = decode_encoded_text(chunk.strip())
        if dec.get("normalized_flag"):
            return dec["normalized_flag"]
    return None


def _preview_bytes(data: bytes, limit: int = 300) -> str:
    strings = _printable_strings_from_bytes(data)
    if strings:
        return "\n".join(strings[:8])[:limit]
    return _decode_bytes_lossy(data)[:limit]


def _parse_fls_inode_line(line: str) -> Optional[Dict[str, str]]:
    """Parse common fls lines, including deleted/realloc entries.

    Examples:
      r/r 2082: flag.txt
      r/r * 2082(realloc): flag.txt
      + r/r * 2082(realloc): path/to/flag.txt
    """
    m = re.search(r"\b(?P<inode>\d+)(?:\([^)]*\))?:\s+(?P<path>.+)$", line)
    if not m:
        return None
    return {
        "inode": m.group("inode"),
        "path": m.group("path").strip(),
        "deleted": "*" in line or "realloc" in line.lower(),
        "raw": line.strip(),
    }


def sleuthkit_basic_inode_handler(
    image_path: str,
    sector_offsets: Sequence[int],
    name_keywords: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    keywords = list(name_keywords or [
        "flag", "pico", "ctf", "txt", "uni", "unicode", "secret", "note", "journal", "diary",
        "innocuous", "its-all-in-the-name", "force-wait", "safe", "hidden", "my_folder",
    ])
    findings: List[Dict[str, Any]] = []
    verified_flags: List[Dict[str, Any]] = []
    flag_candidates: List[Dict[str, Any]] = []
    forensic_leads: List[Dict[str, Any]] = []
    icat_attempts: List[Dict[str, Any]] = []

    for offset in sector_offsets:
        # -r: normal recursive listing. -rd: include deleted entries explicitly.
        listing_outputs: List[str] = []
        for args in (["fls", "-r", "-o", str(offset), image_path], ["fls", "-rd", "-o", str(offset), image_path]):
            fls = _run(args, timeout=90)
            if fls.returncode == 0 and fls.stdout:
                listing_outputs.append(fls.stdout)

        seen_inodes: set[str] = set()
        for fls_output in listing_outputs:
            for line in fls_output.splitlines():
                lower = line.lower()
                if not any(k.lower() in lower for k in keywords):
                    continue

                parsed = _parse_fls_inode_line(line)
                if not parsed:
                    continue

                inode = parsed["inode"]
                path = parsed["path"]
                key = f"{offset}:{inode}"
                if key in seen_inodes:
                    continue
                seen_inodes.add(key)

                item = {
                    "offset": offset,
                    "inode": inode,
                    "path": path,
                    "deleted": parsed["deleted"],
                    "source": "fls",
                }
                findings.append(item)
                _safe_append(
                    forensic_leads,
                    {"value": f"Interesting filename hit: {path}", "source": f"inode {inode} @ sector {offset}"},
                )

                # Normal icat can fail on deleted/reallocated ext entries. Try -r as a
                # second pass because Sleuthkit Apprentice often needs deleted-file recovery.
                icat_cmds = [
                    ["icat", "-o", str(offset), image_path, inode],
                    ["icat", "-r", "-o", str(offset), image_path, inode],
                ]
                for icat_cmd in icat_cmds:
                    try:
                        icat = _run_bytes(icat_cmd, timeout=45)
                    except Exception as exc:
                        icat_attempts.append({
                            "offset": offset, "inode": inode, "path": path,
                            "cmd": shlex.join(icat_cmd), "returncode": "exception",
                            "stderr": str(exc),
                        })
                        continue

                    data = icat.stdout or b""
                    preview = _preview_bytes(data) if data else ""
                    icat_attempts.append({
                        "offset": offset,
                        "inode": inode,
                        "path": path,
                        "cmd": shlex.join(icat_cmd),
                        "returncode": icat.returncode,
                        "stdout_bytes": len(data),
                        "stderr": (icat.stderr or b"").decode("utf-8", errors="replace")[:300],
                        "preview": preview,
                    })

                    if icat.returncode != 0 or not data:
                        continue

                    flag = _normalize_possible_flag_bytes(data)
                    if flag:
                        _safe_append(
                            verified_flags,
                            {
                                "value": flag,
                                "source": f"{Path(icat_cmd[0]).name} inode {inode} @ sector {offset}",
                                "handler": "sleuthkit_basic_inode_handler",
                                "path": path,
                                "command": shlex.join(icat_cmd),
                            },
                        )
                        break

                    if preview:
                        _safe_append(
                            flag_candidates,
                            {
                                "value": preview,
                                "source": f"icat preview inode {inode} @ sector {offset}",
                                "path": path,
                                "command": shlex.join(icat_cmd),
                            },
                        )

    return {
        "status": "completed",
        "tool": "sleuthkit_basic_inode_handler",
        "candidates": findings,
        "forensic_leads": forensic_leads,
        "flag_candidates": flag_candidates,
        "verified_flags": verified_flags,
        "icat_attempts": icat_attempts[:50],
    }

def timeline_handler(image_path: str, sector_offset: int, workdir: str, max_candidates: int = 25) -> dict:
    work = Path(workdir)
    work.mkdir(parents=True, exist_ok=True)
    body = work / "body.txt"
    csvf = work / "timeline.csv"
    res = {
        "tool": "timeline_handler",
        "status": "completed",
        "bodyfile": str(body),
        "timeline_csv": str(csvf),
        "candidate_inodes": [],
        "verified_flags": [],
        "forensic_leads": [],
    }
    fls = _run(["fls", "-m", "/", "-r", "-o", str(sector_offset), image_path], timeout=180)
    if fls.returncode != 0:
        res["status"] = "error"
        res["error"] = fls.stderr.strip()
        return res
    body.write_text(fls.stdout, encoding="utf-8", errors="replace")
    mt = _run(["mactime", "-b", str(body), "-d"], timeout=180)
    if mt.returncode != 0:
        res["status"] = "error"
        res["error"] = mt.stderr.strip()
        return res
    csvf.write_text(mt.stdout, encoding="utf-8", errors="replace")
    scored = []
    for row in mt.stdout.splitlines():
        m = re.search(r",(\d+),\"?(/[^\"]+)\"?$", row)
        if not m:
            continue
        inode, path = m.groups()
        score = 0
        if NAME_HINT_RE.search(path):
            score += 10
        if any(t in path.lower() for t in ["/tmp", "/root", "/home", "flag", "note", "secret", "txt"]):
            score += 5
        if score:
            scored.append((score, inode, path))
    seen = set()
    for _, inode, path in sorted(scored, reverse=True)[:max_candidates]:
        if inode in seen:
            continue
        seen.add(inode)
        res["candidate_inodes"].append({"inode": inode, "path": path})
        _add_unique(res["forensic_leads"], {"value": f"Timeline candidate: {path}", "source": f"inode {inode}"})
        icp = _run(["icat", "-o", str(sector_offset), image_path, inode], timeout=30)
        content = icp.stdout.strip()
        if not content:
            continue
        f = extract_flag(content)
        if f:
            _add_unique(res["verified_flags"], {"value": f, "source": f"timeline+icat inode {inode}"})
            continue
        dec = decode_encoded_text(content)
        if dec.get("normalized_flag"):
            _add_unique(
                res["verified_flags"],
                {"value": dec["normalized_flag"], "source": f"timeline+icat+decode inode {inode}"},
            )
    return res


def binary_residual_fragment_grep_handler(image_path: str, clues: Sequence[str]) -> dict:
    res = {
        "tool": "binary_residual_fragment_grep_handler",
        "status": "completed",
        "forensic_leads": [],
        "verified_flags": [],
        "raw_hits": [],
    }
    blob = ""
    for clue in clues:
        cp = _run(["grep", "-a", clue, image_path], timeout=120)
        if cp.returncode in (0, 1) and cp.stdout:
            res["raw_hits"].append(cp.stdout)
            blob += "\n" + cp.stdout
            _add_unique(res["forensic_leads"], {"value": f"Residual grep hit for clue {clue}", "source": "grep -a"})
    f = extract_flag(blob)
    if f:
        _add_unique(res["verified_flags"], {"value": f, "source": "binary_residual_fragment_grep_handler"})
    else:
        pieces = []
        for pat in [r"pic", r"oCT", r"F\{[A-Za-z0-9_]{0,4}", r"[A-Za-z0-9_]{3,4}\}", r"[A-Za-z0-9_]{3,4}"]:
            pieces.extend(re.findall(pat, blob))
        joined = "".join(pieces)
        if joined.startswith("picoCTF{") and "}" in joined:
            cand = joined[: joined.index("}") + 1]
            if FLAG_RE.fullmatch(cand):
                _add_unique(
                    res["verified_flags"],
                    {"value": cand, "source": "binary_residual_fragment_grep_handler:fragment_reassembly"},
                )
    return res
