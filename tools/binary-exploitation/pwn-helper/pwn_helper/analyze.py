
from __future__ import annotations
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from pwn_helper.utils import run_cmd, which

DANGEROUS_FUNCS = [
    "gets", "strcpy", "strncpy", "strcat", "sprintf", "vsprintf",
    "printf", "fprintf", "scanf", "read", "memcpy", "system",
    "execve", "signal", "alarm", "mprotect", "fgets",
]
INTERESTING_SYMBOLS = [
    "win", "flag", "sigsegv", "handler", "main", "system", "puts", "printf"
]

@dataclass
class AnalysisResult:
    binary: str
    file: str
    checksec: dict
    dangerous_functions: list
    interesting_symbols: list
    patterns: list
    notes: list

def parse_file(binary):
    rc, out, err = run_cmd(["file", binary])
    return (out or err).strip()

def parse_checksec(binary):
    result = {"arch": None, "relro": None, "canary": None, "nx": None, "pie": None, "rwx_segments": None, "raw": ""}
    if which("checksec"):
        rc, out, err = run_cmd(["checksec", f"--file={binary}"])
        raw = out + ("\n" + err if err else "")
        result["raw"] = raw.strip()
        pats = {
            "arch": r"Arch:\s*(.+)",
            "relro": r"RELRO:\s*(.+)",
            "canary": r"Stack:\s*(No canary found|Canary found)",
            "nx": r"NX:\s*(.+)",
            "pie": r"PIE:\s*(.+)",
            "rwx_segments": r"RWX:\s*(.+)",
        }
        for k, pat in pats.items():
            m = re.search(pat, raw)
            if m:
                result[k] = m.group(1).strip()
        return result

    rc, out, err = run_cmd(["readelf", "-W", "-l", binary])
    raw = out + ("\n" + err if err else "")
    result["raw"] = raw.strip()
    result["nx"] = "GNU_STACK present" if "GNU_STACK" in raw else "unknown"
    result["pie"] = "unknown"
    return result

def extract_strings(binary):
    rc, out, err = run_cmd(["strings", "-a", binary], timeout=20)
    return out or ""

def extract_symbols(binary):
    rc, out, err = run_cmd(["nm", "-C", binary], timeout=20)
    return out or ""

def detect_dangerous_functions(strings_out, symbols_out):
    hay = strings_out + "\n" + symbols_out
    found = []
    for fn in DANGEROUS_FUNCS:
        if re.search(rf"\b{re.escape(fn)}\b", hay):
            found.append(fn)
    return sorted(set(found))

def detect_interesting_symbols(symbols_out, strings_out):
    hay = symbols_out + "\n" + strings_out
    found = []
    for sym in INTERESTING_SYMBOLS:
        if re.search(rf"\b{re.escape(sym)}\b", hay, re.IGNORECASE):
            found.append(sym)
    return sorted(set(found))

def detect_patterns(checksec, dangerous, symbols):
    patterns = []
    notes = []

    nx = (checksec.get("nx") or "").lower()
    pie = (checksec.get("pie") or "").lower()
    rwx = (checksec.get("rwx_segments") or "").lower()
    sym_low = {s.lower() for s in symbols}
    has_fmt_overflow = "printf" in dangerous and "strcpy" in dangerous

    if has_fmt_overflow:
        patterns.append("format_string_plus_stack_overflow")
        notes.append("偵測到 printf + strcpy，可能是 leak + overflow 題型。")
    if "signal" in dangerous and any("sigsegv" in s or "handler" in s for s in sym_low):
        patterns.append("signal_handler_path")
        notes.append("偵測到 signal / handler，可能存在 crash-trigger 類利用。")
    if "exec" in nx or "rwx" in rwx or "has rwx" in rwx:
        patterns.append("shellcode_injection_candidate")
        notes.append("Stack / segment 具可執行性，適合考慮 shellcode injection。")
    if "nx enabled" in nx and has_fmt_overflow:
        patterns.append("fmt_ret2libc_candidate")
        notes.append("NX 啟用且存在 printf + strcpy，適合考慮 ret2libc / one_gadget。")
    if "strcpy" in dangerous:
        patterns.append("strcpy_copy_path")
        notes.append("輸入透過 strcpy 複製，ROP chain 可能受到 NUL byte 截斷影響。")
    if "no pie" in pie:
        patterns.append("fixed_binary_base")
        notes.append("PIE 關閉，binary base 固定。")
    if "win" in sym_low:
        patterns.append("ret2win_candidate")
        notes.append("偵測到 win 符號，可優先嘗試 ret2win。")
    return patterns, notes

def analyze_binary(binary):
    if not Path(binary).exists():
        raise FileNotFoundError(binary)
    file_out = parse_file(binary)
    checksec = parse_checksec(binary)
    strings_out = extract_strings(binary)
    symbols_out = extract_symbols(binary)
    dangerous = detect_dangerous_functions(strings_out, symbols_out)
    interesting = detect_interesting_symbols(symbols_out, strings_out)
    patterns, notes = detect_patterns(checksec, dangerous, interesting)
    return AnalysisResult(str(Path(binary).resolve()), file_out, checksec, dangerous, interesting, patterns, notes)

def result_to_dict(res):
    return asdict(res)

def pretty_print_result(res):
    d = result_to_dict(res)
    lines = []
    lines.append(f"[+] Binary: {d['binary']}")
    lines.append(f"[+] File: {d['file']}")
    lines.append("[+] Checksec:")
    for k in ["arch", "relro", "canary", "nx", "pie", "rwx_segments"]:
        lines.append(f"    - {k}: {d['checksec'].get(k)}")
    lines.append(f"[+] Dangerous functions: {', '.join(d['dangerous_functions']) or '(none)'}")
    lines.append(f"[+] Interesting symbols: {', '.join(d['interesting_symbols']) or '(none)'}")
    lines.append(f"[+] Patterns: {', '.join(d['patterns']) or '(none)'}")
    if d["notes"]:
        lines.append("[+] Notes:")
        for n in d["notes"]:
            lines.append(f"    - {n}")
    return "\n".join(lines)
