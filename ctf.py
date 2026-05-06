#!/usr/bin/env python3
"""
PicoCTF Modular Toolkit
Single entry point for category-based CTF helper tools.

Two ways to use:
  1) Interactive menu for normal users:
     python ctf.py

  2) Direct command mode for advanced users:
     python ctf.py list
     python ctf.py web http://example.com --mode ctf
     python ctf.py crypto "Y2hlY2tfZmxhZw==" --recursive
     python ctf.py forensics disk.img --strings --report
     python ctf.py binary analyze ./vuln
"""
from __future__ import annotations

import os
import subprocess
import sys
import shlex
import importlib.util
import re
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
PYTHON = sys.executable

TOOLS: Dict[str, dict] = {
    "web": {
        "category": "Web Exploitation",
        "aliases": ["web-exploitation", "hunter", "hunter2"],
        "path": ROOT / "tools" / "web-exploitation" / "hunter2",
        "entry": [PYTHON, "-m", "hunter.cli"],
        "summary": "Hunter-2: rule-based web scanner for picoCTF web targets.",
        "example": "python ctf.py web http://titan.picoctf.net:12345 --mode ctf --passive --report report",
    },
    "crypto": {
        "category": "Cryptography",
        "aliases": ["cryptography", "decode", "decoder", "decode-helper"],
        "path": ROOT / "tools" / "cryptography" / "decode-helper",
        "entry": [PYTHON, "main.py"],
        "summary": "Decode Helper: keyless decoding, recursive multi-layer decode, file input, reports.",
        "example": "python ctf.py crypto 'Y2hlY2tfZmxhZw==' --recursive --compact",
    },
    "forensics": {
        "category": "Forensics",
        "aliases": ["forensic", "artifact", "artifactscope", "disk"],
        "path": ROOT / "tools" / "forensics" / "artifactscope",
        "entry": [PYTHON, "main.py"],
        "summary": "ArtifactScope: file/disk-image triage, strings, carving, git/FS recovery.",
        "example": "python ctf.py forensics ./disk.img --strings --carve --report",
    },
    "binary": {
        "category": "Binary Exploitation",
        "aliases": ["binary-exploitation", "pwn", "pwn-helper"],
        "path": ROOT / "tools" / "binary-exploitation" / "pwn-helper",
        "entry": [PYTHON, "main.py"],
        "summary": "Pwn Helper: ELF protection analysis, exploit strategy, templates, fmt/offset helpers.",
        "example": "python ctf.py binary analyze ./vuln",
    },
}

ALIAS_TO_KEY: Dict[str, str] = {}
for key, meta in TOOLS.items():
    ALIAS_TO_KEY[key] = key
    for alias in meta["aliases"]:
        ALIAS_TO_KEY[alias] = key


# Tool-specific Python package requirements.
# Keep this minimal so Web scans do not force heavy Binary/Forensics dependencies.
PYTHON_DEPS = {
    "web": [("yaml", "PyYAML"), ("requests", "requests")],
    "forensics": [("yaml", "PyYAML")],
    "crypto": [],  # updated decode-helper is standard-library only
    "binary": [("pwn", "pwntools")],
}


def is_msys_python() -> bool:
    exe = str(Path(PYTHON)).replace("\\", "/").lower()
    return "msys64" in exe or "/ucrt64/" in exe or "/mingw64/" in exe


def ensure_pip_available() -> bool:
    """Ensure pip exists before trying package installation.

    Some MSYS2 Python builds do not ship with pip.  In that case we give a
    precise fix instead of failing with a confusing "No module named pip".
    """
    if importlib.util.find_spec("pip") is not None:
        return True

    print("\n[SETUP] 目前這個 Python 沒有 pip，先嘗試啟用 ensurepip。")
    result = subprocess.call([PYTHON, "-m", "ensurepip", "--upgrade"], cwd=str(ROOT))
    if result == 0 and importlib.util.find_spec("pip") is not None:
        return True

    print("\n[ERROR] 目前 Python 無法使用 pip，所以不能自動安裝缺少套件。")
    print(f"[PYTHON] {PYTHON}")
    if is_msys_python():
        print("\n你現在用到的是 MSYS2/UCRT64 Python。建議二選一：")
        print("  1) 改用 Windows Python 啟動：")
        print("     py -3 ctf.py")
        print("  2) 在 MSYS2 UCRT64 終端機安裝 pip：")
        print("     pacman -S mingw-w64-ucrt-x86_64-python-pip")
    else:
        print("\n請先安裝 pip，或改用已安裝 pip 的 Python。")
        print("常見修法：")
        print("  py -3 -m ensurepip --upgrade")
        print("  py -3 -m pip install --upgrade pip")
    return False


def ensure_python_deps(key: str) -> bool:
    """Auto-install missing Python dependencies for the selected module."""
    deps = PYTHON_DEPS.get(key, [])
    missing = [(module, package) for module, package in deps if importlib.util.find_spec(module) is None]
    if not missing:
        return True

    packages = [package for _, package in missing]
    print("\n[SETUP] 缺少必要套件：" + ", ".join(packages))

    if not ensure_pip_available():
        print("\n請修好 pip 後再執行：")
        print("  " + " ".join([PYTHON, "-m", "pip", "install", *packages]))
        return False

    print("[SETUP] 正在自動安裝，之後會繼續執行工具。")
    cmd = [PYTHON, "-m", "pip", "install", *packages]
    result = subprocess.call(cmd, cwd=str(ROOT))
    if result != 0:
        print("\n[SETUP] 一般安裝失敗，改用 --user 再試一次。")
        result = subprocess.call([PYTHON, "-m", "pip", "install", "--user", *packages], cwd=str(ROOT))

    if result != 0:
        print("\n[ERROR] 依賴安裝失敗。請手動執行：")
        print("  " + " ".join([PYTHON, "-m", "pip", "install", *packages]))
        return False
    return True


def print_tool_list() -> None:
    print("PicoCTF Modular Toolkit")
    print("=" * 25)
    for key, meta in TOOLS.items():
        print(f"\n[{key}] {meta['category']}")
        print(f"  {meta['summary']}")
        print(f"  aliases : {', '.join(meta['aliases'])}")
        print(f"  example : {meta['example']}")
    print("\nReserved picoCTF categories for future modules:")
    print("  general-skills, reverse-engineering")


def run_tool(key: str, args: List[str]) -> int:
    meta = TOOLS[key]
    if not ensure_python_deps(key):
        return 2
    tool_dir: Path = meta["path"]
    if not tool_dir.exists():
        print(f"[ERROR] tool directory not found: {tool_dir}", file=sys.stderr)
        return 2

    args = normalize_tool_args_for_platform(key, args)
    cmd = list(meta["entry"]) + args
    env = os.environ.copy()
    # Keep each legacy tool import behavior stable by running inside its own root.
    env["PYTHONPATH"] = str(tool_dir) + os.pathsep + env.get("PYTHONPATH", "")

    print("\n[RUN] " + " ".join(cmd), flush=True)
    print(f"[CWD] {tool_dir}\n", flush=True)

    try:
        return subprocess.call(cmd, cwd=str(tool_dir), env=env)
    except KeyboardInterrupt:
        print("\n[Interrupted]", file=sys.stderr)
        return 130


def ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print("\n[取消]")
        return ""


def strip_outer_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '\"'}:
        return value[1:-1].strip()
    return value


def windows_path_to_wsl(value: str) -> str:
    r"""Accept pasted Windows paths while running inside WSL/Linux.

    Examples:
      C:\Users\10801\Downloads\vuln -> /mnt/c/Users/10801/Downloads/vuln
      C:/Users/10801/Downloads/disk.img -> /mnt/c/Users/10801/Downloads/disk.img

    Non-Windows paths are returned unchanged.
    """
    raw = strip_outer_quotes(value)
    if not raw:
        return raw

    # WSL/Linux path or relative path: keep unchanged.
    if raw.startswith(("/", "./", "../", "~")):
        return os.path.expanduser(raw)

    normalized = raw.replace("\\", "/")

    # Drive-letter path, e.g. C:/Users/...
    if len(normalized) >= 3 and normalized[1] == ":" and normalized[2] == "/" and normalized[0].isalpha():
        drive = normalized[0].lower()
        rest = normalized[3:]
        return f"/mnt/{drive}/{rest}"

    return raw


def normalize_file_target(raw: str) -> str:
    target = windows_path_to_wsl(raw)
    if target and target != raw.strip():
        print(f"[PATH] Windows 路徑已轉換為 WSL 路徑：{target}")

    # Direct command mode is usually launched from the toolkit root, but each
    # legacy tool runs inside its own subdirectory.  If a relative file path
    # exists from the current launcher location, pass an absolute path so it
    # still works after cwd changes.  Tool-local paths such as samples/base64.txt
    # remain unchanged when they do not exist from the launcher cwd.
    if target and not os.path.isabs(target):
        candidate = Path(target).expanduser()
        if candidate.exists():
            target = str(candidate.resolve())
    return target


def normalize_tool_args_for_platform(key: str, args: List[str]) -> List[str]:
    """Normalize pasted Windows file paths for direct command mode too."""
    if not args:
        return args

    new_args = list(args)
    if key == "crypto":
        # Decode Helper file mode: normalize the value after --file.
        for i, arg in enumerate(new_args):
            if arg == "--file" and i + 1 < len(new_args):
                new_args[i + 1] = normalize_file_target(new_args[i + 1])
                break
    elif key == "forensics":
        # First non-option argument is the target file/disk image.
        for i, arg in enumerate(new_args):
            if not arg.startswith("-"):
                new_args[i] = normalize_file_target(arg)
                break
    elif key == "binary":
        # Common form: binary analyze <target> or binary strategy <target>.
        for i, arg in enumerate(new_args):
            if i == 0 and arg in {"analyze", "strategy", "template", "offset", "fmt"}:
                continue
            if not arg.startswith("-"):
                new_args[i] = normalize_file_target(arg)
                break
    return new_args



def read_text_preview(path_value: str, limit: int = 12000) -> str:
    try:
        with open(path_value, "r", encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return ""


def detect_crypto_input_mode(text: str) -> str:
    """Best-effort router for Decode Helper modes."""
    sample = text.strip()
    if not sample:
        return "direct-decode"

    lower = sample.lower()
    script_signals = [
        "def ", "import ", "from ", "bytes_to_long", "long_to_bytes",
        "getprime", "pow(", "inverse(", "xor", "chr(", "ord(",
    ]
    if any(sig in lower for sig in script_signals):
        return "script-reverse"

    rsa_patterns = [
        r"(?m)^\s*n\s*=\s*\d+",
        r"(?m)^\s*e\s*=\s*\d+",
        r"(?m)^\s*c\s*=\s*\d+",
        r"(?m)^\s*n\d+\s*=\s*\d+",
        r"(?m)^\s*e\d+\s*=\s*\d+",
        r"(?m)^\s*c\d+\s*=\s*\d+",
        r"(?m)^\s*(p|q|phi|d|dp|dq|qinv)\s*=\s*\d+",
    ]
    hits = sum(1 for pat in rsa_patterns if re.search(pat, sample))
    if hits >= 2:
        return "crypto-rsa"

    return "direct-decode"


def build_crypto_args_from_file(target: str, report_path: str) -> list[str]:
    preview = read_text_preview(target)
    mode = detect_crypto_input_mode(preview)
    if mode == "crypto-rsa":
        print("[ROUTER] 偵測到 RSA 結構化輸入，將切換到 crypto-rsa 模式。")
        return ["--mode", "crypto-rsa", "--file", target, "--report", report_path]
    if mode == "script-reverse":
        print("[ROUTER] 偵測到腳本/加密程式內容，將切換到 script-reverse 模式。")
        return ["--mode", "script-reverse", "--file", target, "--report", report_path]
    print("[ROUTER] 偵測為一般編碼/密文輸入，將使用 direct-decode 模式。")
    return ["--file", target, "--recursive", "--depth", "4", "--max-branch", "4", "--top", "10", "--report", report_path]


def build_crypto_args_from_text(text_value: str, report_path: str) -> list[str]:
    mode = detect_crypto_input_mode(text_value)
    if mode == "script-reverse":
        print("[ROUTER] 偵測到腳本/加密程式內容。建議改用檔案模式，或直接選 3. 自訂參數。")
    return [text_value, "--recursive", "--compact", "--report", report_path]



def looks_like_elf(path_value: str) -> bool:
    """Return True when the target appears to be a Linux ELF binary."""
    try:
        with open(path_value, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def warn_if_not_elf(path_value: str) -> bool:
    """Warn users when Binary mode is given a non-ELF input.

    The most common mistake is pasting a crypto sample/text file path into
    Binary Exploitation mode.  We do not block execution completely because
    advanced users may still want to test an unusual file, but the interactive
    flow defaults to returning to the menu.
    """
    if not path_value:
        return False
    if not Path(path_value).exists():
        print(f"[WARN] 找不到檔案：{path_value}")
        return False
    if looks_like_elf(path_value):
        return True

    print("\n[WARN] 這個檔案看起來不是 Linux ELF binary。")
    print(f"[FILE] {path_value}")
    print("Binary Exploitation 模式應該輸入像 ./vuln、chall、ret2win 這類 ELF 檔。")
    print("如果你貼的是 hex.txt、cipher.txt、encoded.txt，請改選：")
    print("  2. Cryptography -> Decode Helper")
    return False


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    return raw


def is_valid_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def interactive_web() -> int:
    print("\n[Web Exploitation] Hunter-2 CTF 掃描")
    print("請貼上 picoCTF 題目的網址，例如：http://titan.picoctf.net:12345/")
    url = normalize_url(ask("URL> "))
    if not url:
        return 0
    if not is_valid_url(url):
        print("[ERROR] URL 格式不正確，請確認有 host，例如 http://host:port")
        return 2

    print("\n掃描模式：")
    print("  1. CTF 完整模式，推薦：discover + passive + artifact/report")
    print("  2. 快速模式：較少請求，先看基本結果")
    print("  3. 自訂 Hunter-2 參數")
    mode = ask("選擇 [1/2/3，預設 1]> ") or "1"

    if mode == "2":
        args = [url, "fast", "--mode", "ctf", "--report", "report"]
    elif mode == "3":
        extra = ask("請輸入額外參數，例如 --mode ctf --print-matches --report report\nARGS> ")
        args = [url] + (shlex.split(extra) if extra else ["--mode", "ctf"])
    else:
        # Hunter-2 內建 --mode ctf 會啟用：ctf pack, discover, passive, verbose,
        # print matches, artifact analysis, save artifacts, html report 等設定。
        args = [url, "medium", "--mode", "ctf", "--report", "report"]

    print("\n即將啟動 Hunter-2 整套 CTF 掃描流程。")
    return run_tool("web", args)


def interactive_crypto() -> int:
    print("\n[Cryptography] Decode Helper")
    print("分析模式：")
    print("  1. 貼上密文/編碼字串，推薦")
    print("  2. 讀取文字檔，支援 Windows 路徑")
    print("  3. 自訂 Decode Helper 參數")
    choice = ask("選擇 [1/2/3，預設 1]> ") or "1"

    if choice == "2":
        target = normalize_file_target(ask("請輸入文字檔路徑（支援 Windows 路徑，例如 C:\\Users\\...）> "))
        if not target:
            return 0
        return run_tool("crypto", build_crypto_args_from_file(target, "reports/toolkit-crypto-file-result.md"))

    if choice == "3":
        extra = ask("請輸入 Decode Helper 參數，例如 --file samples/base64.txt --recursive --top 10\nARGS> ")
        return run_tool("crypto", shlex.split(extra) if extra else [])

    text_value = ask("請貼上要解碼的文字> ")
    if not text_value:
        return 0

    mode = detect_crypto_input_mode(text_value)
    if mode == "crypto-rsa":
        print("[ROUTER] 偵測到 RSA 結構化輸入。為避免命令列長度與換行問題，會先存成暫存檔再交給 crypto-rsa。")
        temp_dir = ROOT / "tools" / "cryptography" / "decode-helper" / "reports"
        temp_dir.mkdir(parents=True, exist_ok=True)
        temp_path = temp_dir / "toolkit-crypto-inline-rsa.txt"
        temp_path.write_text(text_value, encoding="utf-8")
        return run_tool("crypto", ["--mode", "crypto-rsa", "--file", str(temp_path), "--report", "reports/toolkit-crypto-inline-rsa.md"])

    if mode == "script-reverse":
        print("[ROUTER] 偵測到腳本/加密程式內容。建議改用檔案模式，或選 3. 自訂參數。")

    return run_tool("crypto", build_crypto_args_from_text(text_value, "reports/toolkit-crypto-result.md"))

def interactive_forensics() -> int:
    print("\n[Forensics] ArtifactScope")
    target = normalize_file_target(ask("請輸入檔案或 disk image 路徑（支援 Windows 路徑，例如 C:\\Users\\...）> "))
    if not target:
        return 0
    print("\n分析模式：")
    print("  1. 基本分析")
    print("  2. strings + carve + report，推薦")
    choice = ask("選擇 [1/2，預設 2]> ") or "2"
    args = [target, "--strings", "--carve", "--report"] if choice == "2" else [target]
    return run_tool("forensics", args)


def interactive_binary() -> int:
    print("\n[Binary Exploitation] Pwn Helper")
    target = normalize_file_target(ask("請輸入 ELF / binary 路徑（支援 Windows 路徑，例如 C:\\Users\\...）> "))
    if not target:
        return 0
    if not warn_if_not_elf(target):
        choice = ask("仍然要用 Binary 模式嘗試執行嗎？[y/N]> ").lower()
        if choice not in {"y", "yes"}:
            print("已取消。請回主選單後改選正確分類。")
            return 0
    print("\n分析模式：")
    print("  1. analyze，保護機制與基本資訊")
    print("  2. strategy，利用方向建議")
    choice = ask("選擇 [1/2，預設 1]> ") or "1"
    action = "strategy" if choice == "2" else "analyze"
    return run_tool("binary", [action, target])


def interactive_menu() -> int:
    while True:
        print("\nPicoCTF Modular Toolkit")
        print("=" * 25)
        print("1. Web Exploitation    -> Hunter-2")
        print("2. Cryptography        -> Decode Helper")
        print("3. Forensics           -> ArtifactScope")
        print("4. Binary Exploitation -> Pwn Helper")
        print("5. 顯示工具列表")
        print("0. 離開")
        choice = ask("\n請選擇模式 [0-5]> ")

        if choice in {"0", "q", "quit", "exit"}:
            print("bye")
            return 0
        if choice == "1":
            return interactive_web()
        if choice == "2":
            return interactive_crypto()
        if choice == "3":
            return interactive_forensics()
        if choice == "4":
            return interactive_binary()
        if choice == "5":
            print_tool_list()
            continue
        print("[ERROR] 無效選項，請重新選擇。")


def main(argv: List[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # No argument = user-friendly interactive mode.
    if not argv:
        return interactive_menu()

    if argv[0] in {"-h", "--help"}:
        print("Usage:")
        print("  python ctf.py                  # interactive menu")
        print("  python ctf.py list")
        print("  python ctf.py <category> [tool arguments...]\n")
        print("Categories: web, crypto, forensics, binary")
        print("Examples:")
        print("  python ctf.py web http://target --mode ctf")
        print("  python ctf.py crypto 'Y2hlY2tfZmxhZw==' --recursive")
        return 0

    cmd = argv[0].lower().strip()
    if cmd in {"menu", "interactive", "start"}:
        return interactive_menu()
    if cmd in {"list", "categories", "tools"}:
        print_tool_list()
        return 0

    key = ALIAS_TO_KEY.get(cmd)
    if not key:
        print(f"[ERROR] unknown category/tool: {argv[0]}", file=sys.stderr)
        print("Available: web, crypto, forensics, binary", file=sys.stderr)
        print("Tip: run without arguments for interactive mode: python ctf.py", file=sys.stderr)
        return 2

    return run_tool(key, argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
