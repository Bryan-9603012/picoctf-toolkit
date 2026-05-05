
from __future__ import annotations
import json
import re
import shutil
import subprocess
from pathlib import Path

HEX32_RE = re.compile(r'([0-9a-fA-F]{32})')

def run_cmd(cmd, timeout=15, input_data=None):
    try:
        p = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 1, "", str(e)

def which(name):
    return shutil.which(name)

def save_json(path, obj):
    Path(path).write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")

def extract_hex32(text: str):
    m = HEX32_RE.search(text or "")
    return m.group(1) if m else None

def parse_num_list(s: str):
    out = []
    for x in s.split(","):
        x = x.strip()
        if not x:
            continue
        out.append(int(x, 0))
    return out
