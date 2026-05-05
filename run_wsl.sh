#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "[BOOT] PicoCTF Modular Toolkit - WSL/Linux"
echo "[DIR ] $(pwd)"

PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "[ERROR] 找不到 python3，請先安裝：sudo apt update && sudo apt install -y python3 python3-venv python3-pip"
  exit 1
fi

# Use a project-local virtualenv so system Python is not polluted.
if [ ! -d ".venv" ]; then
  echo "[SETUP] 建立 .venv"
  "$PY" -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

python -m ensurepip --upgrade >/dev/null 2>&1 || true
python -m pip install --upgrade pip >/dev/null

# Minimal deps needed for interactive web/Hunter-2 flow.
echo "[SETUP] 檢查必要套件 PyYAML requests"
python -m pip install -q PyYAML requests

echo "[RUN ] python ctf.py $*"
echo
python ctf.py "$@"
