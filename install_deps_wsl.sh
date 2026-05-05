#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
PY="${PYTHON:-python3}"

if ! command -v "$PY" >/dev/null 2>&1; then
  echo "[ERROR] 找不到 python3。Ubuntu/WSL 可執行：sudo apt update && sudo apt install -y python3 python3-venv python3-pip"
  exit 1
fi

if [ ! -d ".venv" ]; then
  echo "[SETUP] 建立 .venv"
  "$PY" -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate
python -m ensurepip --upgrade >/dev/null 2>&1 || true
python -m pip install --upgrade pip
python -m pip install -r requirements-all.txt
python -m pip install PyYAML requests

echo "[OK] WSL/Linux 依賴安裝完成。之後可執行：./run_wsl.sh"
