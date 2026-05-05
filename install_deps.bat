@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul
cd /d "%~dp0"
title PicoCTF Toolkit - Install Dependencies

set "PY_CMD="
where py >nul 2>nul
if not errorlevel 1 (
    py -3 -c "import sys" >nul 2>nul
    if not errorlevel 1 set "PY_CMD=py -3"
)
if not defined PY_CMD (
    where python >nul 2>nul
    if not errorlevel 1 set "PY_CMD=python"
)
if not defined PY_CMD (
    echo [ERROR] 找不到 Python。
    goto END
)

echo [PY] !PY_CMD!
echo [SETUP] 安裝基本依賴：PyYAML requests
!PY_CMD! -m ensurepip --upgrade
!PY_CMD! -m pip install --upgrade pip
!PY_CMD! -m pip install PyYAML requests

echo.
echo [DONE] 完成。接著可以雙擊 ctf.bat。
:END
echo.
pause
