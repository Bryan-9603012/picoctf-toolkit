@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul
cd /d "%~dp0"
title PicoCTF Toolkit - Install Dependencies

set "EXIT_CODE=0"
set "WSL_DIR="
set "PY_CMD="

echo [BOOT] Install Dependencies
echo [DIR ] %CD%
echo.

where wsl.exe >nul 2>nul
if not errorlevel 1 (
    for /f "delims=" %%I in ('wsl.exe wslpath -a "%CD%" 2^>nul') do set "WSL_DIR=%%I"
)

if defined WSL_DIR (
    echo [MODE] 使用 WSL 安裝依賴。
    echo [WSL ] !WSL_DIR!
    echo [RUN ] wsl.exe bash -lc "cd \"!WSL_DIR!\" ^&^& chmod +x install_deps_wsl.sh run_wsl.sh ^&^& ./install_deps_wsl.sh"
    echo.
    wsl.exe bash -lc "cd \"!WSL_DIR!\" && chmod +x install_deps_wsl.sh run_wsl.sh && ./install_deps_wsl.sh"
    set "EXIT_CODE=!ERRORLEVEL!"
    goto END
)

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
    echo [ERROR] 找不到 WSL，也找不到 Windows Python。
    goto END
)

echo [MODE] 使用 Windows Python 後備模式。
echo [PY  ] !PY_CMD!
echo [SETUP] 安裝基本依賴：PyYAML requests pwntools
!PY_CMD! -m ensurepip --upgrade
!PY_CMD! -m pip install --upgrade pip
!PY_CMD! -m pip install PyYAML requests pwntools
set "EXIT_CODE=!ERRORLEVEL!"

:END
echo.
echo [DONE] Exit code: !EXIT_CODE!
echo.
pause
exit /b !EXIT_CODE!
