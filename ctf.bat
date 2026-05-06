@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul
cd /d "%~dp0"
title PicoCTF Modular Toolkit

set "EXIT_CODE=0"
set "PY_CMD="
set "USE_WSL=0"
set "WSL_DIR="

echo [BOOT] PicoCTF Modular Toolkit
echo [DIR ] %CD%
echo.

echo [%DATE% %TIME%] Launcher start > "%~dp0ctf-last-run.log"

rem Prefer WSL on Windows because this toolkit is currently tuned for the WSL/Linux flow.
where wsl.exe >nul 2>nul
if not errorlevel 1 (
    for /f "delims=" %%I in ('wsl.exe wslpath -a "%CD%" 2^>nul') do set "WSL_DIR=%%I"
    if defined WSL_DIR set "USE_WSL=1"
)

if "%USE_WSL%"=="1" (
    echo [MODE] 使用 WSL 啟動，較穩定。
    echo [WSL ] !WSL_DIR!
    echo [RUN ] wsl.exe bash -lc "cd \"!WSL_DIR!\" ^&^& chmod +x run_wsl.sh install_deps_wsl.sh ^&^& ./run_wsl.sh"
    echo.
    >> "%~dp0ctf-last-run.log" echo [%DATE% %TIME%] WSL mode !WSL_DIR!
    wsl.exe bash -lc "cd \"!WSL_DIR!\" && chmod +x run_wsl.sh install_deps_wsl.sh && ./run_wsl.sh"
    set "EXIT_CODE=!ERRORLEVEL!"
    goto END
)

rem Fallback: try native Windows Python launcher.
where py >nul 2>nul
if not errorlevel 1 (
    py -3 -c "import sys; print(sys.executable)" >nul 2>nul
    if not errorlevel 1 set "PY_CMD=py -3"
)
if not defined PY_CMD (
    where python >nul 2>nul
    if not errorlevel 1 (
        python -c "import sys; print(sys.executable)" >nul 2>nul
        if not errorlevel 1 set "PY_CMD=python"
    )
)
if not defined PY_CMD (
    where python3 >nul 2>nul
    if not errorlevel 1 (
        python3 -c "import sys; print(sys.executable)" >nul 2>nul
        if not errorlevel 1 set "PY_CMD=python3"
    )
)

if not defined PY_CMD (
    echo [ERROR] 找不到可用的 WSL 或 Python 3。
    echo.
    echo 建議：
    echo   1. 安裝 WSL Ubuntu 後直接雙擊 ctf.bat
    echo   2. 或安裝 Windows Python 後執行 py -3 ctf.py
    goto END
)

echo [MODE] 使用 Windows Python 後備模式。
echo [PY  ] !PY_CMD!
echo [RUN ] !PY_CMD! "%~dp0ctf.py" %*
echo.
>> "%~dp0ctf-last-run.log" echo [%DATE% %TIME%] Windows mode !PY_CMD!
call !PY_CMD! "%~dp0ctf.py" %*
set "EXIT_CODE=!ERRORLEVEL!"

:END
echo.>> "%~dp0ctf-last-run.log"
echo [%DATE% %TIME%] Exit code !EXIT_CODE! >> "%~dp0ctf-last-run.log"
echo.
echo ------------------------------------------------------------
echo 程式已結束。Exit code: !EXIT_CODE!
echo 如果前面有錯誤，請把畫面或 ctf-last-run.log 貼給我。
echo ------------------------------------------------------------
echo.
pause
exit /b !EXIT_CODE!
