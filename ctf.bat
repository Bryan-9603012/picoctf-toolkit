@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul
cd /d "%~dp0"
title PicoCTF Modular Toolkit

set "EXIT_CODE=0"
set "PY_CMD="

echo [BOOT] PicoCTF Modular Toolkit
echo [DIR ] %CD%
echo.

rem Prefer official Windows Python launcher.
where py >nul 2>nul
if not errorlevel 1 (
    py -3 -c "import sys; print(sys.executable)" >nul 2>nul
    if not errorlevel 1 (
        set "PY_CMD=py -3"
    )
)

rem Fallback to python in PATH.
if not defined PY_CMD (
    where python >nul 2>nul
    if not errorlevel 1 (
        python -c "import sys; print(sys.executable)" >nul 2>nul
        if not errorlevel 1 (
            set "PY_CMD=python"
        )
    )
)

rem Fallback to python3 in PATH.
if not defined PY_CMD (
    where python3 >nul 2>nul
    if not errorlevel 1 (
        python3 -c "import sys; print(sys.executable)" >nul 2>nul
        if not errorlevel 1 (
            set "PY_CMD=python3"
        )
    )
)

if not defined PY_CMD (
    echo [ERROR] 找不到可用的 Python 3。
    echo.
    echo 建議安裝 Windows 版 Python，並勾選 Add python.exe to PATH。
    echo 下載位置： https://www.python.org/downloads/windows/
    echo.
    goto END
)

echo [PY  ] !PY_CMD!
echo.

rem Write a small log so even if the window closes unexpectedly, there is evidence.
echo [%DATE% %TIME%] Launch with !PY_CMD! > "%~dp0ctf-last-run.log"

echo [RUN ] !PY_CMD! "%~dp0ctf.py" %*
echo.
call !PY_CMD! "%~dp0ctf.py" %*
set "EXIT_CODE=!ERRORLEVEL!"

echo.>> "%~dp0ctf-last-run.log"
echo [%DATE% %TIME%] Exit code !EXIT_CODE! >> "%~dp0ctf-last-run.log"

:END
echo.
echo ------------------------------------------------------------
echo 程式已結束。Exit code: !EXIT_CODE!
echo 如果前面有錯誤，請把畫面或 ctf-last-run.log 貼給我。
echo ------------------------------------------------------------
echo.
pause
exit /b !EXIT_CODE!
