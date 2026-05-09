@echo off
:: ============================================================
::  Dagda IDE — Windows Launcher
::  The All-Father of Polyglot IDEs
:: ============================================================

setlocal ENABLEEXTENSIONS

:: ── Locate Python ────────────────────────────────────────────
set PYTHON=
for %%P in (python python3 py) do (
    where %%P >nul 2>&1 && set PYTHON=%%P && goto :found_python
)

echo [ERROR] Python is not installed or not on PATH.
echo         Install Python 3.9+ from https://python.org
pause
exit /b 1

:found_python
echo [Dagda] Using Python: %PYTHON%
%PYTHON% --version

:: ── Check minimum Python version (3.9) ───────────────────────
%PYTHON% -c "import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)" 2>nul
if errorlevel 1 (
    echo [ERROR] Python 3.9 or newer is required.
    pause
    exit /b 1
)

:: ── Install pygments if missing (optional, graceful fallback) ─
%PYTHON% -c "import pygments" >nul 2>&1
if errorlevel 1 (
    echo [Dagda] Installing pygments for syntax highlighting...
    %PYTHON% -m pip install --quiet pygments
)

:: ── Launch Dagda ─────────────────────────────────────────────
cd /d "%~dp0"
echo [Dagda] Starting...
%PYTHON% main.py

if errorlevel 1 (
    echo.
    echo [Dagda] Exited with an error. Check the output above.
    pause
)
endlocal
