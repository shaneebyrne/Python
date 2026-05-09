@echo off
:: ═══════════════════════════════════════════════════════
::  BeanFeasa — Windows Launcher
::  Log Analysis & Threat Detection Toolkit
:: ═══════════════════════════════════════════════════════
setlocal enabledelayedexpansion

title BeanFeasa Launcher
color 0B

echo.
echo   =============================================
echo     BeanFeasa - Log Analysis Toolkit
echo   =============================================
echo.

:: ── Locate Python ──
set "PYTHON="
where python >nul 2>&1 && set "PYTHON=python"
if not defined PYTHON (
    where python3 >nul 2>&1 && set "PYTHON=python3"
)
if not defined PYTHON (
    where py >nul 2>&1 && set "PYTHON=py"
)

if not defined PYTHON (
    echo   [ERROR] Python not found in PATH.
    echo   Install Python 3.10+ from https://python.org
    echo.
    pause
    exit /b 1
)

:: ── Verify version ──
for /f "tokens=2 delims= " %%v in ('%PYTHON% --version 2^>^&1') do set "PY_VER=%%v"
echo   [*] Python found: %PY_VER%

:: ── Set working directory to script location ──
cd /d "%~dp0"
echo   [*] Working directory: %CD%

:: ── Check / install dependencies ──
echo   [*] Checking dependencies...
%PYTHON% -c "import yaml" >nul 2>&1
if errorlevel 1 (
    echo   [*] Installing pyyaml...
    %PYTHON% -m pip install pyyaml --quiet
)

%PYTHON% -c "import Evtx" >nul 2>&1
if errorlevel 1 (
    echo   [*] Installing python-evtx...
    %PYTHON% -m pip install python-evtx --quiet
)

%PYTHON% -c "from minidump.minidumpfile import MinidumpFile" >nul 2>&1
if errorlevel 1 (
    echo   [*] Installing minidump...
    %PYTHON% -m pip install minidump --quiet
)

echo   [*] Dependencies OK.
echo.

:: ── Launch ──
echo   [*] Starting BeanFeasa GUI...
echo   =============================================
echo.
%PYTHON% main.py %*

if errorlevel 1 (
    echo.
    echo   [ERROR] BeanFeasa exited with an error.
    echo.
    pause
)

endlocal
