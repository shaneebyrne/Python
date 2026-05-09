@echo off
setlocal
title Lugh v3.0
echo ====================================================
echo   Lugh - Cybersecurity Toolkit  v3.0
echo   Email / IDN / Files / Hashes / Logs / Links / Adv
echo ====================================================
echo.
cd /d "%~dp0"

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found in PATH.
    echo Install from https://python.org
    pause & exit /b 1
)

if not exist "%~dp0main.py" (
    echo [ERROR] main.py not found in: %~dp0
    pause & exit /b 1
)
if not exist "%~dp0engines\__init__.py" (
    echo [ERROR] engines\ folder missing. Check folder structure.
    pause & exit /b 1
)
if not exist "%~dp0gui\__init__.py" (
    echo [ERROR] gui\ folder missing. Check folder structure.
    pause & exit /b 1
)

echo   Path: %cd%
echo.

python -c "import customtkinter" >nul 2>&1
if %errorlevel% neq 0 (
    echo   Installing customtkinter...
    pip install customtkinter --quiet
)
python -c "import yara" >nul 2>&1
if %errorlevel% neq 0 echo   [INFO] yara-python not installed (pip install yara-python)
python -c "import Evtx.Evtx" >nul 2>&1
if %errorlevel% neq 0 echo   [INFO] python-evtx not installed (auto-installs on first .evtx load)

echo.
echo Launching Lugh...
python "%~dp0main.py"
if %errorlevel% neq 0 ( echo. & echo [ERROR] Lugh exited with an error. & pause )
endlocal
