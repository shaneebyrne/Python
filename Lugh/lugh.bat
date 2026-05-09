@echo off
:: ═══════════════════════════════════════════════════════
::  Lugh - Cybersecurity Toolkit CLI
::  Drop this file in a folder on your system PATH.
::  Then call: lugh headers file.eml --all
:: ═══════════════════════════════════════════════════════
::
::  SETUP: Edit the path below to match your Lugh install location.
::

set "LUGH_HOME=C:\Users\Shane.Byrne\OneDrive - Tempo Communications Inc\Code\Python\Tools\Lugh"

:: ─────────────────────────────────────────────────────
:: Don't edit below this line
:: ─────────────────────────────────────────────────────
if not exist "%LUGH_HOME%\lugh.py" (
    echo [ERROR] lugh.py not found at: %LUGH_HOME%
    echo Edit LUGH_HOME in this batch file to point to your Lugh folder.
    exit /b 1
)

python "%LUGH_HOME%\lugh.py" %*
