@echo off
setlocal
cd /d "%~dp0"

rem Fallback launcher for systems where .pyw files are not associated with
rem Python. Prefers the windowless launcher so no console window stays open.

where pyw >nul 2>nul
if not errorlevel 1 (
    start "" pyw "%~dp0launch.pyw"
    exit /b 0
)

where pythonw >nul 2>nul
if not errorlevel 1 (
    start "" pythonw "%~dp0launch.pyw"
    exit /b 0
)

echo Python 3 was not found on PATH.
echo Install it from https://www.python.org/downloads/windows/
pause
exit /b 1
