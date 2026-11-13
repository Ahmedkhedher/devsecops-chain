@echo off
setlocal
cd /d "%~dp0"

rem Fallback launcher when .pyw files are not associated with Python.
rem Starts the localhost web UI in the background and opens the browser.

where pyw >nul 2>nul
if not errorlevel 1 (
    start "" pyw "%~dp0launch_web.pyw"
    exit /b 0
)

where pythonw >nul 2>nul
if not errorlevel 1 (
    start "" pythonw "%~dp0launch_web.pyw"
    exit /b 0
)

echo Python 3 was not found on PATH.
echo Install it from https://www.python.org/downloads/windows/
pause
exit /b 1
