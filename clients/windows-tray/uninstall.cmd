@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" -Uninstall %*
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
    echo.
    echo Uninstall failed with exit code %RC%.
    pause
)
exit /b %RC%
