@echo off
:: FLARE v0.6 - Start Server
:: Port is read from the FLARE_PORT environment variable (set by setup\2_configure.ps1).
:: Default if not configured: 7331
cd /d "%~dp0"

if "%FLARE_PORT%"=="" set FLARE_PORT=7331

echo.
echo   FLARE v0.6 Server
echo   Port: %FLARE_PORT%
echo   You will be prompted to pick the network interface to advertise.
echo   The dashboard will open in your browser automatically.
echo   Press Ctrl+C in this window to stop the server.
echo.

:: Open the dashboard in the default browser after a short delay (non-blocking).
:: The delay gives the server time to finish startup before the browser hits it.
start /b powershell -NoProfile -Command "Start-Sleep 6; Start-Process 'https://localhost:%FLARE_PORT%'"

:: Start the server in the foreground so Ctrl+C stops it cleanly.
:: NOTE: --host is intentionally omitted so the server prompts for an interface.
::       Pass --host 0.0.0.0 explicitly to skip the prompt (e.g. for headless).
python -X utf8 flare_server.py
pause
