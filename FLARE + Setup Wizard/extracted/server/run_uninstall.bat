@echo off
:: FLARE - Server Uninstall Launcher
:: Bypasses PowerShell execution policy and runs the server uninstaller.
:: The script self-elevates to Administrator if needed.
:: Double-click this file or run it from any command prompt.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall_server.ps1"
pause
