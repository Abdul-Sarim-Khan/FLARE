@echo off
:: FLARE v0.4 - Server Uninstall Launcher
:: Bypasses PowerShell execution policy and runs the server uninstaller.
:: Double-click this file or run it from any command prompt.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall_server.ps1"
pause
