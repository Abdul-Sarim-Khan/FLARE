@echo off
:: FLARE - Client Uninstall Launcher
:: Bypasses PowerShell execution policy and runs the client uninstaller.
:: Double-click this file or run it from any command prompt.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall_client.ps1"
pause
