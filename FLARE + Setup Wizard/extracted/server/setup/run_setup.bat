@echo off
:: FLARE - Server Setup Launcher
:: Bypasses PowerShell execution policy and runs the full server setup sequence.
:: Double-click this file or run it from any command prompt.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp00_run_all_setup.ps1"
pause
