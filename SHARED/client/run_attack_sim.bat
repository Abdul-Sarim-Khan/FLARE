@echo off
:: FLARE v0.4 - Attack Simulation Launcher
:: Bypasses PowerShell execution policy and runs the full attack simulation.
:: Double-click this file, or run it from any command prompt.
:: Make sure flare_agent.py (or the FLAREAgent service) is running first.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0simulate_attacks.ps1"
pause
