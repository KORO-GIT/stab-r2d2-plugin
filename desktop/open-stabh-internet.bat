@echo off
setlocal
cd /d "%~dp0"
python.exe stabh-internet-bridge.py
if errorlevel 1 pause
