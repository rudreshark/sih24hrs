@echo off
title DIODESHIELD Passive Network Monitor
set PYTHON=python
if exist ".venv\Scripts\python.exe" set PYTHON=.venv\Scripts\python.exe
echo Starting receive-only live packet capture and dashboard...
start /b cmd /c "timeout /t 2 /nobreak >nul & start http://localhost:8000/dashboard/"
%PYTHON% -m uvicorn diodeshield.api.main:app --host 0.0.0.0 --port 8000
pause
