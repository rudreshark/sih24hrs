@echo off
title DIODESHIELD OT - Autonomous Network Security & Threat Defense
color 0B
cls

echo ===============================================================================
echo   DIODESHIELD: Enterprise OT Threat Defense & Passive Network Sensor
echo ===============================================================================
echo.

:: Detect Python executable
set PYTHON=python
if exist ".venv\Scripts\python.exe" (
    set PYTHON=.venv\Scripts\python.exe
)

:: Get primary local LAN IPv4 address
for /f "tokens=4" %%a in ('route print ^| findstr 0.0.0.0 ^| findstr /v "0.0.0.0 "') do (
    set LOCAL_IP=%%a
)
if "%LOCAL_IP%"=="" set LOCAL_IP=127.0.0.1

echo [*] Initializing DiodeShield Core Detection Engine...
echo [*] Multi-Interface Listener: Active on 0.0.0.0 across OT & LAN Ports
echo.
echo ===============================================================================
echo   NETWORK ACCESS & DEMO INSTRUCTIONS
echo ===============================================================================
echo   [>] Local Web SOC Dashboard:
echo       http://localhost:8000/dashboard/
echo.
echo   [>] Remote Attack Target (for testing from another laptop on LAN):
echo       Target IP: %LOCAL_IP%
echo       Target Ports: 19001 (UDP Flood Trap), 1502 / 502 (Modbus ICS Trap)
echo.
echo   [>] Command to run on the SECOND laptop:
echo       python scripts/remote_attack_tool.py --target %LOCAL_IP% --attack udp_flood
echo       python scripts/remote_attack_tool.py --target %LOCAL_IP% --attack modbus_exploit
echo ===============================================================================
echo.

:: Automatically open the dashboard in default browser after 2 seconds
start /b cmd /c "timeout /t 2 /nobreak >nul & start http://localhost:8000/dashboard/"

:: Start the Uvicorn server with real-time multi-interface capture
%PYTHON% -m uvicorn diodeshield.api.main:app --host 0.0.0.0 --port 8000

pause
