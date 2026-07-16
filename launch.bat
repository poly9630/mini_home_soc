@echo off
:: Scapy needs raw socket access on Windows - requires admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
echo  Starting Mini Home SOC...
echo  Dashboard -^> http://127.0.0.1:5000
timeout /t 2 /nobreak >nul
start "" "http://127.0.0.1:5000"
python mini_home_soc.py
pause
