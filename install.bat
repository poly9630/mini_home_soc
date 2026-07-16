@echo off
setlocal EnableDelayedExpansion

echo.
echo  ============================================
echo    Mini Home SOC v2.0 - Windows Installer
echo  ============================================
echo.

:: Require admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo  [!] Administrator privileges required.
    echo      Right-click install.bat and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

set INSTALL_DIR=%~dp0
echo  Install directory: %INSTALL_DIR%
echo.

:: ------ Step 1: Python ------
echo  [1/4] Checking Python...
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo        Python not found. Attempting install via winget...
    winget install Python.Python.3.12 -e --silent --accept-source-agreements --accept-package-agreements
    if !errorLevel! neq 0 (
        echo.
        echo  [FAIL] Automatic install failed.
        echo         Download Python from: https://www.python.org/downloads/
        echo         Tick "Add Python to PATH" during install, then re-run this script.
        pause
        exit /b 1
    )
    echo        Python installed. Please close and re-run this installer.
    pause
    exit /b 0
)
for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo        Found: %%v

:: ------ Step 2: Npcap ------
echo.
echo  [2/4] Checking Npcap (packet capture driver)...
sc query npcap >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo  [!] Npcap is NOT installed.
    echo.
    echo      Npcap is required for Scapy to capture packets on Windows.
    echo      Download from:  https://npcap.com/#download
    echo.
    echo      During installation, check:
    echo        [x] Install Npcap in WinPcap API-compatible mode
    echo.
    echo      After installing Npcap, re-run this installer.
    echo.
    pause
    exit /b 1
)
echo        Npcap found.

:: ------ Step 3: Python deps ------
echo.
echo  [3/4] Installing Python dependencies...
python -m pip install --upgrade pip --quiet
python -m pip install -r "%INSTALL_DIR%requirements.txt" --quiet
if %errorLevel% neq 0 (
    echo.
    echo  [FAIL] Dependency installation failed.
    echo         Check your internet connection and try:
    echo           pip install -r requirements.txt
    pause
    exit /b 1
)
echo        Dependencies installed (Flask, Scapy, requests).

:: ------ Step 4: Shortcuts ------
echo.
echo  [4/4] Creating shortcuts...

:: Write launch.bat
(
    echo @echo off
    echo net session ^>nul 2^>^&1
    echo if %%errorLevel%% neq 0 ^(
    echo     powershell -Command "Start-Process '%%~f0' -Verb RunAs"
    echo     exit /b
    echo ^)
    echo cd /d "%%~dp0"
    echo echo  Starting Mini Home SOC...
    echo echo  Dashboard -^> http://127.0.0.1:5000
    echo timeout /t 2 /nobreak ^>nul
    echo start "" "http://127.0.0.1:5000"
    echo python mini_home_soc.py
    echo pause
) > "%INSTALL_DIR%launch.bat"
echo        Created launch.bat

:: Desktop shortcut via PowerShell
set SHORTCUT=%USERPROFILE%\Desktop\Mini Home SOC.lnk
powershell -NoProfile -Command "$ws=New-Object -ComObject WScript.Shell; $s=$ws.CreateShortcut('%SHORTCUT%'); $s.TargetPath='%INSTALL_DIR%launch.bat'; $s.WorkingDirectory='%INSTALL_DIR%'; $s.Description='Mini Home SOC Dashboard'; $s.IconLocation='shell32.dll,14'; $s.Save()"
echo        Desktop shortcut created: "Mini Home SOC"

echo.
echo  ============================================
echo    Installation complete!
echo.
echo    Launch:    Double-click "Mini Home SOC" on Desktop
echo               or run launch.bat
echo.
echo    Dashboard: http://127.0.0.1:5000
echo  ============================================
echo.
pause
