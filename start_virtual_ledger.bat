@echo off
setlocal EnableExtensions
chcp 65001 >nul
title Satochip-25519 Ledger bridge

echo ================================================================
echo   Satochip-25519-J3R452 - Ledger USB/IP bridge
echo   Local-only experimental bridge; blind signing is disabled by default
echo ================================================================
echo.

set "PYTHON_EXE=C:\Users\chx81\Documents\antigravity\quirky-nobel\FIDO2Applet-JCOP-Ed25519\simulator-support\venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" set "PYTHON_EXE=python"

where usbip >nul 2>nul
if errorlevel 1 (
    echo [!] usbip was not found. Install usbip-win2 or attach the device manually.
    echo     winget install -e --id vadimgrn.usbip-win2
    echo.
)

echo [*] Starting the daemon in a separate window.
echo     The daemon prompts for the PIN privately; the PIN is not passed on a command line.
start "Virtual Ledger Daemon" "%PYTHON_EXE%" "%~dp0virtual_ledger_usbip_daemon.py"

rem The daemon initializes PC/SC and the SecureChannel before it binds TCP.
rem Poll the local port instead of racing it with a fixed two-second sleep.
set "READY=0"
for /l %%I in (1,1,60) do call :wait_for_daemon %%I
if "%READY%"=="0" (
    echo [!] The daemon did not become ready within 60 seconds.
    echo     Check the daemon window for PIN, reader, or SecureChannel errors.
    exit /b 1
)

where usbip >nul 2>nul
if errorlevel 1 goto :done

echo [*] Attaching the virtual Ledger device through USB/IP...
usbip attach -r 127.0.0.1 -b 1-1
if errorlevel 1 (
    echo [!] USB/IP attach failed. Run this script from an Administrator shell,
    echo     or attach 127.0.0.1 busid 1-1 manually after checking usbip-win2.
) else (
    echo [OK] USB/IP attachment succeeded.
    echo      The device should appear as Ledger Nano S in Device Manager.
)

:done
echo.
echo Press any key to close this launcher window. The daemon remains separate.
pause >nul
exit /b 0

:wait_for_daemon
if "%READY%"=="1" exit /b 0
powershell.exe -NoProfile -NonInteractive -Command "$c=New-Object Net.Sockets.TcpClient; try {$c.Connect('127.0.0.1',3240); exit 0} catch {exit 1} finally {$c.Dispose()}" >nul 2>&1
if not errorlevel 1 (
    set "READY=1"
    exit /b 0
)
timeout /t 1 /nobreak >nul
exit /b 0
