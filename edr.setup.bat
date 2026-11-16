@echo off
rem SA2 Sentinel EDR agent + console. Usage: edr.setup.bat [port]   (default 8001)
rem Connect it to the dashboard in the browser: Settings -> Dashboard URL + API key -> Test connection -> Save.
rem Detection only: files are hashed/uploaded, never executed; nothing is killed or blocked.
title SA2 Sentinel EDR
cd /d "%~dp0"
call scripts\ensure_venv.bat || goto fail

net session >nul 2>&1 || (
  echo [setup] Not running as Administrator: some processes and connections will be hidden.
  echo         For full visibility: right-click edr.setup.bat -^> Run as administrator.
)

set "PORT=8001"
if not "%~1"=="" set "PORT=%~1"
netstat -ano | findstr /r /c:"127.0.0.1:%PORT% .*LISTENING" /c:"0.0.0.0:%PORT% .*LISTENING" >nul && (
  echo [setup] Port %PORT% is already in use. Close the other program or run: edr.setup.bat 8011
  goto fail
)

if not "%SA2_NO_BROWSER%"=="1" start "" /b cmd /c "ping -n 5 127.0.0.1 >nul & start "" http://127.0.0.1:%PORT%/settings"

".venv\Scripts\python.exe" -m src.edr.app --port %PORT%
if errorlevel 1 goto fail
exit /b 0

:fail
echo.
echo [setup] SA2 Sentinel did not start. See the messages above.
if not "%SA2_NO_PAUSE%"=="1" pause
exit /b 1
