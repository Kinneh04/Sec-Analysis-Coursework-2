@echo off
rem SA2 Scan dashboard (VT-style uploader + admin panel). Usage: dashboard.setup.bat [port]   (default 8000)
rem Set SA2_ADMIN_PASSWORD to choose the admin password; otherwise one is generated and printed below.
title SA2 Scan dashboard
cd /d "%~dp0"
call scripts\ensure_venv.bat || goto fail

if not exist "artifacts\v3.2\models\final_pe_v3.pkl" (
  echo [setup] Missing model: artifacts\v3.2\models\final_pe_v3.pkl
  echo         artifacts\ is not in git. Copy the artifacts\v3.2 and artifacts\deploy folders from the project machine.
  goto fail
)
if not exist "artifacts\deploy\calibration_temporal_benign.json" (
  echo [setup] Missing artifacts\deploy\calibration_temporal_benign.json ^(calibrated threshold^).
  goto fail
)

set "PORT=8000"
if not "%~1"=="" set "PORT=%~1"
netstat -ano | findstr /r /c:"127.0.0.1:%PORT% .*LISTENING" /c:"0.0.0.0:%PORT% .*LISTENING" >nul && (
  echo [setup] Port %PORT% is already in use. Close the other program or run: dashboard.setup.bat 8010
  goto fail
)

rem Open the browser a few seconds after the server starts (skip with SA2_NO_BROWSER=1).
if not "%SA2_NO_BROWSER%"=="1" start "" /b cmd /c "ping -n 5 127.0.0.1 >nul & start "" http://127.0.0.1:%PORT%/"

".venv\Scripts\python.exe" -m src.webscan.app --port %PORT%
if errorlevel 1 goto fail
exit /b 0

:fail
echo.
echo [setup] SA2 Scan did not start. See the messages above.
if not "%SA2_NO_PAUSE%"=="1" pause
exit /b 1
