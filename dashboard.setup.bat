@echo off
rem SA2 Scan dashboard (V8 blend: EMBER2024 + Binary Ninja). Usage: dashboard.setup.bat [port]   (default 8000)
rem Set SA2_ADMIN_PASSWORD to choose the admin password; otherwise one is generated and printed below.
rem Binary Ninja: set SA2_BN=0 to disable it. With the default SA2_BN_MODE_SWITCH=restart, each scan restarts Binary Ninja.
rem Only one process should use Binary Ninja at a time: a second dashboard or CLI scorer gets bn_busy and EMBER2024 decides.
title SA2 Scan dashboard
cd /d "%~dp0"
call scripts\ensure_venv.bat || goto fail

for %%F in (artifacts\v8\models\candidate.pkl artifacts\v8\models\R1.pkl artifacts\v8\freeze\freeze_manifest.json) do (
  if not exist "%%F" (
    echo [setup] Missing model file: %%F
    echo         These files are tracked in git. Run "git pull", or clone the repository again.
    goto fail
  )
)

rem Pretrained EMBER2024 model, 3.7 MB, Apache-2.0, hash-checked: downloaded if missing, replaced if its hash is wrong,
rem otherwise only verified. With SA2_EMBER_DOWNLOAD=0 it is only verified and never downloaded.
".venv\Scripts\python.exe" -m src.v8.deploy --download-model
if errorlevel 1 (
  echo [setup] The EMBER2024 model is not usable. The [error] line above says why: missing, wrong hash or download failed.
  echo         To install it by hand, copy EMBER2024_PE.model into artifacts\ember2024\models\artifacts\ember2024\models\ and re-run.
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
