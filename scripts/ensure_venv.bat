@echo off
rem Shared by dashboard.setup.bat and edr.setup.bat: create .venv (Python 3.11-3.13) and install requirements.txt.
cd /d "%~dp0.."
if exist ".venv\Scripts\python.exe" goto install

set "PY="
for %%V in (3.11 3.12 3.13) do (
  if not defined PY py -%%V -c "import sys" >nul 2>&1 && set "PY=py -%%V"
)
if not defined PY python -c "import sys; sys.exit(not ((3, 11) <= sys.version_info[:2] <= (3, 13)))" >nul 2>&1 && set "PY=python"
if not defined PY (
  echo [setup] Python 3.11, 3.12 or 3.13 was not found. Install it from https://www.python.org/downloads/ and re-run.
  exit /b 1
)
echo [setup] Creating .venv with %PY% ...
%PY% -m venv .venv || exit /b 1

:install
echo [setup] Checking Python packages (requirements.txt) ...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements.txt || exit /b 1
exit /b 0
