@echo off
setlocal
cd /d "%~dp0"
set "ELECTRON=%~dp0node_modules\electron\dist\electron.exe"
set "PYTHON_RUNTIME="

if exist "%~dp0.bundled-runtime\python\python.exe" set "PYTHON_RUNTIME=%~dp0.bundled-runtime\python\python.exe"
if not defined PYTHON_RUNTIME for %%P in (py.exe python.exe) do if not defined PYTHON_RUNTIME (
    where %%P >nul 2>&1
    if not errorlevel 1 set "PYTHON_RUNTIME=%%P"
)

if not defined PYTHON_RUNTIME (
    echo Python was not found. Install Python 3.12 or provide .bundled-runtime\python\python.exe.
    pause
    exit /b 1
)

echo Checking Python dependencies...
"%PYTHON_RUNTIME%" -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo Flask is missing. Installing dependencies from requirements.txt...
    "%PYTHON_RUNTIME%" -m pip install --disable-pip-version-check --no-input -r "%~dp0requirements.txt"
    if errorlevel 1 (
        echo Dependency installation failed. Check Python/pip and network access, then rerun Launch.bat.
        pause
        exit /b 1
    )
)
set "CAMERA_DISCOVERY_PYTHON=%PYTHON_RUNTIME%"

if not exist "%ELECTRON%" (
    echo Electron not found. Running npm install first...
    set "PATH=C:\Program Files\nodejs;%PATH%"
    call npm.cmd install --ignore-scripts
    if errorlevel 1 (
        echo npm install failed. Check Node.js/npm, then rerun Launch.bat.
        pause
        exit /b 1
    )
)

echo Starting Camera Discovery Octopus...
start "" "%ELECTRON%" .
endlocal
