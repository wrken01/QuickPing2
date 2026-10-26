@echo off
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 server.py
    goto end
)
where python >nul 2>nul
if %errorlevel%==0 (
    python server.py
    goto end
)
echo Python not found. Install Python 3 from python.org first.
:end
pause
