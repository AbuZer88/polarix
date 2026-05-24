@echo off
title Polarix — Local Dev Server
cd /d "%~dp0"

REM Load env vars from .env file (one KEY=VALUE per line, no spaces around =)
for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
    if not "%%A"=="" if not "%%A:~0,1%"=="#" set "%%A=%%B"
)

echo.
echo  =========================================
echo   Polarix — Local Development Server
echo  =========================================
echo   Dashboard : http://localhost:8080/dashboard
echo   Admin     : http://localhost:8080/dashboard/admin.html
echo   API docs  : http://localhost:8080/docs
echo   Health    : http://localhost:8080/health
echo  =========================================
echo.

python -m uvicorn backend.main:app --host 0.0.0.0 --port 8080 --reload
pause
