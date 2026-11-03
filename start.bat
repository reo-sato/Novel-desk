@echo off
chcp 65001 > nul
cd /d "%~dp0"
where node > nul 2>&1
if errorlevel 1 (
  echo Node.js not found. Please install Node.js 18 or later: https://nodejs.org/
  pause
  exit /b
)
:start
node server.js
rem 75 = updated, restart automatically
if "%errorlevel%"=="75" goto start
pause
