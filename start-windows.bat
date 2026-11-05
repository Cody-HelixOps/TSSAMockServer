@echo off
title Mock TSSA
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js 18 or later is required, and it is not installed.
  echo.
  echo Install it from https://nodejs.org or run:  winget install OpenJS.NodeJS.LTS
  echo Then double-click this file again.
  echo.
  pause
  exit /b 1
)
node start.js %*
pause
