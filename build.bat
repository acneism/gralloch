@echo off
setlocal enableextensions
title Gralloch build

rem One-click build. build-windows.ps1 puts the Rust + MinGW toolchain on PATH
rem (it looks on PATH, then MINGW_DIR, then %USERPROFILE%\mingw\mingw64\bin, then
rem C:\msys64) and builds the native MCP server. Pass -Yara to also compile YARA.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0gralloch-plugin\gralloch-mcp\build-windows.ps1" %*
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
  echo.
  echo [gralloch] build FAILED ^(exit %RC%^). If it is a missing MinGW linker, install
  echo            MinGW-w64 ^(WinLibs: https://winlibs.com^) and set MINGW_DIR to its root.
  pause
  exit /b %RC%
)
echo.
echo [gralloch] build OK -^> gralloch-plugin\bin\gralloch-mcp.exe
echo [gralloch] next: install the plugin ^(see README: Claude Code / Codex^).
pause
exit /b 0
