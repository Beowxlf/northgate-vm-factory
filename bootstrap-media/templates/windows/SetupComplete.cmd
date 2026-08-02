@echo off
setlocal
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%WINDIR%\Setup\Scripts\NorthGate-Bootstrap.ps1"
set "NGBM_EXIT=%ERRORLEVEL%"
if not "%NGBM_EXIT%"=="0" (
  >"%ProgramData%\NorthGate\Bootstrap\SETUPCOMPLETE_FAILED" echo bootstrap_failed=true
)
exit /b 0
