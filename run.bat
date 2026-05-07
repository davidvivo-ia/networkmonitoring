@echo off
REM Lanzador de conveniencia para ipmonitor en Windows.
REM Delega en run.ps1, que se auto-eleva via UAC.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" %*
