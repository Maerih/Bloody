@echo off
REM Wazuh active-response wrapper for bloody-isolate.ps1 (place both in active-response\bin).
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0bloody-isolate.ps1" %*
