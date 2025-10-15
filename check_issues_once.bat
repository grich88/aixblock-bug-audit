@echo off
echo Checking AIxBlock Issues for new comments...
powershell -ExecutionPolicy Bypass -File monitor_issues.ps1 -once
pause
