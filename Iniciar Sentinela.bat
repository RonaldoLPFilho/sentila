@echo off
cd /d "%~dp0"
where pythonw >nul 2>&1 && (start "" pythonw -m sentinela %*) || (start "" pyw -m sentinela %*)
