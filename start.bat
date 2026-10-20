@echo off
REM CyberGuard 正式模式启动（DEMO_MODE=0，不注册演示接口）
chcp 65001 >nul
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (set "PY=.venv\Scripts\python.exe") else (set "PY=python")
set PYTHONIOENCODING=utf-8
set DEMO_MODE=0
"%PY%" app.py
pause