@echo off
REM ===========================================================================
REM  CyberGuard 演示启动脚本
REM  DEMO_MODE=1 会启用前端「暴力破解演示控制台」所需的 POST 接口
REM  （仅允许来自本机的请求）。正式部署请用 start.bat（DEMO_MODE=0）。
REM ===========================================================================
chcp 65001 >nul
cd /d "%~dp0"

echo ============================================================
echo   CyberGuard DDoS 防护监控平台 — 演示模式启动
echo ============================================================
echo.

if exist ".venv\Scripts\python.exe" (
    set "PY=.venv\Scripts\python.exe"
) else (
    set "PY=python"
)

set PYTHONIOENCODING=utf-8
set DEMO_MODE=1

echo   解释器 : %PY%
echo   演示模式: DEMO_MODE=1
echo   访问地址: http://127.0.0.1:5000
echo.
echo   按 Ctrl+C 停止服务
echo ============================================================
echo.

"%PY%" app.py
pause