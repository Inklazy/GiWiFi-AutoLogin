@echo off
chcp 936 >nul
title GiWiFi 开机自动认证配置向导

echo ========================================================
echo          GiWiFi 校园网开机静默自动认证一键配置
echo ========================================================
echo.

set SCRIPT_DIR=%~dp0
set VBS_RUN=%SCRIPT_DIR%run_silent.vbs

if not exist "%VBS_RUN%" (
    echo [错误] 未找到启动脚本: %VBS_RUN%
    pause
    exit /b 1
)

echo 正在注册 Windows 开机任务计划 (无黑框静默运行)...
schtasks /create /tn "GiWiFi_AutoLogin" /tr "wscript.exe "%VBS_RUN%"" /sc onlogon /rl highest /f

if %errorlevel% equ 0 (
    echo.
    echo ========================================================
    echo [成功] 已成功创建开机自动登录任务！
    echo 任务名称: GiWiFi_AutoLogin
    echo 执行方式: 开机或用户登录时静默后台运行 (无任何CMD黑框)
    echo 日志文件: %SCRIPT_DIR%giwifi_login.log
    echo ========================================================
) else (
    echo.
    echo [提示] 任务创建失败，请右键点击本文件，选择【以管理员身份运行】后重试！
)

echo.
pause
