@echo off
chcp 936 >nul
title 卸载 GiWiFi 开机任务

echo 正在删除 GiWiFi 任务计划...
schtasks /delete /tn "GiWiFi_AutoLogin" /f
if %errorlevel% equ 0 (
    echo.
    echo [成功] 已成功移除 GiWiFi 开机任务计划！
) else (
    echo.
    echo [提示] 移除失败或任务尚未创建。
)
echo.
pause
