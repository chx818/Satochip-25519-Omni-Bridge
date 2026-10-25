@echo off
chcp 65001 >nul
echo [*] 正在断开 Virtual Ledger USB 设备...
usbip detach -p 0 >nul 2>nul
taskkill /fi "WINDOWTITLE eq Virtual Ledger Daemon*" /f >nul 2>nul
echo [√] 已停止并卸载虚拟 Ledger 设备。
pause
