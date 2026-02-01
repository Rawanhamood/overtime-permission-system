@echo off
chcp 65001 >nul
echo.
echo ========================================
echo     إيقاف العملية على المنفذ 5050
echo ========================================
echo.

echo البحث عن العملية التي تستخدم المنفذ 5050...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :5050 ^| findstr LISTENING 2^>nul') do (
    echo تم العثور على العملية PID %%a
    echo إيقاف العملية...
    taskkill /PID %%a /F
    echo تم إيقاف العملية بنجاح!
)

echo.
echo إيقاف جميع عمليات Node.js...
taskkill /IM node.exe /F >nul 2>&1
taskkill /IM nodemon.exe /F >nul 2>&1

echo.
echo ========================================
echo     تم التنظيف بنجاح!
echo ========================================
echo.
timeout /t 2 >nul

