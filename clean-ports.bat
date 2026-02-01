@echo off
chcp 65001 >nul
echo.
echo ========================================
echo     تنظيف المنافذ المشغولة
echo ========================================
echo.

echo إيقاف عمليات Node.js و nodemon...
taskkill /IM node.exe /F >nul 2>&1
taskkill /IM nodemon.exe /F >nul 2>&1

echo.
echo البحث عن عمليات تستخدم منافذ التطوير...

:: تنظيف المنافذ من 3000 إلى 3010
for /L %%p in (3000,1,3010) do (
    for /f "tokens=5" %%a in ('netstat -ano ^| findstr :%%p ^| findstr LISTENING 2^>nul') do (
        echo إيقاف العملية PID %%a (المنفذ %%p)
        taskkill /PID %%a /F >nul 2>&1
    )
)

:: تنظيف المنافذ الأخرى
set other_ports=4000 5000 5050 8000 8080 9000
for %%p in (%other_ports%) do (
    for /f "tokens=5" %%a in ('netstat -ano ^| findstr :%%p ^| findstr LISTENING 2^>nul') do (
        echo إيقاف العملية PID %%a (المنفذ %%p)
        taskkill /PID %%a /F >nul 2>&1
    )
)

echo.
echo ========================================
echo     تم تنظيف المنافذ بنجاح!
echo ========================================
echo.
timeout /t 2 >nul