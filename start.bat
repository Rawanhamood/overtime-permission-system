@echo off
chcp 65001 >nul
echo.
echo ========================================
echo     نظام تصاريح العمل بعد الدوام
echo ========================================
echo.

:: تنظيف المنافذ أولاً
echo تنظيف المنافذ القديمة...
call clean-ports.bat

echo.
echo فحص الحزم المطلوبة...
call npm install

echo.
echo تهيئة قاعدة البيانات...
node database\init.js

echo.
echo ========================================
echo     تشغيل الخادم
echo ========================================
echo.
node backend\server.js

pause