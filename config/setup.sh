#!/bin/bash
echo "🚀 بدء إعداد نظام تصاريح العمل..."

# 1. تثبيت dependencies
echo "📦 تثبيت الحزم المطلوبة..."
npm install

# 2. إنشاء قاعدة البيانات والبيانات الأولية
echo "🗄️ إنشاء قاعدة البيانات..."
node database/init.js

# 3. تشغيل الخادم
echo "🌐 تشغيل الخادم..."
echo "✅ النظام جاهز على: http://localhost:3000"
npm run dev