const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// مسار قاعدة البيانات - يشير إلى مجلد backend/database
const dbPath = path.join(__dirname, '../backend/database/overtime.db');
console.log('📂 جاري الاتصال بقاعدة البيانات:', dbPath);

// إنشاء اتصال بقاعدة البيانات
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('❌ فشل الاتصال بقاعدة البيانات:', err.message);
        process.exit(1);
    }
    console.log('✅ تم الاتصال بقاعدة البيانات بنجاح');
    
    // تفعيل المفاتيح الخارجية
    db.run('PRAGMA foreign_keys = ON', (err) => {
        if (err) {
            console.error('❌ فشل تفعيل المفاتيح الخارجية:', err.message);
        } else {
            console.log('✅ تم تفعيل المفاتيح الخارجية');
        }
    });
});

module.exports = db;