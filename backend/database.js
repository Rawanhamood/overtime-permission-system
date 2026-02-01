const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

// مسار قاعدة البيانات الموحد
const dbPath = path.join(__dirname, 'database', 'overtime.db');

// التأكد من وجود مجلد قاعدة البيانات
const dbDir = path.dirname(dbPath);
if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
}

// إنشاء اتصال بقاعدة البيانات
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('❌ خطأ في الاتصال بقاعدة البيانات:', err.message);
        console.error('📁 المسار:', dbPath);
        process.exit(1);
    }
    console.log('✅ تم الاتصال بقاعدة البيانات:', dbPath);
    db.run('PRAGMA foreign_keys = ON');
});

// دالة query للاستعلامات التي ترجع بيانات
function query(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) {
                console.error('❌ خطأ في الاستعلام:', err.message);
                console.error('📝 SQL:', sql);
                console.error('📋 المعاملات:', params);
                reject(err);
            } else {
                resolve(rows || []);
            }
        });
    });
}

// دالة run للاستعلامات التي تعدل البيانات
function run(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function(err) {
            if (err) {
                console.error('❌ خطأ في التنفيذ:', err.message);
                console.error('📝 SQL:', sql);
                console.error('📋 المعاملات:', params);
                reject(err);
            } else {
                resolve({
                    lastID: this.lastID,
                    changes: this.changes
                });
            }
        });
    });
}

// دالة get للاستعلامات التي ترجع صف واحد
function get(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) {
                console.error('❌ خطأ في الاستعلام:', err.message);
                console.error('📝 SQL:', sql);
                console.error('📋 المعاملات:', params);
                reject(err);
            } else {
                resolve(row || null);
            }
        });
    });
}

// تصدير الدوال وكائن قاعدة البيانات
module.exports = {
    db,
    query,
    run,
    get
};

