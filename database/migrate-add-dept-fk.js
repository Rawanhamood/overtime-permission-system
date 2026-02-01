const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const dbFile = path.join(__dirname, '../backend/database/overtime.db');
const backupFileDir = path.join(__dirname, '../backend/database');
const backupFile = path.join(backupFileDir, `overtime.db.bak_${Date.now()}`);

if (!fs.existsSync(dbFile)) {
    console.error('❌ ملف قاعدة البيانات غير موجود:', dbFile);
    process.exit(1);
}

console.log('🔁 عمل نسخة احتياطية من قاعدة البيانات إلى:', backupFile);
fs.copyFileSync(dbFile, backupFile);

const db = new sqlite3.Database(dbFile, (err) => {
    if (err) {
        console.error('❌ خطأ في فتح قاعدة البيانات:', err.message);
        process.exit(1);
    }
});

function run(sql, params=[]) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function(err) {
            if (err) reject(err);
            else resolve(this);
        });
    });
}

function all(sql, params=[]) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

(async () => {
    try {
        console.log('🔐 تعطيل التحقق من المفاتيح الأجنبية مؤقتاً');
        await run("PRAGMA foreign_keys = OFF");

        console.log('BEGIN TRANSACTION');
        await run('BEGIN TRANSACTION');

        // 1) إنشاء جداول جديدة مع قيود FK
        console.log('🧱 إنشاء الجداول الجديدة (إذا لم تكن موجودة)');

        await run(`
            CREATE TABLE IF NOT EXISTS departments_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(100) NOT NULL,
                type VARCHAR(50) NOT NULL,
                manager_id INTEGER,
                parent_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (manager_id) REFERENCES employees(employee_id),
                FOREIGN KEY (parent_id) REFERENCES departments(id)
            )
        `);

        await run(`
            CREATE TABLE IF NOT EXISTS employees_new (
                employee_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                full_name VARCHAR(100) NOT NULL,
                job_number VARCHAR(20) UNIQUE NOT NULL,
                directorate VARCHAR(100) NOT NULL,
                department_id INTEGER,
                position VARCHAR(100),
                email VARCHAR(100),
                phone VARCHAR(15),
                manager_id INTEGER,
                user_type VARCHAR(20) DEFAULT 'employee',
                is_active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (department_id) REFERENCES departments(id),
                FOREIGN KEY (manager_id) REFERENCES employees(employee_id)
            )
        `);

        await run(`
            CREATE TABLE IF NOT EXISTS permits_new (
                permit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_id INTEGER NOT NULL,
                request_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reason TEXT NOT NULL,
                start_date DATE NOT NULL,
                end_date DATE NOT NULL,
                expected_exit_time TIME NOT NULL,
                status VARCHAR(20) DEFAULT 'pending_manager',
                manager_decision VARCHAR(10),
                manager_decision_date TIMESTAMP,
                manager_notes TEXT,
                security_decision VARCHAR(10),
                security_decision_date TIMESTAMP,
                security_notes TEXT,
                actual_exit_time TIME,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
            )
        `);

        await run(`
            CREATE TABLE IF NOT EXISTS notifications_new (
                notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title VARCHAR(200) NOT NULL,
                message TEXT NOT NULL,
                notification_type VARCHAR(20) NOT NULL,
                related_permit_id INTEGER,
                is_read BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES employees(employee_id),
                FOREIGN KEY (related_permit_id) REFERENCES permits(permit_id)
            )
        `);

        // 2) نسخ البيانات من الجداول القديمة إلى الجديدة (إن وجدت)
        console.log('📦 نسخ بيانات الأقسام (departments)');
        await run(`INSERT OR IGNORE INTO departments_new (id, name, type, manager_id, parent_id, created_at) SELECT id, name, type, manager_id, parent_id, created_at FROM departments`);

        console.log('📦 نسخ بيانات الموظفين (employees)');
        await run(`INSERT OR IGNORE INTO employees_new (employee_id, username, password_hash, full_name, job_number, directorate, department_id, position, email, phone, manager_id, user_type, is_active, created_at) SELECT employee_id, username, password_hash, full_name, job_number, directorate, department_id, position, email, phone, manager_id, user_type, is_active, created_at FROM employees`);

        console.log('📦 نسخ بيانات التصاريح (permits)');
        await run(`INSERT OR IGNORE INTO permits_new (permit_id, employee_id, request_date, reason, start_date, end_date, expected_exit_time, status, manager_decision, manager_decision_date, manager_notes, security_decision, security_decision_date, security_notes, actual_exit_time, created_at) SELECT permit_id, employee_id, request_date, reason, start_date, end_date, expected_exit_time, status, manager_decision, manager_decision_date, manager_notes, security_decision, security_decision_date, security_notes, actual_exit_time, created_at FROM permits`);

        console.log('📦 نسخ بيانات الإشعارات (notifications)');
        await run(`INSERT OR IGNORE INTO notifications_new (notification_id, user_id, title, message, notification_type, related_permit_id, is_read, created_at) SELECT notification_id, user_id, title, message, notification_type, related_permit_id, is_read, created_at FROM notifications`);

        // 3) حذف الجداول القديمة وإعادة التسمية
        console.log('⚠️ حذف الجداول القديمة وإعادة التسمية - سيتم استبدال الجداول إذا كل شيء صحيح');

        await run('DROP TABLE IF EXISTS notifications');
        await run('ALTER TABLE notifications_new RENAME TO notifications');

        await run('DROP TABLE IF EXISTS permits');
        await run('ALTER TABLE permits_new RENAME TO permits');

        await run('DROP TABLE IF EXISTS employees');
        await run('ALTER TABLE employees_new RENAME TO employees');

        await run('DROP TABLE IF EXISTS departments');
        await run('ALTER TABLE departments_new RENAME TO departments');

        console.log('COMMIT');
        await run('COMMIT');

        console.log('🔐 إعادة تفعيل التحقق من المفاتيح الأجنبية');
        await run('PRAGMA foreign_keys = ON');

        console.log('✅ انتهى الترحيل بنجاح. نسخة احتياطية محفوظة في:', backupFile);
        db.close();
    } catch (err) {
        console.error('❌ حدث خطأ أثناء الترحيل:', err);
        try { await run('ROLLBACK'); } catch (e) {}
        db.close();
        process.exit(1);
    }
})();
