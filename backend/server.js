const express = require('express');
const path = require('path');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============== ⭐⭐ middleware للتحقق من التوكن ⭐⭐ ==============
const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'غير مصرح، يرجى تسجيل الدخول أولاً'
        });
    }
    
    try {
        // فك التوكن (في نظامك الحالي، التوكن هو مجرد base64)
        const decoded = JSON.parse(Buffer.from(token, 'base64').toString());
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({
            success: false,
            message: 'توكن غير صالح'
        });
    }
};

// ============== ⭐⭐ middleware خاص للحارس (security_guard) ⭐⭐ ==============
const checkGuardPermissions = (req, res, next) => {
    if (req.user && req.user.role === 'security_guard') {
        // الحارس لا يمكنه:
        // 1. الموافقة على التصاريح
        // 2. رفض التصاريح  
        // 3. إنهاء التصاريح مبكراً
        // 4. إدارة الأقسام
        const blockedPaths = [
            '/api/permits/security-approve',
            '/api/permits/end-early',
            '/api/departments',
            '/api/auto-assign-managers',
            '/api/reassign-all-managers'
        ];
        
        if (blockedPaths.some(path => req.path.startsWith(path))) {
            return res.status(403).json({
                success: false,
                message: 'الحارس ليس لديه صلاحية لهذا الإجراء'
            });
        }
    }
    next();
};

// ============== ⭐⭐ middleware للتحقق من الصلاحية (معدّل) ⭐⭐ ==============
const authorizeRoles = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(403).json({
                success: false,
                message: 'ليس لديك صلاحية للوصول'
            });
        }
        
        const userRole = req.user.role;
        
        // السماح للحارس (security_guard) بالوصول لـ APIs محددة فقط
        if (userRole === 'security_guard') {
            // الحارس يمكنه الوصول فقط لـ APIs محددة
            const guardAllowedAPIs = ['security', 'security_guard', 'admin'];
            if (!guardAllowedAPIs.some(allowedRole => roles.includes(allowedRole))) {
                return res.status(403).json({
                    success: false,
                    message: 'ليس لديك صلاحية للوصول'
                });
            }
        } else if (!roles.includes(userRole)) {
            return res.status(403).json({
                success: false,
                message: 'ليس لديك صلاحية للوصول'
            });
        }
        next();
    };
};

const checkManagerRole = (req, res, next) => {
    const userRole = req.user?.role;
    if (userRole !== 'manager' && userRole !== 'admin') {
        return res.status(403).json({
            success: false,
            message: 'غير مصرح لك بتنفيذ هذه العملية'
        });
    }
    next();
};

const checkSecurityRole = (req, res, next) => {
    const userRole = req.user?.role;
    if (userRole !== 'security' && userRole !== 'admin') {
        return res.status(403).json({
            success: false,
            message: 'غير مصرح لك بتنفيذ هذه العملية'
        });
    }
    next();
};

// ============== اتصال بقاعدة البيانات (مُحسّن) ==============
const dbDir = path.join(__dirname, 'database');

// محاولة الملفات بالترتيب
const dbCandidates = [
    'overtime.db',      // الملف الأصلي
    'overtime_new.db',  // الملف الجديد
    'overtime_system.db' // ملف احتياطي
];

let dbPath = null;
let selectedDb = '';

// البحث عن أول ملف قاعدة بيانات صالح
for (const dbFile of dbCandidates) {
    const fullPath = path.join(dbDir, dbFile);
    try {
        if (fs.existsSync(fullPath)) {
            // تحقق من أن الملف غير فارغ (أكبر من 0 بايت)
            const stats = fs.statSync(fullPath);
            if (stats.size > 0) {
                dbPath = fullPath;
                selectedDb = dbFile;
                console.log(`✅ وجدت قاعدة بيانات: ${dbFile} (${stats.size} بايت)`);
                break;
            } else {
                console.log(`⚠️  ملف ${dbFile} موجود لكنه فارغ`);
            }
        }
    } catch (err) {
        console.log(`⚠️  خطأ في فحص ${dbFile}: ${err.message}`);
    }
}

// إذا لم نجد أي ملف، أنشئ ملفاً جديداً
if (!dbPath) {
    selectedDb = 'overtime_system.db';
    dbPath = path.join(dbDir, selectedDb);
    console.log(`🔄 لم أجد قاعدة بيانات صالحة، سأنشئ: ${selectedDb}`);
}

console.log(`🔍 استخدام قاعدة البيانات: ${selectedDb}`);
console.log(`📁 المسار الكامل: ${dbPath}`);

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('❌ خطأ في الاتصال بقاعدة البيانات:', err.message);
        console.error('💡 الأسباب المحتملة:');
        console.error('   1. الملف تالف أو محمي');
        console.error('   2. لا توجد صلاحيات للوصول');
        console.error('   3. الملف قيد الاستخدام من قبل برنامج آخر');
        
        // محاولة حل تلقائي
        console.log('\n🔄 أحاول إصلاح المشكلة تلقائياً...');
        
        // محاولة استخدام قاعدة بيانات في الذاكرة مؤقتاً
        console.log('💾 استخدام قاعدة بيانات مؤقتة في الذاكرة...');
        const memoryDb = new sqlite3.Database(':memory:', (err2) => {
            if (err2) {
                console.error('❌ فشل حتى قاعدة البيانات في الذاكرة:', err2.message);
                console.log('\n🚨 **حلول يدوية:**');
                console.log('   1. أعد تشغيل الكمبيوتر');
                console.log('   2. شغل PowerShell كمسؤول');
                console.log('   3. جرب: node database/init.js');
                console.log('   4. تأكد أن الملف غير مفتوح في برنامج آخر');
                process.exit(1);
            }
            
            console.log('✅ تم الاتصال بقاعدة بيانات مؤقتة في الذاكرة');
            console.log('⚠️  ملاحظة: البيانات لن تحفظ بعد إغلاق الخادم');
            console.log('💡 استخدم node database/init.js لإنشاء قاعدة بيانات دائمة');
            
            // استبدل db بالنسخة المؤقتة
            Object.assign(db, memoryDb);
            initializeDatabase(db);
        });
        return;
    }
    
    console.log('✅ تم الاتصال بقاعدة البيانات بنجاح');
    db.run('PRAGMA foreign_keys = ON');
    
    // التحقق من الجداول
    checkDatabaseTables(db);
});


// ============== دوال لتهيئة قاعدة البيانات ==============

function checkDatabaseTables(db) {
    const query = `
        SELECT name 
        FROM sqlite_master 
        WHERE type='table' 
        AND name NOT LIKE 'sqlite_%'
    `;
    
    db.all(query, [], (err, tables) => {
        if (err) {
            console.error('❌ خطأ في قراءة الجداول:', err.message);
            console.log('🔄 سأحاول إنشاء الجداول الأساسية...');
            initializeDatabase(db);
            return;
        }
        
        const tableNames = tables ? tables.map(t => t.name) : [];
        console.log(`📋 عدد الجداول الموجودة: ${tableNames.length}`);
        
        if (tableNames.length > 0) {
            console.log('📊 الجداول:', tableNames.join(', '));
        }
        
        // الجداول الأساسية المطلوبة
        const essentialTables = ['employees', 'permits', 'departments'];
        const missingTables = essentialTables.filter(t => !tableNames.includes(t));
        
        if (missingTables.length > 0) {
            console.log(`⚠️  الجداول المفقودة: ${missingTables.join(', ')}`);
            console.log('🔄 جاري إنشاء الجداول المفقودة...');
            initializeDatabase(db);
        } else {
            console.log('✅ جميع الجداول الأساسية موجودة');
            
            // التحقق من وجود بيانات أساسية
            db.get('SELECT COUNT(*) as count FROM employees', [], (err, result) => {
                if (err) {
                    console.error('❌ خطأ في عد الموظفين:', err.message);
                } else {
                    console.log(`👥 عدد الموظفين: ${result.count}`);
                    
                    if (result.count === 0) {
                        console.log('🔄 لا توجد بيانات، جاري إضافة المستخدمين الأساسيين...');
                        addEssentialUsers(db);
                    } else {
                        console.log('✅ قاعدة البيانات تحتوي على بيانات');
                        // تحديث جدول التصاريح إذا لزم الأمر
                        updatePermitsTable(db);
                    }
                }
            });
        }
    });
}

function initializeDatabase(db) {
    console.log('🔨 جاري إنشاء الجداول الأساسية...');
    
    const tables = [
        // جدول الأقسام أولاً (لأن الموظفين يشيرون إليه)
        `CREATE TABLE IF NOT EXISTS departments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT,
            manager_id INTEGER,
            parent_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,
        
        // جدول الموظفين
        `CREATE TABLE IF NOT EXISTS employees (
            employee_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            user_type TEXT NOT NULL,
            job_number TEXT,
            directorate TEXT,
            department_id INTEGER,
            manager_id INTEGER,
            email TEXT,
            phone TEXT,
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,
        
        // جدول التصاريح
        `CREATE TABLE IF NOT EXISTS permits (
            permit_id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            reason TEXT NOT NULL,
            start_date TEXT NOT NULL,
            end_date TEXT NOT NULL,
            expected_exit_time TEXT NOT NULL,
            manager_notes TEXT,
            manager_decision TEXT,
            manager_decision_date TEXT,
            manager_username TEXT,
            security_decision TEXT,
            security_decision_date TEXT,
            security_username TEXT,
            security_notes TEXT,
            actual_entry_time TEXT,
            actual_exit_time TEXT,
            entry_guard_username TEXT,
            exit_guard_username TEXT,
            entry_notes TEXT,
            exit_notes TEXT,
            checkin_timestamp TEXT,
            checkout_timestamp TEXT,
            status TEXT DEFAULT 'pending_manager',
            request_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,
        
        // جدول تصاريح الشركات
        `CREATE TABLE IF NOT EXISTS company_entry_permits (
            permit_id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_username TEXT NOT NULL,
            employee_name TEXT,
            company_name TEXT NOT NULL,
            company_representative TEXT NOT NULL,
            representative_id TEXT,
            representative_phone TEXT,
            vehicle_number TEXT,
            entry_purpose TEXT NOT NULL,
            expected_entry_date TEXT NOT NULL,
            expected_entry_time TEXT NOT NULL,
            expected_exit_date TEXT NOT NULL,
            expected_exit_time TEXT NOT NULL,
            number_of_visitors INTEGER DEFAULT 1,
            actual_visitors_count INTEGER,
            additional_notes TEXT,
            manager_status TEXT DEFAULT 'pending',
            manager_username TEXT,
            manager_notes TEXT,
            manager_decision_date TEXT,
            security_status TEXT DEFAULT 'pending',
            security_username TEXT,
            security_notes TEXT,
            security_decision_date TEXT,
            actual_entry_time TEXT,
            actual_exit_time TEXT,
            entry_guard_username TEXT,
            exit_guard_username TEXT,
            entry_notes TEXT,
            exit_notes TEXT,
            status TEXT DEFAULT 'pending',
            request_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (employee_username) REFERENCES employees(username)
        )`,
        
        // جدول تصاريح الشركات المرسلة للحرس
        `CREATE TABLE IF NOT EXISTS guard_company_permits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            permit_id INTEGER NOT NULL,
            security_username TEXT NOT NULL,
            security_notes TEXT,
            sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (permit_id) REFERENCES company_entry_permits(permit_id)
        )`,
        
        // ✅ جدول العمال المرتبطين بتصاريح الشركات
        `CREATE TABLE IF NOT EXISTS company_workers (
            worker_id INTEGER PRIMARY KEY AUTOINCREMENT,
            permit_id INTEGER NOT NULL,
            worker_name TEXT NOT NULL,
            worker_id_number TEXT,
            worker_profession TEXT,
            worker_phone TEXT,
            added_by TEXT,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_original BOOLEAN DEFAULT 0,
            FOREIGN KEY (permit_id) REFERENCES company_entry_permits(permit_id)
        )`,
        
     
`CREATE TABLE IF NOT EXISTS notifications (
    notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    permit_id INTEGER,
    company_permit_id INTEGER,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'info',
    is_read BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES employees(employee_id)
)`,
        
        // جدول المخالفات
        `CREATE TABLE IF NOT EXISTS time_violations (
            violation_id INTEGER PRIMARY KEY AUTOINCREMENT,
            permit_id INTEGER NOT NULL,
            employee_id INTEGER NOT NULL,
            violation_type TEXT,
            expected_time TEXT,
            actual_time TEXT,
            time_difference INTEGER,
            severity TEXT,
            reported_by TEXT,
            resolved BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`
    ];
    
    db.serialize(() => {
        // إنشاء الجداول بالتسلسل
        tables.forEach((query, index) => {
            db.run(query, (err) => {
                if (err) {
                    console.error(`❌ خطأ في إنشاء الجدول ${index + 1}:`, err.message);
                } else {
                    console.log(`✅ تم إنشاء/تأكيد الجدول ${index + 1}`);
                }
            });
        });
        
        // بعد إنشاء الجداول، أضف المستخدمين الأساسيين
        setTimeout(() => {
            addEssentialUsers(db);
        }, 1500);
    });
}

function updatePermitsTable(db) {
    console.log('🔍 التحقق من أعمدة جدول التصاريح...');
    
    const columnsToAdd = [
        ['actual_entry_time', 'TEXT'],
        ['entry_guard_username', 'TEXT'],
        ['exit_guard_username', 'TEXT'],
        ['entry_notes', 'TEXT'],
        ['exit_notes', 'TEXT'],
        ['checkin_timestamp', 'TEXT'],
        ['checkout_timestamp', 'TEXT']
    ];
    
    db.all(`PRAGMA table_info(permits)`, (err, columns) => {
        if (err) {
            console.error('❌ خطأ في قراءة هيكل جدول permits:', err.message);
            return;
        }
        
        const existingColumns = columns ? columns.map(col => col.name) : [];
        
        // إضافة الأعمدة المفقودة
        columnsToAdd.forEach(([columnName, columnType]) => {
            if (!existingColumns.includes(columnName)) {
                db.run(`ALTER TABLE permits ADD COLUMN ${columnName} ${columnType}`, (alterErr) => {
                    if (alterErr) {
                        console.error(`❌ خطأ في إضافة العمود ${columnName}:`, alterErr.message);
                    } else {
                        console.log(`✅ تم إضافة العمود: ${columnName}`);
                    }
                });
            } else {
                console.log(`✅ العمود ${columnName} موجود بالفعل`);
            }
        });
    });
}

function addEssentialUsers(db) {
    console.log('👤 جاري إضافة المستخدمين الأساسيين...');
    
    const users = [
        // [username, password, full_name, user_type, job_number, directorate, email, phone]
        ['admin', 'admin123', 'مدير النظام', 'admin', 'ADM001', 'الإدارة العامة', 'admin@company.com', '0500000000'],
        ['employee1', 'admin123', 'محمد حسن', 'employee', 'EMP001', 'الإدارة العامة', 'employee1@company.com', '0500000001'],
        ['employee2', 'admin123', 'فاطمة علي', 'employee', 'EMP002', 'الإدارة العامة', 'employee2@company.com', '0500000002'],
        ['manager1', 'admin123', 'أحمد علي', 'manager', 'MGR001', 'الإدارة العامة', 'manager1@company.com', '0500000003'],
        ['security1', 'admin123', 'خالد أمين', 'security', 'SEC001', 'الأمن والسلامة', 'security1@company.com', '0500000004'],
        ['security2', 'admin123', 'حارس الأمن', 'security_guard', 'SEC002', 'الأمن والسلامة', 'security2@company.com', '0500000005']
    ];
    
    let completed = 0;
    const totalUsers = users.length;
    
    users.forEach((user, index) => {
        // تحقق إذا كان المستخدم موجوداً
        db.get('SELECT employee_id FROM employees WHERE username = ?', [user[0]], (err, existing) => {
            if (err) {
                console.log(`⚠️  خطأ في التحقق من ${user[0]}: ${err.message}`);
                completed++;
                checkCompletion();
                return;
            }
            
            if (!existing) {
                // إضافة المستخدم
                db.run(`
                    INSERT INTO employees 
                    (username, password_hash, full_name, user_type, job_number, directorate, email, phone, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
                `, user, function(err) {
                    if (err) {
                        console.log(`❌ ${user[0]}: ${err.message}`);
                    } else {
                        console.log(`✅ ${user[0]}: تمت إضافته (ID: ${this.lastID})`);
                    }
                    completed++;
                    checkCompletion();
                });
            } else {
                console.log(`ℹ️  ${user[0]}: موجود بالفعل`);
                completed++;
                checkCompletion();
            }
        });
    });
    
    function checkCompletion() {
        if (completed === totalUsers) {
            console.log(`\n📊 تمت معالجة ${totalUsers} مستخدم`);
            console.log('🎉 قاعدة البيانات جاهزة للاستخدام!\n');
            
            // عرض بيانات الدخول
            console.log('='.repeat(60));
            console.log('👤 بيانات الدخول المتاحة:');
            console.log('='.repeat(60));
            users.forEach(user => {
                console.log(`📧 ${user[0].padEnd(12)} / ${user[1].padEnd(10)} (${user[3]})`);
            });
            console.log('='.repeat(60) + '\n');
        }
    }
}

// ======================== ⭐⭐ دالة إنشاء الإشعارات المحسنة ⭐⭐ ========================
async function createNotification(notification) {
    try {
        const {
            user_id,
            permit_id = null,
            company_permit_id = null,
            title,
            message,
            type = 'info',  // تغيير من notification_type إلى type
            is_read = 0
        } = notification;

        const query = `
            INSERT INTO notifications 
            (user_id, permit_id, company_permit_id, title, message, type, is_read, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        `;

        const params = [user_id, permit_id, company_permit_id, title, message, type, is_read];
        
        return new Promise((resolve, reject) => {
            db.run(query, params, function(err) {
                if (err) {
                    console.error('❌ خطأ في إنشاء إشعار:', err.message);
                    console.error('🔍 تفاصيل:', { query, params, error: err.message });
                    reject(err);
                } else {
                    console.log(`✅ تم إنشاء إشعار جديد (ID: ${this.lastID})`);
                    resolve(this.lastID);
                }
            });
        });
    } catch (error) {
        console.error('❌ خطأ في دالة إنشاء الإشعار:', error.message);
        throw error;
    }
}

// دالة مساعدة للحصول على معرف المستخدم بالاسم
function getUserIdByUsername(username) {
    return new Promise((resolve, reject) => {
        db.get('SELECT employee_id FROM employees WHERE username = ?', [username], (err, row) => {
            if (err) reject(err);
            else resolve(row ? row.employee_id : null);
        });
    });
}

// ============== دالة لإرسال إشعار لجميع المديرين ==============
function notifyAllManagers(permit_id, title, message, type = 'warning', company_permit_id = null) {
    const query = `
        SELECT employee_id FROM employees 
        WHERE (user_type = 'manager' OR user_type = 'admin') 
        AND is_active = 1
    `;
    
    db.all(query, [], (err, managers) => {
        if (err || !managers) {
            console.error('❌ خطأ في جلب المديرين:', err);
            return;
        }
        
        managers.forEach(manager => {
            createNotification({
                user_id: manager.employee_id,
                permit_id: permit_id,
                company_permit_id: company_permit_id,
                title,
                message,
                type
            });
        });
        
        console.log(`✅ تم إرسال إشعار لـ ${managers.length} مدير`);
    });
}

// ============== دالة لإرسال إشعار لجميع مسؤولي الأمن (بدون الحراس) ==============
function notifyAllSecurityStaff(permit_id, title, message, type = 'info', company_permit_id = null) {
    const query = `
        SELECT employee_id FROM employees 
        WHERE user_type = 'security' 
        AND is_active = 1
    `;
    
    db.all(query, [], (err, securityUsers) => {
        if (err || !securityUsers) {
            console.error('❌ خطأ في جلب مسؤولي الأمن:', err);
            return;
        }
        
        securityUsers.forEach(user => {
            createNotification({
                user_id: user.employee_id,
                permit_id: permit_id,
                company_permit_id: company_permit_id,
                title,
                message,
                type
            });
        });
        
        console.log(`✅ تم إرسال إشعار لـ ${securityUsers.length} من مسؤولي الأمن`);
    });
}

// ============== دالة لإرسال إشعار لجميع الحراس فقط ==============
function notifyAllGuards(permit_id, title, message, type = 'info', company_permit_id = null) {
    const query = `
        SELECT employee_id FROM employees 
        WHERE user_type = 'security_guard' 
        AND is_active = 1
    `;
    
    db.all(query, [], (err, guards) => {
        if (err || !guards) {
            console.error('❌ خطأ في جلب الحراس:', err);
            return;
        }
        
        guards.forEach(guard => {
            createNotification({
                user_id: guard.employee_id,
                permit_id: permit_id,
                company_permit_id: company_permit_id,
                title,
                message,
                type
            });
        });
        
        console.log(`✅ تم إرسال إشعار لـ ${guards.length} حارس`);
    });
}

// ============== دالة لإرسال إشعار لجميع مسؤولي الأمن والحراس ==============
function notifyAllSecurityUsers(permit_id, title, message, type = 'info') {
    const query = `
        SELECT employee_id FROM employees 
        WHERE (user_type = 'security' OR user_type = 'security_guard') 
        AND is_active = 1
    `;
    
    db.all(query, [], (err, securityUsers) => {
        if (err || !securityUsers) {
            console.error('❌ خطأ في جلب مسؤولي الأمن:', err);
            return;
        }
        
        securityUsers.forEach(user => {
            createNotification({
                user_id: user.employee_id,
                permit_id,
                title,
                message,
                type  // ✅ إصلاح: استخدام type بدلاً من notification_type
            });
        });
        
        console.log(`✅ تم إرسال إشعار لـ ${securityUsers.length} من مسؤولي الأمن والحراس`);
    });
}

// ============== APIs الأساسية ==============

// 1. API للتحقق من صحة الخادم (بدون حماية)
app.get('/api/health', (req, res) => {
    res.json({ 
        success: true,
        status: 'OK', 
        message: 'نظام تصاريح العمل يعمل',
        database: selectedDb,
        timestamp: new Date().toISOString()
    });
});

// 2. API لتسجيل الدخول (بدون حماية)
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    console.log('🔐 محاولة تسجيل دخول:', username);
    
    const query = `SELECT * FROM employees WHERE username = ? AND password_hash = ? AND is_active = 1`;
    
    db.get(query, [username, password], (err, user) => {
        if (err) {
            console.error('❌ خطأ في تسجيل الدخول:', err);
            return res.status(500).json({
                success: false,
                message: 'حدث خطأ في الخادم'
            });
        }
        
        if (user) {
            const userData = {
                employee_id: user.employee_id,
                username: user.username,
                role: user.user_type,
                name: user.full_name
            };
            
            // تحويل إلى base64 (توكن مؤقت)
            const token = Buffer.from(JSON.stringify(userData)).toString('base64');
            
            console.log(`✅ تسجيل دخول ناجح: ${username} (${user.user_type})`);
            
            res.json({
                success: true,
                token: token,
                user: {
                    username: user.username,
                    role: user.user_type,
                    name: user.full_name,
                    full_name: user.full_name,
                    job_number: user.job_number,
                    directorate: user.directorate,
                    department_id: user.department_id,
                    email: user.email,
                    phone: user.phone,
                    employee_id: user.employee_id
                }
            });
        } else {
            console.log(`❌ فشل تسجيل دخول: ${username}`);
            res.status(401).json({
                success: false,
                message: 'اسم المستخدم أو كلمة المرور غير صحيحة'
            });
        }
    });
});

// 3. API للحصول على ملف المستخدم الشخصي (محمي)
app.get('/api/user/profile', authenticateToken, (req, res) => {
    const username = req.user?.username;
    
    if (!username) {
        return res.status(401).json({
            success: false,
            message: 'غير مصرح، يرجى تسجيل الدخول أولاً'
        });
    }
    
    console.log('👤 جلب ملف المستخدم:', username);
    
    const query = `
        SELECT 
            employee_id,
            username,
            full_name,
            user_type as role,
            job_number,
            directorate,
            department_id,
            email,
            phone,
            position,
            is_active,
            created_at
        FROM employees 
        WHERE username = ? AND is_active = 1
    `;
    
    db.get(query, [username], (err, user) => {
        if (err) {
            console.error('❌ خطأ في جلب ملف المستخدم:', err);
            return res.status(500).json({
                success: false,
                message: 'حدث خطأ في الخادم'
            });
        }
        
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'المستخدم غير موجود'
            });
        }
        
        console.log(`✅ تم جلب ملف المستخدم: ${username}`);
        
        res.json({
            success: true,
            user: {
                employee_id: user.employee_id,
                username: user.username,
                name: user.full_name,
                full_name: user.full_name,
                fullName: user.full_name,
                role: user.role,
                userType: user.role,
                job_number: user.job_number,
                directorate: user.directorate,
                department_id: user.department_id,
                email: user.email,
                phone: user.phone,
                position: user.position,
                is_active: user.is_active
            }
        });
    });
});

// ======================== ⭐⭐ تحسين API إنشاء تصريح الشركة ⭐⭐ ========================
app.post('/api/permits/company-entry/new', authenticateToken, async (req, res) => {
    try {
        console.log('🏢 استقبال طلب إنشاء تصريح شركة جديد');
        console.log('📥 البيانات:', JSON.stringify(req.body, null, 2));
        
        const {
            employee_username,
            employee_name,
            company_name,
            company_representative,
            representative_phone,
            entry_purpose,
            expected_entry_date,
            expected_entry_time,
            expected_exit_date,
            expected_exit_time,
            number_of_visitors,
            additional_notes,
            status = 'pending'
        } = req.body;
        
        // ✅ الحصول على اسم المستخدم من التوكن إذا لم يُرسل
        const finalEmployeeUsername = employee_username || req.user?.username;
        
        if (!finalEmployeeUsername) {
            return res.status(400).json({
                success: false,
                message: 'اسم المستخدم مطلوب. يرجى تسجيل الدخول أولاً.'
            });
        }
        
        // التحقق من الحقول المطلوبة
        const requiredFields = [
            'company_name',
            'company_representative',
            'representative_phone',
            'entry_purpose',
            'expected_entry_date',
            'expected_entry_time',
            'expected_exit_date',
            'expected_exit_time'
        ];
        
        const missingFields = requiredFields.filter(field => !req.body[field]);
        if (missingFields.length > 0) {
            return res.status(400).json({
                success: false,
                message: `حقول مطلوبة: ${missingFields.join(', ')}`
            });
        }
        
        // التحقق من وجود المستخدم
        db.get('SELECT * FROM employees WHERE username = ?', [finalEmployeeUsername], async (err, user) => {
            if (err) {
                console.error('❌ خطأ في البحث عن المستخدم:', err);
                return res.status(500).json({
                    success: false,
                    message: 'حدث خطأ في الخادم'
                });
            }
            
            if (!user) {
                return res.status(404).json({
                    success: false,
                    message: 'المستخدم غير موجود'
                });
            }
            
            try {
                // إدخال التصريح في قاعدة البيانات
                // ✅ استخدام employee_id حسب بنية الجدول الفعلية
                const query = `
                    INSERT INTO company_entry_permits 
                    (employee_id, company_name, company_representative,
                     representative_phone, entry_purpose, expected_entry_date, expected_entry_time,
                     expected_exit_date, expected_exit_time, number_of_visitors, 
                     requesting_department, employees, additional_notes, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `;
                
                // تحضير بيانات القسم والعمال
                const requestingDepartment = JSON.stringify({
                    employee_name: employee_name || user.full_name || user.name || '',
                    directorate: user.directorate || '',
                    job_number: user.job_number || '',
                    department: user.department_id || '',
                    supervisor_name: user.manager_id || ''
                });
                
                // تحضير بيانات العمال من additional_notes إذا كانت موجودة
                let workersData = [];
                if (additional_notes) {
                    try {
                        const notesObj = JSON.parse(additional_notes);
                        if (notesObj.employees && Array.isArray(notesObj.employees)) {
                            workersData = notesObj.employees;
                        }
                    } catch (e) {
                        // ignore
                    }
                }
                const employeesJson = JSON.stringify(workersData);
                
                const params = [
                    user.employee_id, // ✅ استخدام employee_id
                    company_name,
                    company_representative,
                    representative_phone || '',
                    entry_purpose,
                    expected_entry_date,
                    expected_entry_time,
                    expected_exit_date,
                    expected_exit_time,
                    number_of_visitors || 1,
                    requestingDepartment,
                    employeesJson,
                    additional_notes || '',
                    status || 'pending_manager'
                ];
                
                console.log('📝 تنفيذ الاستعلام:', query);
                console.log('🔢 المعاملات:', params);
                
                db.run(query, params, function(err) {
                    if (err) {
                        console.error('❌ خطأ في إدخال التصريح:', err);
                        return res.status(500).json({
                            success: false,
                            message: 'خطأ في حفظ التصريح: ' + err.message
                        });
                    }
                    
                    const permitId = this.lastID;
                    console.log(`✅ تم إنشاء تصريح الشركة رقم: ${permitId}`);
                    
                    // ======= ⭐⭐ التحسين: إنشاء إشعارات بشكل صحيح ⭐⭐ =======
                    try {
                        // 1. إشعار للموظف نفسه
                        createNotification({
                            user_id: user.employee_id,
                            company_permit_id: permitId,
                            title: '🏢 تم تقديم طلب تصريح الشركة',
                            message: `تم استلام طلب تصريح الشركة ${company_name} وسيتم مراجعته من قبل المدير.`,
                            type: 'info'
                        });
                        
                        // 2. ✅ إشعار لجميع المديرين (وليس المدير المباشر فقط)
                        notifyAllManagers(
                            null, // permit_id للتصاريح الشخصية فقط
                            '🏢 طلب تصريح شركة جديد بانتظار الموافقة',
                            `طلب تصريح شركة جديد من الموظف ${employee_name || user.full_name} (${company_name}) ينتظر موافقتك.`,
                            'warning',
                            permitId // ✅ إضافة company_permit_id
                        );
                        
                    } catch (notificationError) {
                        console.warn('⚠️ حدث خطأ في إنشاء الإشعارات:', notificationError.message);
                        // لا نوقف العملية بسبب خطأ في الإشعارات
                    }
                    
                    res.json({
                        success: true,
                        message: 'تم تقديم طلب تصريح الشركة بنجاح',
                        permit_id: permitId,
                        timestamp: new Date().toISOString()
                    });
                });
                
            } catch (error) {
                console.error('❌ خطأ في معالجة الطلب:', error);
                res.status(500).json({
                    success: false,
                    message: 'حدث خطأ في الخادم: ' + error.message
                });
            }
        });
        
    } catch (error) {
        console.error('❌ خطأ في API إنشاء تصريح شركة:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في الخادم: ' + error.message
        });
    }
});

// ============== ⭐⭐ تصاريح دخول الشركات (Company Entry Permits) ⭐⭐ ==============

// API لإنشاء تصريح شركة جديد (POST)
app.post('/api/permits/company-entry', authenticateToken, authorizeRoles('employee', 'admin'), async (req, res) => {
    try {
        console.log('🏢 استقبال طلب إنشاء تصريح شركة جديد');
        console.log('📥 البيانات:', JSON.stringify(req.body, null, 2));
        
        // جمع البيانات من body
        const formData = req.body;
        
        // التحقق من البيانات الأساسية
        if (!formData.employee_name || !formData.company_name || !formData.start_date || !formData.end_date) {
            return res.status(400).json({
                success: false,
                message: 'بيانات غير مكتملة'
            });
        }
        
        // الحصول على معلومات المستخدم من التوكن
        const user = req.user;
        
        // بناء بيانات التصريح
        const permitData = {
            employee_username: user.username,
            employee_name: formData.employee_name,
            company_name: formData.company_name,
            company_supervisor: formData.company_supervisor || '',
            company_phone: formData.company_phone || '',
            company_address: formData.company_address || '',
            work_details: formData.work_details || '',
            start_date: formData.start_date,
            end_date: formData.end_date,
            entry_time: formData.entry_time || '08:00',
            exit_time: formData.exit_time || '17:00',
            additional_notes: formData.additional_notes || '',
            // جمع بيانات العمال
            employees: formData.employees || [],
            // معلومات الجهة الطالبة
            directorate: formData.directorate || '',
            job_number: formData.job_number || '',
            department: formData.department || '',
            supervisor_name: formData.supervisor_name || '',
            permit_date: formData.permit_date || new Date().toISOString().split('T')[0],
            permit_time: formData.permit_time || new Date().toTimeString().slice(0, 5)
        };
        
        console.log('📋 بيانات التصريح المبنية:', permitData);
        
        // إدراج التصريح في قاعدة البيانات
        const query = `
            INSERT INTO company_entry_permits 
            (employee_username, employee_name, company_name, company_representative,
             representative_phone, entry_purpose, expected_entry_date, expected_entry_time,
             expected_exit_date, expected_exit_time, number_of_visitors, additional_notes,
             manager_status, security_status, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 'pending', 'pending')
            RETURNING *
        `;
        
        // تحويل بيانات العمال إلى نص JSON لتخزينها
        const employeesJson = JSON.stringify(permitData.employees);
        
        const params = [
            permitData.employee_username,
            permitData.employee_name,
            permitData.company_name,
            permitData.company_supervisor,
            permitData.company_phone,
            permitData.work_details,
            permitData.start_date,
            permitData.entry_time,
            permitData.end_date,
            permitData.exit_time,
            permitData.employees.length,
            JSON.stringify({
                directorate: permitData.directorate,
                job_number: permitData.job_number,
                department: permitData.department,
                supervisor_name: permitData.supervisor_name,
                company_address: permitData.company_address,
                additional_notes: permitData.additional_notes,
                employees: permitData.employees
            })
        ];
        
        db.get(query, params, (err, result) => {
            if (err) {
                console.error('❌ خطأ في إنشاء تصريح الشركة:', err);
                return res.status(500).json({
                    success: false,
                    message: 'خطأ في حفظ التصريح: ' + err.message
                });
            }
            
            const permitId = result.permit_id;
            console.log(`✅ تم إنشاء تصريح الشركة رقم: ${permitId}`);
            
            // إرسال إشعار للموظف
            db.get('SELECT employee_id FROM employees WHERE username = ?', 
            [permitData.employee_username], (err, employee) => {
                if (!err && employee) {
                    createNotification({
                        user_id: employee.employee_id,
                        permit_id: permitId,
                        title: '🏢 تم تقديم طلب تصريح الشركة',
                        message: `تم استلام طلب تصريح الشركة ${permitData.company_name} وسيتم مراجعته من قبل المدير.`,
                        type: 'info'
                    });
                }
            });
            
            // ✅ حفظ العمال الأصليين في جدول company_workers
            if (permitData.employees && Array.isArray(permitData.employees) && permitData.employees.length > 0) {
                permitData.employees.forEach((worker, index) => {
                    db.run(`
                        INSERT INTO company_workers 
                        (permit_id, worker_name, worker_id_number, worker_profession, worker_phone, added_by, is_original)
                        VALUES (?, ?, ?, ?, ?, ?, 1)
                    `, [
                        permitId,
                        worker.name || worker.worker_name || '',
                        worker.id_number || worker.worker_id_number || null,
                        worker.profession || worker.worker_profession || null,
                        worker.phone || worker.worker_phone || null,
                        permitData.employee_username,
                        1  // عمال أصليين
                    ], (err) => {
                        if (err) {
                            console.error(`❌ خطأ في حفظ العامل ${index + 1}:`, err);
                        } else {
                            console.log(`✅ تم حفظ العامل الأصلي: ${worker.name || worker.worker_name}`);
                        }
                    });
                });
            }
            
            // إرسال إشعار للمدير
            db.get('SELECT employee_id FROM employees WHERE employee_id = (SELECT manager_id FROM employees WHERE username = ?)', 
            [permitData.employee_username], (err, manager) => {
                if (!err && manager) {
                    createNotification({
                        user_id: manager.employee_id,
                        permit_id: permitId,
                        title: '🏢 طلب تصريح شركة جديد',
                        message: `هناك طلب تصريح شركة جديد من ${permitData.employee_name} (${permitData.company_name}) ينتظر الموافقة.`,
                        type: 'warning'
                    });
                }
            });
            
            res.json({
                success: true,
                message: 'تم تقديم طلب تصريح الشركة بنجاح',
                permit_id: permitId,
                permit: result,
                timestamp: new Date().toISOString()
            });
        });
        
    } catch (error) {
        console.error('❌ خطأ في API إنشاء تصريح شركة:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في الخادم: ' + error.message
        });
    }
});

// API رئيسي لتصاريح الشركات (للعرض العام)
app.get('/api/permits/company-entry', authenticateToken, 
    authorizeRoles('admin', 'security', 'manager'), (req, res) => {
    try {
        console.log('📋 جلب جميع تصاريح الشركات');
        
        const { limit, offset, status } = req.query;
        const limitValue = parseInt(limit) || 50;
        const offsetValue = parseInt(offset) || 0;
        
        let query = `
            SELECT cep.*, e.full_name as employee_full_name, e.job_number, e.phone
            FROM company_entry_permits cep
            LEFT JOIN employees e ON cep.employee_username = e.username
            WHERE 1=1
        `;
        
        const params = [];
        
        // فلترة حسب الحالة إذا كانت محددة
        if (status) {
            if (status === 'pending') {
                query += ` AND cep.manager_status = 'pending'`;
            } else if (status === 'approved_manager') {
                query += ` AND cep.manager_status = 'approved' AND cep.security_status = 'pending'`;
            } else if (status === 'approved_security') {
                query += ` AND cep.security_status = 'approved'`;
            } else if (status === 'rejected') {
                query += ` AND (cep.manager_status = 'rejected' OR cep.security_status = 'rejected')`;
            } else if (status === 'checked_in') {
                query += ` AND cep.status = 'checked_in'`;
            } else if (status === 'completed') {
                query += ` AND cep.status = 'completed'`;
            }
        }
        
        // إضافة الترتيب والتحديد
        query += ` ORDER BY cep.request_date DESC LIMIT ? OFFSET ?`;
        params.push(limitValue, offsetValue);
        
        db.all(query, params, (err, permits) => {
            if (err) {
                console.error('❌ خطأ في جلب تصاريح الشركات:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'خطأ في جلب البيانات' 
                });
            }
            
            // جلب العدد الإجمالي
            let countQuery = `SELECT COUNT(*) as total FROM company_entry_permits WHERE 1=1`;
            const countParams = [];
            
            if (status) {
                if (status === 'pending') {
                    countQuery += ` AND manager_status = 'pending'`;
                } else if (status === 'approved_manager') {
                    countQuery += ` AND manager_status = 'approved' AND security_status = 'pending'`;
                } else if (status === 'approved_security') {
                    countQuery += ` AND security_status = 'approved'`;
                } else if (status === 'rejected') {
                    countQuery += ` AND (manager_status = 'rejected' OR security_status = 'rejected')`;
                } else if (status === 'checked_in') {
                    countQuery += ` AND status = 'checked_in'`;
                } else if (status === 'completed') {
                    countQuery += ` AND status = 'completed'`;
                }
            }
            
            db.get(countQuery, countParams, (err, countResult) => {
                if (err) {
                    console.error('❌ خطأ في عد التصاريح:', err);
                    return res.json({
                        success: true,
                        permits: permits || [],
                        count: permits ? permits.length : 0
                    });
                }
                
                res.json({
                    success: true,
                    permits: permits || [],
                    count: permits ? permits.length : 0,
                    total: countResult ? countResult.total : 0,
                    limit: limitValue,
                    offset: offsetValue
                });
            });
        });
    } catch (error) {
        console.error('❌ خطأ في API جلب تصاريح الشركات:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في الخادم' 
        });
    }
});

// API للحصول على التصاريح حسب حالة المدير
app.get('/api/permits/company-entry/by-manager-status/:status', authenticateToken, 
    authorizeRoles('manager', 'admin'), (req, res) => {
    try {
        const { status } = req.params;
        const { username } = req.query;
        
        console.log(`📋 جلب تصاريح الشركات بحالة المدير: ${status}`);
        
        let query = `
            SELECT cep.*, e.full_name as employee_full_name, e.job_number
            FROM company_entry_permits cep
            LEFT JOIN employees e ON cep.employee_username = e.username
            WHERE cep.manager_status = ?
        `;
        
        const params = [status];
        
        // إذا كان هناك اسم مستخدم، فلتر حسب مدير الموظف
        if (username) {
            query += ` AND cep.employee_username = ?`;
            params.push(username);
        }
        
        query += ` ORDER BY cep.request_date DESC`;
        
        db.all(query, params, (err, permits) => {
            if (err) {
                console.error('❌ خطأ في جلب تصاريح الشركات:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'خطأ في جلب البيانات' 
                });
            }
            
            res.json({
                success: true,
                permits: permits || [],
                count: permits ? permits.length : 0
            });
        });
    } catch (error) {
        console.error('❌ خطأ في API تصاريح الشركات بحالة المدير:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في الخادم' 
        });
    }
});

// API للحصول على التصاريح حسب حالة الأمن
app.get('/api/permits/company-entry/by-security-status/:status', authenticateToken, 
    authorizeRoles('security', 'admin'), (req, res) => {
    try {
        const { status } = req.params;
        
        console.log(`📋 جلب تصاريح الشركات بحالة الأمن: ${status}`);
        
        const query = `
            SELECT cep.*, e.full_name as employee_full_name, e.job_number
            FROM company_entry_permits cep
            LEFT JOIN employees e ON cep.employee_username = e.username
            WHERE cep.security_status = ?
            ORDER BY cep.request_date DESC
        `;
        
        db.all(query, [status], (err, permits) => {
            if (err) {
                console.error('❌ خطأ في جلب تصاريح الشركات:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'خطأ في جلب البيانات' 
                });
            }
            
            res.json({
                success: true,
                permits: permits || [],
                count: permits ? permits.length : 0
            });
        });
    } catch (error) {
        console.error('❌ خطأ في API تصاريح الشركات بحالة الأمن:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في الخادم' 
        });
    }
});

// API للحصول على التصاريح حسب الموظف
app.get('/api/permits/company-entry/by-employee/:username', authenticateToken, 
    authorizeRoles('admin', 'manager'), (req, res) => {
    try {
        const { username } = req.params;
        
        console.log(`📋 جلب تصاريح الشركات للموظف: ${username}`);
        
        const query = `
            SELECT cep.*, e.full_name as employee_full_name, e.job_number
            FROM company_entry_permits cep
            LEFT JOIN employees e ON cep.employee_username = e.username
            WHERE cep.employee_username = ?
            ORDER BY cep.request_date DESC
        `;
        
        db.all(query, [username], (err, permits) => {
            if (err) {
                console.error('❌ خطأ في جلب تصاريح الشركات:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'خطأ في جلب البيانات' 
                });
            }
            
            res.json({
                success: true,
                permits: permits || [],
                count: permits ? permits.length : 0
            });
        });
    } catch (error) {
        console.error('❌ خطأ في API تصاريح الشركات للموظف:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في الخادم' 
        });
    }
});

// API للحصول على تصاريح الشركات المرسلة للحرس
app.get('/api/permits/company-entry/sent-to-guard', authenticateToken, 
    authorizeRoles('security', 'security_guard', 'admin'), (req, res) => {
    try {
        console.log('📤 جلب تصاريح الشركات المرسلة للحرس');
        
        const query = `
            SELECT gcp.*, cep.company_name, cep.company_representative, 
                   cep.expected_entry_date, cep.expected_entry_time,
                   e.full_name as employee_name
            FROM guard_company_permits gcp
            JOIN company_entry_permits cep ON gcp.permit_id = cep.permit_id
            LEFT JOIN employees e ON cep.employee_username = e.username
            ORDER BY gcp.sent_at DESC
            LIMIT 50
        `;
        
        db.all(query, [], (err, records) => {
            if (err) {
                console.error('❌ خطأ في جلب تصاريح الشركات المرسلة:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'خطأ في جلب البيانات' 
                });
            }
            
            res.json({
                success: true,
                records: records || [],
                count: records ? records.length : 0
            });
        });
    } catch (error) {
        console.error('❌ خطأ في API تصاريح الشركات المرسلة:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في الخادم' 
        });
    }
});

// API للحصول على تصاريح الشركات حسب التاريخ
app.get('/api/permits/company-entry/by-date/:date', authenticateToken, 
    authorizeRoles('admin', 'security', 'manager'), (req, res) => {
    try {
        const { date } = req.params;
        
        console.log(`📅 جلب تصاريح الشركات ليوم: ${date}`);
        
        const query = `
            SELECT cep.*, e.full_name as employee_full_name, e.job_number
            FROM company_entry_permits cep
            LEFT JOIN employees e ON cep.employee_username = e.username
            WHERE DATE(cep.expected_entry_date) = DATE(?)
            ORDER BY cep.expected_entry_time ASC
        `;
        
        db.all(query, [date], (err, permits) => {
            if (err) {
                console.error('❌ خطأ في جلب تصاريح الشركات حسب التاريخ:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'خطأ في جلب البيانات' 
                });
            }
            
            res.json({
                success: true,
                permits: permits || [],
                count: permits ? permits.length : 0,
                date: date
            });
        });
    } catch (error) {
        console.error('❌ خطأ في API تصاريح الشركات حسب التاريخ:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في الخادم' 
        });
    }
});

// API للتحقق من وجود تصريح شركة
app.head('/api/permits/company-entry/:id', authenticateToken, (req, res) => {
    try {
        const { id } = req.params;
        
        console.log(`🔍 التحقق من وجود تصريح الشركة: ${id}`);
        
        const query = `SELECT 1 FROM company_entry_permits WHERE permit_id = ? LIMIT 1`;
        
        db.get(query, [id], (err, row) => {
            if (err) {
                console.error('❌ خطأ في التحقق من التصريح:', err);
                return res.status(500).end();
            }
            
            if (row) {
                res.status(200).end();
            } else {
                res.status(404).end();
            }
        });
    } catch (error) {
        console.error('❌ خطأ في API التحقق من التصريح:', error);
        res.status(500).end();
    }
});

// API لاختبار اتصال نظام تصاريح الشركات
app.get('/api/permits/company-entry/test', authenticateToken, (req, res) => {
    try {
        console.log('🧪 اختبار اتصال نظام تصاريح الشركات');
        
        // التحقق من وجود الجداول
        const tableCheckQuery = `
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name IN ('company_entry_permits', 'guard_company_permits')
        `;
        
        db.all(tableCheckQuery, [], (err, tables) => {
            if (err) {
                return res.json({
                    success: false,
                    message: 'خطأ في التحقق من الجداول',
                    error: err.message
                });
            }
            
            const tableNames = tables ? tables.map(t => t.name) : [];
            const hasCompanyPermitsTable = tableNames.includes('company_entry_permits');
            const hasGuardTable = tableNames.includes('guard_company_permits');
            
            res.json({
                success: true,
                message: 'نظام تصاريح الشركات يعمل',
                tables: {
                    company_entry_permits: hasCompanyPermitsTable,
                    guard_company_permits: hasGuardTable
                },
                available_apis: [
                    'GET /api/permits/company-entry',
                    'GET /api/permits/company-entry/pending/:username',
                    'GET /api/permits/company-entry/security-pending',
                    'POST /api/permits/company-entry/new',
                    'GET /api/permits/company-entry/my/:username',
                    'GET /api/permits/company-entry/:id',
                    'GET /api/permits/company-entry/active',
                    'GET /api/permits/company-entry/checked-in',
                    'GET /api/permits/company-entry/stats/:username',
                    'GET /api/permits/company-entry/search',
                    'POST /api/permits/company-entry/approve',
                    'POST /api/permits/company-entry/security-approve',
                    'POST /api/permits/company-entry/send-to-guard',
                    'POST /api/permits/company-entry/guard-checkin',
                    'POST /api/permits/company-entry/guard-checkout'
                ],
                timestamp: new Date().toISOString()
            });
        });
    } catch (error) {
        console.error('❌ خطأ في اختبار النظام:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في الخادم' 
        });
    }
});

// الحصول على تصاريح الشركات المعلقة للمدير (بدون username)
app.get('/api/permits/company-entry/pending', authenticateToken, authorizeRoles('manager', 'admin'), async (req, res) => {
    try {
        console.log('📋 جلب تصاريح الشركات المعلقة للمدير');
        
        // جلب تصاريح الشركات المعلقة (status = 'pending_manager')
        const query = `
            SELECT * FROM company_entry_permits 
            WHERE status = 'pending_manager'
            ORDER BY created_at DESC, request_date DESC
        `;
        
        db.all(query, [], (err, permits) => {
            if (err) {
                console.error('❌ خطأ في جلب تصاريح الشركات المعلقة:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'خطأ في جلب البيانات' 
                });
            }
            
            res.json({
                success: true,
                permits: permits || []
            });
        });
    } catch (error) {
        console.error('❌ خطأ في API تصاريح الشركات المعلقة:', error);
        res.status(500).json({ 
            success: false, 
            message: 'خطأ في جلب البيانات' 
        });
    }
});

// الحصول على تصاريح الشركات المعلقة للمدير (مع username - للتوافق مع الكود القديم)
app.get('/api/permits/company-entry/pending/:username', authenticateToken, authorizeRoles('manager', 'admin'), async (req, res) => {
    try {
        const { username } = req.params;
        
        console.log(`📋 جلب تصاريح الشركات المعلقة للمدير: ${username}`);
        
        // جلب تصاريح الشركات المعلقة للمدير
        const query = `
            SELECT * FROM company_entry_permits 
            WHERE manager_status = 'pending' 
            AND employee_username = ?
            ORDER BY request_date DESC
        `;
        
        db.all(query, [username], (err, result) => {
            if (err) {
                console.error('❌ خطأ في جلب تصاريح الشركات المعلقة:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'خطأ في جلب البيانات' 
                });
            }
            
            res.json({
                success: true,
                permits: result || []
            });
        });
    } catch (error) {
        console.error('❌ خطأ في API تصاريح الشركات المعلقة:', error);
        res.status(500).json({ 
            success: false, 
            message: 'خطأ في جلب البيانات' 
        });
    }
});

// الحصول على تصاريح الشركات المعلقة للأمن
app.get('/api/permits/company-entry/security-pending', authenticateToken, authorizeRoles('security', 'admin'), (req, res) => {
    try {
        console.log('📋 جلب تصاريح الشركات المعلقة للأمن');
        
        // جلب تصاريح الشركات المعتمدة من المدير والمنتظرة الأمن
        const query = `
            SELECT * FROM company_entry_permits 
            WHERE manager_status = 'approved' 
            AND security_status = 'pending'
            ORDER BY request_date DESC
        `;
        
        db.all(query, [], (err, result) => {
            if (err) {
                console.error('❌ خطأ في جلب تصاريح الشركات المعلقة للأمن:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'خطأ في جلب البيانات' 
                });
            }
            
            res.json({
                success: true,
                permits: result || []
            });
        });
    } catch (error) {
        console.error('❌ خطأ في API تصاريح الشركات المعلقة للأمن:', error);
        res.status(500).json({ 
            success: false, 
            message: 'خطأ في جلب البيانات' 
        });
    }
});

// الموافقة/الرفض من المدير لتصاريح الشركات
app.post('/api/permits/company-entry/approve', authenticateToken, authorizeRoles('manager', 'admin'), (req, res) => {
    try {
        const { permit_id, manager_username, decision, notes } = req.body;
        
        console.log(`🔄 معالجة موافقة المدير على تصريح شركة: ${permit_id}`);
        console.log('📥 البيانات:', { permit_id, manager_username, decision, notes });
        
        // تحديث حالة الموافقة المديرية
        const query = `
            UPDATE company_entry_permits 
            SET manager_status = ?, 
                manager_username = ?, 
                manager_notes = ?,
                manager_decision_date = CURRENT_TIMESTAMP
            WHERE permit_id = ?
            RETURNING *
        `;
        
        const status = decision === 'approve' ? 'approved' : 'rejected';
        const params = [status, manager_username, notes || '', permit_id];
        
        db.get(query, params, (err, row) => {
            if (err) {
                console.error('❌ خطأ في تحديث تصريح الشركة:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'خطأ في المعالجة' 
                });
            }
            
            if (!row) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'تصريح الشركة غير موجود' 
                });
            }
            
            console.log(`✅ تم تحديث تصريح الشركة ${permit_id}: ${status}`);
            
            // إرسال إشعار للموظف
            if (row.employee_username) {
                db.get('SELECT employee_id FROM employees WHERE username = ?', [row.employee_username], (err, employee) => {
                    if (!err && employee) {
                        const title = decision === 'approve' 
                            ? '✅ تمت الموافقة على تصريح الشركة' 
                            : '❌ تم رفض تصريح الشركة';
                        const message = decision === 'approve'
                            ? `قام المدير بالموافقة على تصريح الشركة الخاص بك. سيتم مراجعته الآن من قبل الأمن.`
                            : `قام المدير برفض تصريح الشركة الخاص بك. يرجى التواصل معه للحصول على مزيد من المعلومات.`;
                        
                        createNotification({
                            user_id: employee.employee_id,
                            company_permit_id: permit_id,
                            title: title,
                            message: message,
                            type: decision === 'approve' ? 'success' : 'warning'
                        });
                    }
                });
            }
            
            // إذا تمت الموافقة، إرسال إشعار لمكتب الأمن (وليس الحراس)
            if (status === 'approved') {
                // ✅ استخدام دالة محدثة لدعم company_permit_id
                db.all('SELECT employee_id FROM employees WHERE user_type = "security" AND is_active = 1', 
                [], (err, securityUsers) => {
                    if (!err && securityUsers && securityUsers.length > 0) {
                        securityUsers.forEach(security => {
                            createNotification({
                                user_id: security.employee_id,
                                company_permit_id: permit_id,
                                title: '🏢 تصريح شركة جديد بانتظار الموافقة الأمنية',
                                message: `تصريح شركة جديد بانتظار الموافقة الأمنية.`,
                                type: 'warning'
                            });
                        });
                        console.log(`✅ تم إرسال إشعار لـ ${securityUsers.length} من مسؤولي الأمن`);
                    }
                });
            }
            
            res.json({
                success: true,
                permit: row
            });
        });
    } catch (error) {
        console.error('❌ خطأ في API موافقة المدير على تصريح شركة:', error);
        res.status(500).json({ 
            success: false, 
            message: 'خطأ في المعالجة' 
        });
    }
});

// الموافقة/الرفض من الأمن لتصاريح الشركات
app.post('/api/permits/company-entry/security-approve', authenticateToken, authorizeRoles('security', 'admin'), (req, res) => {
    try {
        const { permit_id, security_username, decision, notes } = req.body;
        
        console.log(`🔄 معالجة موافقة الأمن على تصريح شركة: ${permit_id}`);
        console.log('📥 البيانات:', { permit_id, security_username, decision, notes });
        
        // تحديث حالة الموافقة الأمنية
        const query = `
            UPDATE company_entry_permits 
            SET security_status = ?, 
                security_username = ?, 
                security_notes = ?,
                security_decision_date = CURRENT_TIMESTAMP
            WHERE permit_id = ?
            RETURNING *
        `;
        
        const status = decision === 'allow' ? 'approved' : 'rejected';
        const params = [status, security_username, notes || '', permit_id];
        
        db.get(query, params, (err, row) => {
            if (err) {
                console.error('❌ خطأ في تحديث تصريح الشركة:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'خطأ في المعالجة' 
                });
            }
            
            if (!row) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'تصريح الشركة غير موجود أو لم يوافق عليه المدير بعد' 
                });
            }
            
            console.log(`✅ تم تحديث تصريح الشركة ${permit_id}: ${status}`);
            
            // إرسال إشعار للموظف
            if (row.employee_username) {
                db.get('SELECT employee_id FROM employees WHERE username = ?', [row.employee_username], (err, employee) => {
                    if (!err && employee) {
                        const title = decision === 'allow' 
                            ? '✅ تمت الموافقة النهائية على تصريح الشركة' 
                            : '❌ تم رفض تصريح الشركة من قبل الأمن';
                        const message = decision === 'allow'
                            ? `تمت الموافقة النهائية على تصريح الشركة الخاص بك من قبل مكتب الأمن.`
                            : `تم رفض تصريح الشركة الخاص بك من قبل مكتب الأمن. يرجى التواصل مع المدير للحصول على مزيد من المعلومات.`;
                        
                        createNotification({
                            user_id: employee.employee_id,
                            company_permit_id: permit_id,
                            title: title,
                            message: message,
                            type: decision === 'allow' ? 'success' : 'warning'
                        });
                    }
                });
            }
            
            // إذا تمت الموافقة، إرسال إشعار للحراس مع معلومات جدول العمال
            if (status === 'approved') {
                // جلب معلومات التصريح والعمال
                db.get(`
                    SELECT cep.*, e.full_name as employee_name, e.job_number
                    FROM company_entry_permits cep
                    JOIN employees e ON cep.employee_username = e.username
                    WHERE cep.permit_id = ?
                `, [permit_id], (err, permitInfo) => {
                    if (!err && permitInfo) {
                        // جلب عدد العمال الأصليين
                        let workersCount = permitInfo.number_of_visitors || 1;
                        let workersInfo = '';
                        
                        // محاولة جلب معلومات العمال من جدول company_workers أو من employees field
                        db.all('SELECT worker_name FROM company_workers WHERE permit_id = ? AND is_original = 1', [permit_id], (err, workers) => {
                            if (!err && workers && workers.length > 0) {
                                workersInfo = ` (${workers.length} عامل: ${workers.map(w => w.worker_name).join(', ')})`;
                            } else if (permitInfo.employees) {
                                try {
                                    const employeesData = JSON.parse(permitInfo.employees);
                                    if (Array.isArray(employeesData) && employeesData.length > 0) {
                                        workersInfo = ` (${employeesData.length} عامل: ${employeesData.map(w => w.name || w.worker_name).join(', ')})`;
                                    }
                                } catch (e) {
                                    // ignore
                                }
                            }
                            
                            // ✅ إشعار لجميع الحراس مع معلومات جدول العمال
                            db.all('SELECT employee_id FROM employees WHERE user_type = "security_guard" AND is_active = 1', 
                            [], (err, guards) => {
                                if (!err && guards && guards.length > 0) {
                                    guards.forEach(guard => {
                                        createNotification({
                                            user_id: guard.employee_id,
                                            company_permit_id: permit_id,
                                            title: '🏢 تصريح شركة جديد جاهز مع جدول العمال',
                                            message: `تصريح شركة جديد للموظف ${permitInfo.employee_name || row.employee_name || 'غير محدد'} (${permitInfo.job_number || 'غير محدد'}) جاهز.${workersInfo} يمكنك إضافة عمال إضافيين حسب مكان العمل.`,
                                            type: 'info'
                                        });
                                    });
                                    console.log(`✅ تم إرسال إشعار لـ ${guards.length} حارس`);
                                }
                            });
                        });
                    } else {
                        // إذا فشل جلب المعلومات، إرسال إشعار عام
                        db.all('SELECT employee_id FROM employees WHERE user_type = "security_guard" AND is_active = 1', 
                        [], (err, guards) => {
                            if (!err && guards && guards.length > 0) {
                                guards.forEach(guard => {
                                    createNotification({
                                        user_id: guard.employee_id,
                                        company_permit_id: permit_id,
                                        title: '🏢 تصريح شركة جديد جاهز',
                                        message: `تصريح شركة جديد جاهز. يمكنك إضافة عمال إضافيين حسب مكان العمل.`,
                                        type: 'info'
                                    });
                                });
                                console.log(`✅ تم إرسال إشعار لـ ${guards.length} حارس`);
                            }
                        });
                    }
                });
            }
            
            // إرسال إشعار للمدير إذا تمت الموافقة
            if (status === 'approved' && row.manager_username) {
                db.get('SELECT employee_id FROM employees WHERE username = ?', [row.manager_username], (err, manager) => {
                    if (!err && manager) {
                        createNotification({
                            user_id: manager.employee_id,
                            company_permit_id: permit_id,
                            title: '🏢 تمت الموافقة على تصريح الشركة',
                            message: `تمت الموافقة النهائية على تصريح الشركة من قبل مكتب الأمن.`,
                            type: 'info'
                        });
                    }
                });
            }
            
            res.json({
                success: true,
                permit: row
            });
        });
    } catch (error) {
        console.error('❌ خطأ في API موافقة الأمن على تصريح شركة:', error);
        res.status(500).json({ 
            success: false, 
            message: 'خطأ في المعالجة' 
        });
    }
});

// الحصول على تصريح شركة محدد
app.get('/api/permits/company-entry/:id', authenticateToken, authorizeRoles('employee', 'manager', 'security', 'admin'), (req, res) => {
    try {
        const { id } = req.params;
        
        console.log(`🔍 جلب تفاصيل تصريح الشركة: ${id}`);
        
        const query = `
            SELECT * FROM company_entry_permits 
            WHERE permit_id = ?
        `;
        
        db.get(query, [id], (err, row) => {
            if (err) {
                console.error('❌ خطأ في جلب تفاصيل تصريح الشركة:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'خطأ في جلب البيانات' 
                });
            }
            
            if (!row) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'التصريح غير موجود' 
                });
            }
            
            // التحقق من صلاحية المستخدم لمشاهدة التصريح
            const userRole = req.user.role;
            const userName = req.user.username;
            
            let hasAccess = false;
            
            if (userRole === 'admin') {
                hasAccess = true;
            } else if (userRole === 'employee' && row.employee_username === userName) {
                hasAccess = true;
            } else if (userRole === 'manager' && row.manager_username === userName) {
                hasAccess = true;
            } else if (userRole === 'security') {
                hasAccess = true;
            }
            
            if (!hasAccess) {
                return res.status(403).json({ 
                    success: false, 
                    message: 'ليس لديك صلاحية للوصول إلى هذا التصريح' 
                });
            }
            
            res.json({
                success: true,
                permit: row
            });
        });
    } catch (error) {
        console.error('❌ خطأ في API جلب تصريح الشركة:', error);
        res.status(500).json({ 
            success: false, 
            message: 'خطأ في جلب البيانات' 
        });
    }
});

// إرسال تصريح شركة للحرس
app.post('/api/permits/company-entry/send-to-guard', authenticateToken, authorizeRoles('security', 'admin'), (req, res) => {
    try {
        const { permit_id, security_username, security_notes, timestamp } = req.body;
        
        console.log(`📤 إرسال تصريح شركة للحرس: ${permit_id}`);
        console.log('📥 البيانات:', { permit_id, security_username, security_notes, timestamp });
        
        // التحقق من وجود التصريح المعتمد من الأمن
        const checkQuery = `
            SELECT * FROM company_entry_permits 
            WHERE permit_id = ? AND security_status = 'approved'
        `;
        
        db.get(checkQuery, [permit_id], (err, permit) => {
            if (err) {
                console.error('❌ خطأ في التحقق من تصريح الشركة:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'خطأ في التحقق من التصريح' 
                });
            }
            
            if (!permit) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'التصريح غير موجود أو غير معتمد من الأمن' 
                });
            }
            
            // حفظ في جدول التصاريح المرسلة للحرس
            const insertQuery = `
                INSERT INTO guard_company_permits 
                (permit_id, security_username, security_notes, sent_at)
                VALUES (?, ?, ?, ?)
                RETURNING *
            `;
            
            const sentTime = timestamp || new Date().toISOString();
            
            db.get(insertQuery, [permit_id, security_username, security_notes || '', sentTime], (err, result) => {
                if (err) {
                    console.error('❌ خطأ في إرسال التصريح للحرس:', err);
                    return res.status(500).json({ 
                        success: false, 
                        message: 'خطأ في الإرسال' 
                    });
                }
                
                console.log(`✅ تم إرسال تصريح الشركة ${permit_id} للحرس بنجاح`);
                
                // إرسال إشعار لجميع الحراس
                notifyAllSecurityUsers(
                    permit_id,
                    '🏢 تصريح شركة جديد للحرس',
                    `تصريح شركة جديد متاح للتسجيل في نقطة الحراسة.`,
                    'info'
                );
                
                // إرسال إشعار للموظف
                if (permit.employee_username) {
                    db.get('SELECT employee_id FROM employees WHERE username = ?', [permit.employee_username], (err, employee) => {
                        if (!err && employee) {
                            createNotification({
                                user_id: employee.employee_id,
                                permit_id: permit_id,
                                title: '🏢 تصريح الشركة جاهز',
                                message: `تم إرسال تصريح الشركة الخاص بك إلى نقطة الحراسة وجاهز للتسجيل.`,
                                type: 'info'
                            });
                        }
                    });
                }
                
                res.json({
                    success: true,
                    message: 'تم إرسال التصريح للحرس بنجاح',
                    record: result
                });
            });
        });
    } catch (error) {
        console.error('❌ خطأ في API إرسال تصريح الشركة للحرس:', error);
        res.status(500).json({ 
            success: false, 
            message: 'خطأ في الإرسال' 
        });
    }
});

// API لإرسال إشعار للمدير بخصوص تصريح شركة جديد
app.post('/api/notifications/manager-company-entry', authenticateToken, (req, res) => {
    try {
        const { permit_id, title, message, type = 'company_entry_manager', priority = 'high' } = req.body;
        
        console.log(`📨 إرسال إشعار للمدير بخصوص تصريح شركة: ${permit_id}`);
        
        // البحث عن جميع المديرين
        const query = `
            SELECT employee_id, full_name, username 
            FROM employees 
            WHERE user_type = 'manager' OR user_type = 'admin'
            AND is_active = 1
        `;
        
        db.all(query, [], (err, managers) => {
            if (err) {
                console.error('❌ خطأ في جلب المديرين:', err);
                return res.status(500).json({
                    success: false,
                    message: 'حدث خطأ في الخادم'
                });
            }
            
            let notificationsSent = 0;
            
            if (managers && managers.length > 0) {
                managers.forEach(manager => {
                    createNotification({
                        user_id: manager.employee_id,
                        permit_id: permit_id,
                        title: title || '🏢 طلب دخول شركة جديد',
                        message: message || 'هناك طلب دخول شركة جديد ينتظر موافقتك.',
                        type: type
                    });
                    notificationsSent++;
                });
                
                console.log(`✅ تم إرسال ${notificationsSent} إشعار للمديرين`);
            } else {
                console.log('⚠️  لا يوجد مديرين في النظام');
            }
            
            res.json({
                success: true,
                message: `تم إرسال ${notificationsSent} إشعار للمديرين`,
                notifications_sent: notificationsSent
            });
        });
        
    } catch (error) {
        console.error('❌ خطأ في API إرسال إشعار للمدير:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في الخادم'
        });
    }
});

// تم نقل هذا الـ endpoint إلى الأسفل لتجنب التكرار


// تفاصيل تصريح شركة معين
app.get('/api/permits/company-entry/details/:permitId', authenticateToken, async (req, res) => {
    try {
        const { permitId } = req.params;
        
        const query = `
            SELECT * FROM company_entry_permits 
            WHERE permit_id = ?
        `;
        
        db.get(query, [permitId], (err, permit) => {
            if (err) {
                console.error('❌ خطأ في جلب تفاصيل التصريح:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'حدث خطأ في الخادم' 
                });
            }
            
            if (!permit) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'التصريح غير موجود' 
                });
            }
            
            res.json({ 
                success: true, 
                permit: permit 
            });
        });
        
    } catch (error) {
        console.error('خطأ في جلب تفاصيل التصريح:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في الخادم' 
        });
    }
});

// API للحصول على تصاريح الشركات الخاصة بالموظف
app.get('/api/permits/company-entry/my/:username', authenticateToken, (req, res) => {
    try {
        const { username } = req.params;
        
        console.log(`🔍 جلب تصاريح الشركات للموظف: ${username}`);
        
        // التحقق من صلاحية المستخدم
        if (req.user.username !== username && req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'غير مصرح لك بالوصول إلى تصاريح مستخدم آخر'
            });
        }
        
        // جلب employee_id أولاً
        db.get('SELECT employee_id FROM employees WHERE username = ?', [username], (err, employee) => {
            if (err) {
                console.error('❌ خطأ في البحث عن الموظف:', err);
                return res.status(500).json({
                    success: false,
                    message: 'حدث خطأ في الخادم'
                });
            }
            
            if (!employee) {
                return res.status(404).json({
                    success: false,
                    message: 'الموظف غير موجود'
                });
            }
            
            // جلب تصاريح الشركات الخاصة بالموظف باستخدام employee_id
            const query = `
                SELECT * FROM company_entry_permits 
                WHERE employee_id = ?
                ORDER BY created_at DESC, request_date DESC
            `;
            
            db.all(query, [employee.employee_id], (err, permits) => {
                if (err) {
                    console.error('❌ خطأ في جلب تصاريح الشركات:', err);
                    return res.status(500).json({
                        success: false,
                        message: 'حدث خطأ في الخادم'
                    });
                }
                
                res.json({
                    success: true,
                    permits: permits || []
                });
            });
        });
        
    } catch (error) {
        console.error('❌ خطأ في API جلب تصاريح الشركات للموظف:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في الخادم'
        });
    }
});

// API للحصول على تصاريح الشركات النشطة (جاهزة للتسجيل في الحراسة)
app.get('/api/permits/company-entry/active', authenticateToken, 
    authorizeRoles('security', 'security_guard', 'admin'), (req, res) => {
    try {
        const today = new Date().toISOString().split('T')[0];
        
        const query = `
            SELECT cep.*, e.full_name as employee_full_name, e.phone as employee_phone
            FROM company_entry_permits cep
            LEFT JOIN employees e ON cep.employee_username = e.username
            WHERE cep.security_status = 'approved'
            AND cep.expected_entry_date <= ?
            AND cep.expected_exit_date >= ?
            AND (cep.actual_entry_time IS NULL OR cep.actual_entry_time = '')
            ORDER BY cep.expected_entry_date ASC, cep.expected_entry_time ASC
        `;
        
        db.all(query, [today, today], (err, permits) => {
            if (err) {
                console.error('❌ خطأ في جلب تصاريح الشركات النشطة:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'خطأ في جلب البيانات' 
                });
            }
            
            // ✅ جلب العمال لكل تصريح
            if (permits && permits.length > 0) {
                let processed = 0;
                permits.forEach((permit, index) => {
                    // جلب العمال من جدول company_workers
                    db.all(`
                        SELECT * FROM company_workers 
                        WHERE permit_id = ? 
                        ORDER BY is_original DESC, added_at ASC
                    `, [permit.permit_id], (err, workers) => {
                        if (!err) {
                            permit.workers = workers || [];
                        } else {
                            permit.workers = [];
                        }
                        
                        // ✅ أيضاً جلب العمال من حقل employees (JSON) إذا كان موجوداً
                        if (permit.employees) {
                            try {
                                const employeesList = typeof permit.employees === 'string' 
                                    ? JSON.parse(permit.employees) 
                                    : permit.employees;
                                
                                if (Array.isArray(employeesList) && employeesList.length > 0) {
                                    // إضافة العمال من JSON إلى القائمة (إذا لم تكن موجودة بالفعل)
                                    employeesList.forEach(emp => {
                                        const exists = permit.workers.some(w => 
                                            w.worker_name === emp.name || 
                                            w.worker_name === emp.worker_name
                                        );
                                        if (!exists) {
                                            permit.workers.push({
                                                worker_id: Date.now() + Math.random(),
                                                permit_id: permit.permit_id,
                                                worker_name: emp.name || emp.worker_name || '',
                                                worker_profession: emp.profession || emp.worker_profession || '',
                                                worker_id_number: emp.id_number || emp.worker_id_number || '',
                                                worker_phone: emp.phone || emp.worker_phone || '',
                                                is_original: true,
                                                added_at: permit.created_at || new Date().toISOString()
                                            });
                                        }
                                    });
                                }
                            } catch (e) {
                                console.warn('⚠️ خطأ في تحليل حقل employees:', e);
                            }
                        }
                        
                        processed++;
                        if (processed === permits.length) {
                            res.json({
                                success: true,
                                permits: permits || [],
                                count: permits ? permits.length : 0
                            });
                        }
                    });
                });
            } else {
                res.json({
                    success: true,
                    permits: [],
                    count: 0
                });
            }
        });
    } catch (error) {
        console.error('❌ خطأ في API تصاريح الشركات النشطة:', error);
        res.status(500).json({ 
            success: false, 
            message: 'خطأ في جلب البيانات' 
        });
    }
});

// API لتسجيل دخول الشركة في الحراسة
app.post('/api/permits/company-entry/guard-checkin', authenticateToken, 
    authorizeRoles('security', 'security_guard', 'admin'), (req, res) => {
    try {
        const { 
            permit_id, 
            guard_username, 
            actual_entry_time, 
            entry_notes,
            actual_visitors_count
        } = req.body;
        
        console.log(`🏢 تسجيل دخول شركة: ${permit_id}`);
        console.log('📥 البيانات:', req.body);
        
        if (!permit_id || !guard_username || !actual_entry_time) {
            return res.status(400).json({
                success: false,
                message: 'بيانات غير مكتملة'
            });
        }
        
        // التحقق من صحة الوقت
        if (!/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/.test(actual_entry_time)) {
            return res.status(400).json({
                success: false,
                message: 'تنسيق الوقت غير صحيح. استخدم الصيغة HH:MM'
            });
        }
        
        // تحديث تسجيل الدخول
        const query = `
            UPDATE company_entry_permits 
            SET actual_entry_time = ?,
                entry_guard_username = ?,
                entry_notes = ?,
                actual_visitors_count = COALESCE(?, number_of_visitors),
                status = 'checked_in'
            WHERE permit_id = ? 
            AND security_status = 'approved'
            AND (actual_entry_time IS NULL OR actual_entry_time = '')
            RETURNING *
        `;
        
        const params = [
            actual_entry_time, 
            guard_username, 
            entry_notes || '',
            actual_visitors_count || null,
            permit_id
        ];
        
        db.get(query, params, (err, permit) => {
            if (err) {
                console.error('❌ خطأ في تسجيل دخول الشركة:', err);
                return res.status(500).json({
                    success: false,
                    message: 'حدث خطأ في الخادم'
                });
            }
            
            if (!permit) {
                return res.status(404).json({
                    success: false,
                    message: 'التصريح غير موجود أو تم تسجيل الدخول مسبقاً'
                });
            }
            
            console.log(`✅ تم تسجيل دخول الشركة ${permit_id} في ${actual_entry_time}`);
            
            // إرسال إشعار للموظف
            if (permit.employee_username) {
                db.get('SELECT employee_id FROM employees WHERE username = ?', 
                [permit.employee_username], (err, employee) => {
                    if (!err && employee) {
                        createNotification({
                            user_id: employee.employee_id,
                            permit_id: permit_id,
                            title: '🏢 تم تسجيل دخول الشركة',
                            message: `تم تسجيل دخول الشركة ${permit.company_name} في الساعة ${actual_entry_time}`,
                            type: 'success'
                        });
                    }
                });
            }
            
            res.json({
                success: true,
                message: 'تم تسجيل دخول الشركة بنجاح',
                permit: permit
            });
        });
        
    } catch (error) {
        console.error('❌ خطأ في API تسجيل دخول الشركة:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في الخادم' 
        });
    }
});

// API لتسجيل خروج الشركة من الحراسة
app.post('/api/permits/company-entry/guard-checkout', authenticateToken, 
    authorizeRoles('security', 'security_guard', 'admin'), (req, res) => {
    try {
        const { 
            permit_id, 
            guard_username, 
            actual_exit_time, 
            exit_notes 
        } = req.body;
        
        console.log(`🏢 تسجيل خروج شركة: ${permit_id}`);
        console.log('📥 البيانات:', req.body);
        
        if (!permit_id || !guard_username || !actual_exit_time) {
            return res.status(400).json({
                success: false,
                message: 'بيانات غير مكتملة'
            });
        }
        
        // التحقق من صحة الوقت
        if (!/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/.test(actual_exit_time)) {
            return res.status(400).json({
                success: false,
                message: 'تنسيق الوقت غير صحيح. استخدم الصيغة HH:MM'
            });
        }
        
        // تحديث تسجيل الخروج
        const query = `
            UPDATE company_entry_permits 
            SET actual_exit_time = ?,
                exit_guard_username = ?,
                exit_notes = ?,
                status = 'completed'
            WHERE permit_id = ? 
            AND actual_entry_time IS NOT NULL
            AND actual_entry_time != ''
            AND (actual_exit_time IS NULL OR actual_exit_time = '')
            RETURNING *
        `;
        
        db.get(query, [actual_exit_time, guard_username, exit_notes || '', permit_id], 
        (err, permit) => {
            if (err) {
                console.error('❌ خطأ في تسجيل خروج الشركة:', err);
                return res.status(500).json({
                    success: false,
                    message: 'حدث خطأ في الخادم'
                });
            }
            
            if (!permit) {
                return res.status(404).json({
                    success: false,
                    message: 'التصريح غير موجود أو لم يسجل دخول بعد'
                });
            }
            
            console.log(`✅ تم تسجيل خروج الشركة ${permit_id} في ${actual_exit_time}`);
            
            // حساب فرق الوقت
            const expectedTime = new Date(`2000-01-01T${permit.expected_exit_time}`);
            const actualTime = new Date(`2000-01-01T${actual_exit_time}`);
            const diffMinutes = (actualTime - expectedTime) / (1000 * 60);
            
            // إرسال إشعار للموظف
            if (permit.employee_username) {
                db.get('SELECT employee_id FROM employees WHERE username = ?', 
                [permit.employee_username], (err, employee) => {
                    if (!err && employee) {
                        let message = `تم تسجيل خروج الشركة ${permit.company_name} في الساعة ${actual_exit_time}`;
                        
                        if (diffMinutes > 15) {
                            message += ` (تأخر ${Math.abs(diffMinutes)} دقيقة)`;
                        } else if (diffMinutes < -15) {
                            message += ` (خرجت مبكراً ${Math.abs(diffMinutes)} دقيقة)`;
                        }
                        
                        createNotification({
                            user_id: employee.employee_id,
                            permit_id: permit_id,
                            title: '🏢 تم تسجيل خروج الشركة',
                            message: message,
                            type: 'success'
                        });
                    }
                });
            }
            
            // إرسال إشعار لمكتب الأمن باسم الحارس المناوب وتوقيت الخروج
            notifyAllSecurityStaff(
                null, // permit_id للتصاريح الشخصية فقط
                '🏢 تسجيل خروج شركة',
                `تم تسجيل خروج شركة بنقطة الحراسة.\nاسم الشركة: ${permit.company_name}\nالحارس المناوب: ${guard_username}\nوقت الخروج: ${actual_exit_time}${exit_notes ? '\nملاحظات: ' + exit_notes : ''}`,
                'info',
                permit_id // company_permit_id
            );
            
            // تسجيل مخالفة وقت إذا كان هناك تأخر كبير
            if (diffMinutes > 30) {
                db.run(`
                    INSERT INTO time_violations 
                    (permit_id, employee_id, violation_type, expected_time, actual_time, 
                     time_difference, severity, reported_by, notes)
                    SELECT 
                        ?, 
                        e.employee_id,
                        'late_checkout_company',
                        ?,
                        ?,
                        ?,
                        'medium',
                        ?,
                        'تأخر في خروج الشركة'
                    FROM employees e
                    WHERE e.username = ?
                `, [
                    permit_id,
                    permit.expected_exit_time,
                    actual_exit_time,
                    diffMinutes,
                    guard_username,
                    permit.employee_username
                ], (err) => {
                    if (!err) {
                        console.log(`⚠️ تم تسجيل مخالفة وقت لتصريح الشركة ${permit_id}`);
                    }
                });
            }
            
            res.json({
                success: true,
                message: 'تم تسجيل خروج الشركة بنجاح',
                permit: permit,
                time_difference: diffMinutes
            });
        });
        
    } catch (error) {
        console.error('❌ خطأ في API تسجيل خروج الشركة:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في الخادم' 
        });
    }
});

// API للحصول على تصاريح الشركات المسجلة دخول (داخل الموقع)
app.get('/api/permits/company-entry/checked-in', authenticateToken, 
    authorizeRoles('security', 'security_guard', 'admin'), (req, res) => {
    try {
        const today = new Date().toISOString().split('T')[0];
        
        const query = `
            SELECT cep.*, e.full_name as employee_full_name, e.phone as employee_phone
            FROM company_entry_permits cep
            LEFT JOIN employees e ON cep.employee_username = e.username
            WHERE cep.status = 'checked_in'
            AND cep.expected_entry_date <= ?
            AND cep.expected_exit_date >= ?
            AND cep.actual_entry_time IS NOT NULL
            AND cep.actual_entry_time != ''
            AND (cep.actual_exit_time IS NULL OR cep.actual_exit_time = '')
            ORDER BY cep.actual_entry_time DESC
        `;
        
        db.all(query, [today, today], (err, permits) => {
            if (err) {
                console.error('❌ خطأ في جلب تصاريح الشركات المسجلة:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'خطأ في جلب البيانات' 
                });
            }
            
            // ✅ جلب العمال لكل تصريح
            if (permits && permits.length > 0) {
                let processed = 0;
                permits.forEach((permit) => {
                    db.all(`
                        SELECT * FROM company_workers 
                        WHERE permit_id = ? 
                        ORDER BY is_original DESC, added_at ASC
                    `, [permit.permit_id], (err, workers) => {
                        if (!err) {
                            permit.workers = workers || [];
                        } else {
                            permit.workers = [];
                        }
                        
                        processed++;
                        if (processed === permits.length) {
                            res.json({
                                success: true,
                                permits: permits || [],
                                count: permits ? permits.length : 0
                            });
                        }
                    });
                });
            } else {
                res.json({
                    success: true,
                    permits: [],
                    count: 0
                });
            }
        });
    } catch (error) {
        console.error('❌ خطأ في API تصاريح الشركات المسجلة:', error);
        res.status(500).json({ 
            success: false, 
            message: 'خطأ في جلب البيانات' 
        });
    }
});

// ========== ✅ APIs إدارة العمال في تصاريح الشركات ==========

// API لإضافة عامل جديد لتصريح شركة (من قبل الحارس)
app.post('/api/permits/company-entry/:permit_id/workers', authenticateToken, 
    authorizeRoles('security', 'security_guard', 'admin'), (req, res) => {
    try {
        const { permit_id } = req.params;
        const { worker_name, worker_id_number, worker_profession, worker_phone, added_by } = req.body;
        
        console.log(`➕ إضافة عامل جديد لتصريح الشركة: ${permit_id}`);
        
        if (!worker_name) {
            return res.status(400).json({
                success: false,
                message: 'اسم العامل مطلوب'
            });
        }
        
        // التحقق من وجود التصريح
        db.get('SELECT permit_id FROM company_entry_permits WHERE permit_id = ?', [permit_id], (err, permit) => {
            if (err || !permit) {
                return res.status(404).json({
                    success: false,
                    message: 'التصريح غير موجود'
                });
            }
            
            // إضافة العامل
            const query = `
                INSERT INTO company_workers 
                (permit_id, worker_name, worker_id_number, worker_profession, worker_phone, added_by, is_original)
                VALUES (?, ?, ?, ?, ?, ?, 0)
            `;
            
            db.run(query, [
                permit_id,
                worker_name,
                worker_id_number || null,
                worker_profession || null,
                worker_phone || null,
                added_by || req.user.username,
                0  // ليس من العمال الأصليين
            ], function(err) {
                if (err) {
                    console.error('❌ خطأ في إضافة العامل:', err);
                    return res.status(500).json({
                        success: false,
                        message: 'حدث خطأ في إضافة العامل'
                    });
                }
                
                // جلب العامل المضاف
                db.get('SELECT * FROM company_workers WHERE worker_id = ?', [this.lastID], (err, worker) => {
                    res.json({
                        success: true,
                        message: 'تم إضافة العامل بنجاح',
                        worker: worker
                    });
                });
            });
        });
        
    } catch (error) {
        console.error('❌ خطأ في API إضافة عامل:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في الخادم'
        });
    }
});

// API لجلب جميع العمال لتصريح شركة
app.get('/api/permits/company-entry/:permit_id/workers', authenticateToken, 
    authorizeRoles('security', 'security_guard', 'admin', 'manager'), (req, res) => {
    try {
        const { permit_id } = req.params;
        
        const query = `
            SELECT * FROM company_workers 
            WHERE permit_id = ? 
            ORDER BY is_original DESC, added_at ASC
        `;
        
        db.all(query, [permit_id], (err, workers) => {
            if (err) {
                console.error('❌ خطأ في جلب العمال:', err);
                return res.status(500).json({
                    success: false,
                    message: 'حدث خطأ في جلب العمال'
                });
            }
            
            res.json({
                success: true,
                workers: workers || [],
                count: workers ? workers.length : 0
            });
        });
        
    } catch (error) {
        console.error('❌ خطأ في API جلب العمال:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في الخادم'
        });
    }
});

// API لحذف عامل من تصريح شركة
app.delete('/api/permits/company-entry/:permit_id/workers/:worker_id', authenticateToken, 
    authorizeRoles('security', 'security_guard', 'admin'), (req, res) => {
    try {
        const { permit_id, worker_id } = req.params;
        
        // التحقق من أن العامل ليس من العمال الأصليين (يمكن حذف فقط العمال المضافة من قبل الحارس)
        db.get('SELECT is_original FROM company_workers WHERE worker_id = ? AND permit_id = ?', 
        [worker_id, permit_id], (err, worker) => {
            if (err || !worker) {
                return res.status(404).json({
                    success: false,
                    message: 'العامل غير موجود'
                });
            }
            
            // لا يمكن حذف العمال الأصليين
            if (worker.is_original) {
                return res.status(403).json({
                    success: false,
                    message: 'لا يمكن حذف العمال الأصليين المضافة في التصريح'
                });
            }
            
            // حذف العامل
            db.run('DELETE FROM company_workers WHERE worker_id = ? AND permit_id = ?', 
            [worker_id, permit_id], function(err) {
                if (err) {
                    console.error('❌ خطأ في حذف العامل:', err);
                    return res.status(500).json({
                        success: false,
                        message: 'حدث خطأ في حذف العامل'
                    });
                }
                
                res.json({
                    success: true,
                    message: 'تم حذف العامل بنجاح'
                });
            });
        });
        
    } catch (error) {
        console.error('❌ خطأ في API حذف عامل:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في الخادم'
        });
    }
});

// API للحصول على إحصائيات تصاريح الشركات
app.get('/api/permits/company-entry/stats/:username', authenticateToken, (req, res) => {
    try {
        const { username } = req.params;
        
        console.log(`📊 جلب إحصائيات تصاريح الشركات للمستخدم: ${username}`);
        
        // التحقق من صلاحية المستخدم
        if (req.user.username !== username && req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'غير مصرح لك بالوصول إلى إحصائيات مستخدم آخر'
            });
        }
        
        // بناء الاستعلامات بناءً على دور المستخدم
        const userRole = req.user.role;
        const userName = req.user.username;
        
        let totalQuery = '';
        let pendingQuery = '';
        let approvedQuery = '';
        let rejectedQuery = '';
        let checkedInQuery = '';
        let completedQuery = '';
        
        const params = [];
        const today = new Date().toISOString().split('T')[0];
        
        if (userRole === 'employee') {
            totalQuery = `SELECT COUNT(*) as count FROM company_entry_permits WHERE employee_username = ?`;
            pendingQuery = `SELECT COUNT(*) as count FROM company_entry_permits WHERE employee_username = ? AND manager_status = 'pending'`;
            approvedQuery = `SELECT COUNT(*) as count FROM company_entry_permits WHERE employee_username = ? AND security_status = 'approved'`;
            rejectedQuery = `SELECT COUNT(*) as count FROM company_entry_permits WHERE employee_username = ? AND (manager_status = 'rejected' OR security_status = 'rejected')`;
            checkedInQuery = `SELECT COUNT(*) as count FROM company_entry_permits WHERE employee_username = ? AND status = 'checked_in' AND expected_entry_date <= ? AND expected_exit_date >= ?`;
            completedQuery = `SELECT COUNT(*) as count FROM company_entry_permits WHERE employee_username = ? AND status = 'completed'`;
            
            params.push(userName, today, today);
        } 
        else if (userRole === 'manager') {
            totalQuery = `
                SELECT COUNT(*) as count 
                FROM company_entry_permits cep
                JOIN employees e ON cep.employee_username = e.username
                WHERE e.manager_id = (SELECT employee_id FROM employees WHERE username = ?)
            `;
            pendingQuery = `
                SELECT COUNT(*) as count 
                FROM company_entry_permits cep
                JOIN employees e ON cep.employee_username = e.username
                WHERE e.manager_id = (SELECT employee_id FROM employees WHERE username = ?)
                AND cep.manager_status = 'pending'
            `;
            approvedQuery = `
                SELECT COUNT(*) as count 
                FROM company_entry_permits cep
                JOIN employees e ON cep.employee_username = e.username
                WHERE e.manager_id = (SELECT employee_id FROM employees WHERE username = ?)
                AND cep.manager_status = 'approved'
            `;
            rejectedQuery = `
                SELECT COUNT(*) as count 
                FROM company_entry_permits cep
                JOIN employees e ON cep.employee_username = e.username
                WHERE e.manager_id = (SELECT employee_id FROM employees WHERE username = ?)
                AND cep.manager_status = 'rejected'
            `;
            checkedInQuery = `
                SELECT COUNT(*) as count 
                FROM company_entry_permits cep
                JOIN employees e ON cep.employee_username = e.username
                WHERE e.manager_id = (SELECT employee_id FROM employees WHERE username = ?)
                AND cep.status = 'checked_in'
                AND cep.expected_entry_date <= ?
                AND cep.expected_exit_date >= ?
            `;
            completedQuery = `
                SELECT COUNT(*) as count 
                FROM company_entry_permits cep
                JOIN employees e ON cep.employee_username = e.username
                WHERE e.manager_id = (SELECT employee_id FROM employees WHERE username = ?)
                AND cep.status = 'completed'
            `;
            
            params.push(userName, userName, userName, userName, userName, today, today, userName);
        }
        else if (userRole === 'security' || userRole === 'security_guard') {
            totalQuery = `SELECT COUNT(*) as count FROM company_entry_permits WHERE security_status = 'approved'`;
            pendingQuery = `SELECT COUNT(*) as count FROM company_entry_permits WHERE manager_status = 'approved' AND security_status = 'pending'`;
            approvedQuery = `SELECT COUNT(*) as count FROM company_entry_permits WHERE security_status = 'approved'`;
            rejectedQuery = `SELECT COUNT(*) as count FROM company_entry_permits WHERE security_status = 'rejected'`;
            checkedInQuery = `SELECT COUNT(*) as count FROM company_entry_permits WHERE status = 'checked_in' AND expected_entry_date <= ? AND expected_exit_date >= ?`;
            completedQuery = `SELECT COUNT(*) as count FROM company_entry_permits WHERE status = 'completed'`;
            
            params.push(today, today);
        }
        else if (userRole === 'admin') {
            totalQuery = `SELECT COUNT(*) as count FROM company_entry_permits`;
            pendingQuery = `SELECT COUNT(*) as count FROM company_entry_permits WHERE manager_status = 'pending'`;
            approvedQuery = `SELECT COUNT(*) as count FROM company_entry_permits WHERE security_status = 'approved'`;
            rejectedQuery = `SELECT COUNT(*) as count FROM company_entry_permits WHERE manager_status = 'rejected' OR security_status = 'rejected'`;
            checkedInQuery = `SELECT COUNT(*) as count FROM company_entry_permits WHERE status = 'checked_in' AND expected_entry_date <= ? AND expected_exit_date >= ?`;
            completedQuery = `SELECT COUNT(*) as count FROM company_entry_permits WHERE status = 'completed'`;
            
            params.push(today, today);
        }
        
        // تنفيذ الاستعلامات
        const queries = [
            { key: 'total', query: totalQuery, params: [params[0]] },
            { key: 'pending', query: pendingQuery, params: [params[1] || params[0]] },
            { key: 'approved', query: approvedQuery, params: [params[2] || params[0]] },
            { key: 'rejected', query: rejectedQuery, params: [params[3] || params[0]] },
            { key: 'checked_in', query: checkedInQuery, params: userRole === 'employee' ? [params[0], today, today] : 
                                    userRole === 'manager' ? [params[5], today, today] : [today, today] },
            { key: 'completed', query: completedQuery, params: userRole === 'employee' ? [params[0]] : 
                                    userRole === 'manager' ? [params[7]] : [params[0]] }
        ];
        
        const stats = {};
        let completedQueries = 0;
        
        queries.forEach((item, index) => {
            db.get(item.query, item.params, (err, result) => {
                stats[item.key] = result ? result.count : 0;
                completedQueries++;
                
                if (completedQueries === queries.length) {
                    res.json({
                        success: true,
                        stats: stats
                    });
                }
            });
        });
        
    } catch (error) {
        console.error('❌ خطأ في API إحصائيات تصاريح الشركات:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في الخادم' 
        });
    }
});

// 🔥 GET /api/permits/company-entry/stats - إحصائيات تصاريح الشركات (محسّن)
app.get('/api/permits/company-entry/stats', authenticateToken, (req, res) => {
    const userRole = req.user.role;
    
    // التحقق من صلاحية المستخدم
    if (userRole !== 'manager' && userRole !== 'admin') {
        return res.status(403).json({
            success: false,
            message: 'غير مصرح لك بالوصول إلى هذه البيانات'
        });
    }
    
    try {
        // استعلام واحد شامل بدلاً من استعلامين منفصلين
        const statsQuery = `
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'pending_manager' THEN 1 ELSE 0 END) as pending,
                SUM(CASE WHEN status = 'pending_security' THEN 1 ELSE 0 END) as pending_security,
                SUM(CASE WHEN status = 'approved_security' THEN 1 ELSE 0 END) as approved,
                SUM(CASE WHEN status IN ('rejected_by_manager', 'rejected_by_security') THEN 1 ELSE 0 END) as rejected,
                SUM(CASE WHEN MONTH(request_date) = MONTH(CURRENT_DATE()) 
                          AND YEAR(request_date) = YEAR(CURRENT_DATE()) THEN 1 ELSE 0 END) as monthly_total,
                SUM(CASE WHEN status = 'approved_security' 
                          AND MONTH(request_date) = MONTH(CURRENT_DATE()) 
                          AND YEAR(request_date) = YEAR(CURRENT_DATE()) THEN 1 ELSE 0 END) as monthly_approved
            FROM company_entry_permits
        `;
        
        db.get(statsQuery, [], (err, stats) => {
            if (err) {
                console.error('❌ خطأ في جلب إحصائيات تصاريح الشركات:', err);
                return res.status(500).json({
                    success: false,
                    message: 'خطأ في الخادم'
                });
            }
            
            res.json({
                success: true,
                stats: {
                    total: stats.total || 0,
                    pending: stats.pending || 0,
                    pending_security: stats.pending_security || 0,
                    approved: stats.approved || 0,
                    rejected: stats.rejected || 0,
                    monthly_total: stats.monthly_total || 0,
                    monthly_approved: stats.monthly_approved || 0
                }
            });
        });
    } catch (error) {
        console.error('❌ خطأ في معالجة طلب الإحصائيات:', error);
        res.status(500).json({
            success: false,
            message: 'خطأ في الخادم'
        });
    }
});

// API لحذف تصريح شركة (للمسؤول فقط)
app.delete('/api/permits/company-entry/:id', authenticateToken, authorizeRoles('admin'), (req, res) => {
    try {
        const { id } = req.params;
        
        console.log(`🗑️  محاولة حذف تصريح الشركة: ${id}`);
        
        const query = `DELETE FROM company_entry_permits WHERE permit_id = ?`;
        
        db.run(query, [id], function(err) {
            if (err) {
                console.error('❌ خطأ في حذف تصريح الشركة:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'خطأ في حذف التصريح' 
                });
            }
            
            if (this.changes === 0) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'التصريح غير موجود' 
                });
            }
            
            console.log(`✅ تم حذف تصريح الشركة ${id}`);
            
            res.json({
                success: true,
                message: 'تم حذف تصريح الشركة بنجاح',
                deleted_id: id
            });
        });
        
    } catch (error) {
        console.error('❌ خطأ في API حذف تصريح الشركة:', error);
        res.status(500).json({ 
            success: false, 
            message: 'خطأ في حذف التصريح' 
        });
    }
});

// API لتحديث تصريح شركة
app.put('/api/permits/company-entry/:id', authenticateToken, (req, res) => {
    try {
        const { id } = req.params;
        const updateData = req.body;
        
        console.log(`✏️  محاولة تحديث تصريح الشركة: ${id}`);
        console.log('📥 بيانات التحديث:', updateData);
        
        // التحقق من صلاحية المستخدم
        db.get('SELECT employee_username, manager_status FROM company_entry_permits WHERE permit_id = ?', 
        [id], (err, permit) => {
            if (err) {
                console.error('❌ خطأ في التحقق من التصريح:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'خطأ في التحقق من التصريح' 
                });
            }
            
            if (!permit) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'التصريح غير موجود' 
                });
            }
            
            // التحقق من الصلاحيات
            const userRole = req.user.role;
            const userName = req.user.username;
            
            let hasPermission = false;
            
            if (userRole === 'admin') {
                hasPermission = true;
            } else if (userRole === 'employee' && permit.employee_username === userName && permit.manager_status === 'pending') {
                hasPermission = true;
            } else if (userRole === 'manager' && permit.manager_status === 'pending') {
                hasPermission = true;
            }
            
            if (!hasPermission) {
                return res.status(403).json({ 
                    success: false, 
                    message: 'ليس لديك صلاحية لتحديث هذا التصريح' 
                });
            }
            
            // بناء استعلام التحديث الديناميكي
            const allowedFields = [
                'company_name', 'company_representative', 'representative_id',
                'representative_phone', 'vehicle_number', 'entry_purpose',
                'expected_entry_date', 'expected_entry_time', 'expected_exit_date',
                'expected_exit_time', 'number_of_visitors', 'additional_notes'
            ];
            
            const updates = [];
            const values = [];
            
            allowedFields.forEach(field => {
                if (updateData[field] !== undefined) {
                    updates.push(`${field} = ?`);
                    values.push(updateData[field]);
                }
            });
            
            if (updates.length === 0) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'لا توجد بيانات للتحديث' 
                });
            }
            
            values.push(id);
            
            const query = `
                UPDATE company_entry_permits 
                SET ${updates.join(', ')}
                WHERE permit_id = ?
                RETURNING *
            `;
            
            db.get(query, values, (err, updatedPermit) => {
                if (err) {
                    console.error('❌ خطأ في تحديث تصريح الشركة:', err);
                    return res.status(500).json({ 
                        success: false, 
                        message: 'خطأ في تحديث التصريح' 
                    });
                }
                
                console.log(`✅ تم تحديث تصريح الشركة ${id}`);
                
                // إرسال إشعار إذا كان التحديث من قبل المدير
                if (userRole === 'manager' && permit.employee_username) {
                    db.get('SELECT employee_id FROM employees WHERE username = ?', 
                    [permit.employee_username], (err, employee) => {
                        if (!err && employee) {
                            createNotification({
                                user_id: employee.employee_id,
                                permit_id: id,
                                title: '✏️  تم تعديل تصريح الشركة',
                                message: 'قام المدير بتعديل تصريح الشركة الخاص بك.',
                                type: 'info'
                            });
                        }
                    });
                }
                
                res.json({
                    success: true,
                    message: 'تم تحديث تصريح الشركة بنجاح',
                    permit: updatedPermit
                });
            });
        });
        
    } catch (error) {
        console.error('❌ خطأ في API تحديث تصريح الشركة:', error);
        res.status(500).json({ 
            success: false, 
            message: 'خطأ في تحديث التصريح' 
        });
    }
});

// API للبحث في تصاريح الشركات
app.get('/api/permits/company-entry/search', authenticateToken, (req, res) => {
    try {
        const { q, status, date_from, date_to, company_name } = req.query;
        
        console.log(`🔍 بحث في تصاريح الشركات:`, req.query);
        
        // بناء الاستعلام الديناميكي
        let query = `
            SELECT cep.*, e.full_name as employee_full_name
            FROM company_entry_permits cep
            LEFT JOIN employees e ON cep.employee_username = e.username
            WHERE 1=1
        `;
        
        const params = [];
        
        // فلترة حسب النص
        if (q) {
            query += ` AND (
                cep.company_name LIKE ? OR 
                cep.company_representative LIKE ? OR 
                cep.vehicle_number LIKE ? OR
                e.full_name LIKE ?
            )`;
            const searchTerm = `%${q}%`;
            params.push(searchTerm, searchTerm, searchTerm, searchTerm);
        }
        
        // فلترة حسب اسم الشركة
        if (company_name) {
            query += ` AND cep.company_name LIKE ?`;
            params.push(`%${company_name}%`);
        }
        
        // فلترة حسب الحالة
        if (status) {
            if (status === 'pending_manager') {
                query += ` AND cep.manager_status = 'pending'`;
            } else if (status === 'pending_security') {
                query += ` AND cep.manager_status = 'approved' AND cep.security_status = 'pending'`;
            } else if (status === 'approved') {
                query += ` AND cep.security_status = 'approved'`;
            } else if (status === 'rejected') {
                query += ` AND (cep.manager_status = 'rejected' OR cep.security_status = 'rejected')`;
            } else if (status === 'checked_in') {
                query += ` AND cep.status = 'checked_in'`;
            } else if (status === 'completed') {
                query += ` AND cep.status = 'completed'`;
            }
        }
        
        // فلترة حسب التاريخ
        if (date_from) {
            query += ` AND DATE(cep.request_date) >= DATE(?)`;
            params.push(date_from);
        }
        
        if (date_to) {
            query += ` AND DATE(cep.request_date) <= DATE(?)`;
            params.push(date_to);
        }
        
        // ترتيب النتائج
        query += ` ORDER BY cep.request_date DESC LIMIT 50`;
        
        db.all(query, params, (err, permits) => {
            if (err) {
                console.error('❌ خطأ في البحث في تصاريح الشركات:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'خطأ في البحث' 
                });
            }
            
            res.json({
                success: true,
                permits: permits || [],
                count: permits ? permits.length : 0
            });
        });
        
    } catch (error) {
        console.error('❌ خطأ في API البحث في تصاريح الشركات:', error);
        res.status(500).json({ 
            success: false, 
            message: 'خطأ في البحث' 
        });
    }
});


// API لحفظ معاينة التصريح وتوليد PDF
app.post('/api/permits/company-entry/preview', authenticateToken, authorizeRoles('employee', 'admin'), (req, res) => {
    try {
        console.log('🖼️ استقبال طلب توليد معاينة تصريح شركة');
        console.log('📥 البيانات:', JSON.stringify(req.body, null, 2));
        
        const formData = req.body;
        const user = req.user;
        
        // بناء بيانات التصريح للمعاينة
        const previewData = {
            employee_name: formData.employee_name || user.name,
            employee_username: user.username,
            company_name: formData.company_name || '',
            company_representative: formData.company_supervisor || '',
            representative_phone: formData.company_phone || '',
            entry_purpose: formData.work_details || '',
            expected_entry_date: formData.start_date || '',
            expected_entry_time: formData.entry_time || '08:00',
            expected_exit_date: formData.end_date || '',
            expected_exit_time: formData.exit_time || '17:00',
            number_of_visitors: formData.employees?.length || 1,
            additional_notes: JSON.stringify({
                directorate: formData.directorate || '',
                job_number: formData.job_number || '',
                department: formData.department || '',
                supervisor_name: formData.supervisor_name || '',
                company_address: formData.company_address || '',
                employees: formData.employees || []
            }),
            request_date: new Date().toISOString(),
            permit_id: 'PREVIEW_' + Date.now()
        };
        
        console.log('✅ تم بناء بيانات المعاينة بنجاح');
        
        res.json({
            success: true,
            message: 'تم توليد المعاينة بنجاح',
            preview_data: previewData,
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        console.error('❌ خطأ في API توليد المعاينة:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في توليد المعاينة: ' + error.message
        });
    }
});

// API لتنزيل PDF تصريح الشركة
app.get('/api/permits/company-entry/download/:permit_id', authenticateToken, (req, res) => {
    try {
        const { permit_id } = req.params;
        
        console.log(`📥 طلب تنزيل PDF لتصريح الشركة: ${permit_id}`);
        
        // إذا كان معاينة
        if (permit_id.startsWith('PREVIEW_')) {
            return res.json({
                success: true,
                message: 'PDF معاينة جاهز للتنزيل',
                pdf_data: {
                    permit_id: permit_id,
                    type: 'preview',
                    download_url: `/api/permits/company-entry/pdf/${permit_id}`
                }
            });
        }
        
        // إذا كان تصريحاً حقيقياً
        db.get('SELECT * FROM company_entry_permits WHERE permit_id = ?', [permit_id], (err, permit) => {
            if (err || !permit) {
                console.error('❌ تصريح غير موجود:', permit_id);
                return res.status(404).json({
                    success: false,
                    message: 'التصريح غير موجود'
                });
            }
            
            // التحقق من صلاحية الوصول
            const userRole = req.user.role;
            const userName = req.user.username;
            
            let hasAccess = false;
            
            if (userRole === 'admin') {
                hasAccess = true;
            } else if (userRole === 'employee' && permit.employee_username === userName) {
                hasAccess = true;
            } else if (userRole === 'manager' && permit.manager_username === userName) {
                hasAccess = true;
            } else if (userRole === 'security') {
                hasAccess = true;
            }
            
            if (!hasAccess) {
                return res.status(403).json({
                    success: false,
                    message: 'ليس لديك صلاحية للوصول إلى هذا التصريح'
                });
            }
            
            res.json({
                success: true,
                message: 'PDF جاهز للتنزيل',
                pdf_data: {
                    permit_id: permit.permit_id,
                    type: 'real',
                    download_url: `/api/permits/company-entry/pdf/${permit.permit_id}`
                }
            });
        });
        
    } catch (error) {
        console.error('❌ خطأ في API تنزيل PDF:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في توليد PDF'
        });
    }
});

// API لتوليد PDF فعلي (يمكنك توسيعه لاستخدام مكتبة مثل pdfkit)
app.get('/api/permits/company-entry/pdf/:permit_id', authenticateToken, (req, res) => {
    try {
        const { permit_id } = req.params;
        
        console.log(`📄 توليد PDF لتصريح الشركة: ${permit_id}`);
        
        // هذا مثال بسيط، يمكنك استخدام مكتبة pdfkit لإنشاء PDF فعلي
        if (permit_id.startsWith('PREVIEW_')) {
            // إرجاع HTML للمعاينة
            const htmlContent = `
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>معاينة تصريح الشركة</title>
                    <style>
                        body { font-family: Arial, sans-serif; direction: rtl; padding: 20px; }
                        .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
                        .header h1 { color: #2c3e50; }
                        .info-section { margin-bottom: 20px; }
                        .info-section h2 { color: #3498db; border-bottom: 1px solid #eee; padding-bottom: 5px; }
                        .row { display: flex; margin-bottom: 10px; }
                        .label { font-weight: bold; width: 200px; }
                        .value { flex: 1; }
                        .footer { margin-top: 50px; text-align: center; color: #7f8c8d; font-size: 12px; }
                        .stamp { border: 2px solid #c0392b; padding: 10px; display: inline-block; margin-top: 30px; }
                    </style>
                </head>
                <body>
                    <div class="header">
                        <h1>معاينة تصريح دخول الشركة</h1>
                        <p>رقم المعاينة: ${permit_id}</p>
                        <p>تاريخ الإنشاء: ${new Date().toLocaleDateString('ar-SA')}</p>
                    </div>
                    
                    <div class="info-section">
                        <h2>معلومات الشركة</h2>
                        <div class="row">
                            <div class="label">اسم الشركة:</div>
                            <div class="value">[اسم الشركة سيظهر هنا]</div>
                        </div>
                        <div class="row">
                            <div class="label">الممثل القانوني:</div>
                            <div class="value">[اسم الممثل القانوني]</div>
                        </div>
                        <div class="row">
                            <div class="label">الغرض من الدخول:</div>
                            <div class="value">[الغرض من الدخول]</div>
                        </div>
                    </div>
                    
                    <div class="info-section">
                        <h2>تفاصيل الزيارة</h2>
                        <div class="row">
                            <div class="label">تاريخ الدخول:</div>
                            <div class="value">[تاريخ الدخول]</div>
                        </div>
                        <div class="row">
                            <div class="label">وقت الدخول:</div>
                            <div class="value">[وقت الدخول]</div>
                        </div>
                        <div class="row">
                            <div class="label">تاريخ الخروج:</div>
                            <div class="value">[تاريخ الخروج]</div>
                        </div>
                        <div class="row">
                            <div class="label">وقت الخروج:</div>
                            <div class="value">[وقت الخروج]</div>
                        </div>
                    </div>
                    
                    <div class="footer">
                        <p>هذه وثيقة معاينة - غير قابلة للاستخدام الرسمي</p>
                        <div class="stamp">معاينة</div>
                    </div>
                </body>
                </html>
            `;
            
            res.setHeader('Content-Type', 'text/html');
            res.send(htmlContent);
            return;
        }
        
        // للتصاريح الحقيقية
        db.get('SELECT * FROM company_entry_permits WHERE permit_id = ?', [permit_id], (err, permit) => {
            if (err || !permit) {
                return res.status(404).send('التصريح غير موجود');
            }
            
            // HTML للتصريح الحقيقي
            const htmlContent = `
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>تصريح دخول الشركة - ${permit.permit_id}</title>
                    <style>
                        body { font-family: 'Arial', sans-serif; direction: rtl; padding: 20px; }
                        .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
                        .header h1 { color: #2c3e50; }
                        .info-section { margin-bottom: 20px; }
                        .info-section h2 { color: #3498db; border-bottom: 1px solid #eee; padding-bottom: 5px; }
                        .row { display: flex; margin-bottom: 10px; }
                        .label { font-weight: bold; width: 200px; }
                        .value { flex: 1; }
                        .footer { margin-top: 50px; text-align: center; color: #7f8c8d; font-size: 12px; }
                        .signature { margin-top: 50px; border-top: 1px solid #333; padding-top: 20px; }
                        .signature-box { display: inline-block; width: 200px; text-align: center; margin: 0 20px; }
                        .approved { color: green; font-weight: bold; }
                        .pending { color: orange; font-weight: bold; }
                        .rejected { color: red; font-weight: bold; }
                    </style>
                </head>
                <body>
                    <div class="header">
                        <h1>تصريح دخول الشركة</h1>
                        <p>رقم التصريح: ${permit.permit_id}</p>
                        <p>تاريخ الطلب: ${new Date(permit.request_date).toLocaleDateString('ar-SA')}</p>
                    </div>
                    
                    <div class="info-section">
                        <h2>معلومات الشركة</h2>
                        <div class="row">
                            <div class="label">اسم الشركة:</div>
                            <div class="value">${permit.company_name}</div>
                        </div>
                        <div class="row">
                            <div class="label">الممثل القانوني:</div>
                            <div class="value">${permit.company_representative}</div>
                        </div>
                        <div class="row">
                            <div class="label">رقم الهاتف:</div>
                            <div class="value">${permit.representative_phone || 'غير محدد'}</div>
                        </div>
                        <div class="row">
                            <div class="label">الغرض من الدخول:</div>
                            <div class="value">${permit.entry_purpose}</div>
                        </div>
                    </div>
                    
                    <div class="info-section">
                        <h2>تفاصيل الزيارة</h2>
                        <div class="row">
                            <div class="label">تاريخ الدخول:</div>
                            <div class="value">${permit.expected_entry_date}</div>
                        </div>
                        <div class="row">
                            <div class="label">وقت الدخول:</div>
                            <div class="value">${permit.expected_entry_time}</div>
                        </div>
                        <div class="row">
                            <div class="label">تاريخ الخروج:</div>
                            <div class="value">${permit.expected_exit_date}</div>
                        </div>
                        <div class="row">
                            <div class="label">وقت الخروج:</div>
                            <div class="value">${permit.expected_exit_time}</div>
                        </div>
                        <div class="row">
                            <div class="label">عدد الزوار:</div>
                            <div class="value">${permit.number_of_visitors}</div>
                        </div>
                    </div>
                    
                    <div class="info-section">
                        <h2>حالة الموافقات</h2>
                        <div class="row">
                            <div class="label">حالة المدير:</div>
                            <div class="value ${permit.manager_status}">${permit.manager_status === 'approved' ? 'مقبول ✓' : permit.manager_status === 'rejected' ? 'مرفوض ✗' : 'قيد الانتظار'}</div>
                        </div>
                        ${permit.manager_username ? `
                        <div class="row">
                            <div class="label">مسؤول الموافقة:</div>
                            <div class="value">${permit.manager_username}</div>
                        </div>
                        ` : ''}
                        <div class="row">
                            <div class="label">حالة الأمن:</div>
                            <div class="value ${permit.security_status}">${permit.security_status === 'approved' ? 'مقبول ✓' : permit.security_status === 'rejected' ? 'مرفوض ✗' : 'قيد الانتظار'}</div>
                        </div>
                        ${permit.security_username ? `
                        <div class="row">
                            <div class="label">مسؤول الأمن:</div>
                            <div class="value">${permit.security_username}</div>
                        </div>
                        ` : ''}
                    </div>
                    
                    <div class="signature">
                        <div class="signature-box">
                            <p>توقيع مدير القسم</p>
                            <p>________________</p>
                        </div>
                        <div class="signature-box">
                            <p>توقيع مسؤول الأمن</p>
                            <p>________________</p>
                        </div>
                        <div class="signature-box">
                            <p>توقيع الحارس</p>
                            <p>________________</p>
                        </div>
                    </div>
                    
                    <div class="footer">
                        <p>© نظام تصاريح الشركات - ${new Date().getFullYear()}</p>
                        <p>هذه وثيقة رسمية - ${permit.permit_id}</p>
                    </div>
                </body>
                </html>
            `;
            
            res.setHeader('Content-Type', 'text/html');
            res.setHeader('Content-Disposition', `inline; filename="company-permit-${permit.permit_id}.html"`);
            res.send(htmlContent);
        });
        
    } catch (error) {
        console.error('❌ خطأ في توليد PDF:', error);
        res.status(500).send('حدث خطأ في توليد الوثيقة');
    }
});

// API للحصول على سجل التصاريح حسب الموظف
app.get('/api/permits/company-entry/history/:username', authenticateToken, (req, res) => {
    try {
        const { username } = req.params;
        const { limit = 20, offset = 0 } = req.query;
        
        console.log(`📜 جلب سجل تصاريح الشركات للموظف: ${username}`);
        
        // التحقق من صلاحية المستخدم
        if (req.user.username !== username && req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'غير مصرح لك بالوصول إلى سجل مستخدم آخر'
            });
        }
        
        const query = `
            SELECT * FROM company_entry_permits 
            WHERE employee_username = ?
            ORDER BY request_date DESC
            LIMIT ? OFFSET ?
        `;
        
        const countQuery = `SELECT COUNT(*) as total FROM company_entry_permits WHERE employee_username = ?`;
        
        db.get(countQuery, [username], (err, countResult) => {
            if (err) {
                console.error('❌ خطأ في عد التصاريح:', err);
                return res.status(500).json({
                    success: false,
                    message: 'حدث خطأ في الخادم'
                });
            }
            
            db.all(query, [username, parseInt(limit), parseInt(offset)], (err, permits) => {
                if (err) {
                    console.error('❌ خطأ في جلب سجل التصاريح:', err);
                    return res.status(500).json({
                        success: false,
                        message: 'حدث خطأ في الخادم'
                    });
                }
                
                res.json({
                    success: true,
                    permits: permits || [],
                    total: countResult ? countResult.total : 0,
                    limit: parseInt(limit),
                    offset: parseInt(offset)
                });
            });
        });
        
    } catch (error) {
        console.error('❌ خطأ في API سجل التصاريح:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في الخادم'
        });
    }
});

// API: إرسال إشعار للموظف بعد قرار المدير
app.post('/api/notifications/employee', authenticateToken, authorizeRoles('manager', 'admin'), (req, res) => {
    const { permit_id, action } = req.body;
    
    if (!permit_id || !action) {
        return res.status(400).json({
            success: false,
            message: 'بيانات غير مكتملة'
        });
    }
    
    db.get(`
        SELECT p.*, e.employee_id, e.full_name, e.username 
        FROM permits p
        JOIN employees e ON p.employee_id = e.employee_id
        WHERE p.permit_id = ?
    `, [permit_id], (err, permit) => {
        if (err || !permit) {
            console.error('خطأ في جلب بيانات التصريح:', err);
            return res.status(404).json({
                success: false,
                message: 'التصريح غير موجود'
            });
        }
        
        const title = action === 'approved' 
            ? '✅ تمت الموافقة على تصريحك من قبل المدير' 
            : '❌ تم رفض تصريحك من قبل المدير';
        
        const message = action === 'approved'
            ? 'قام المدير بالموافقة على طلب تصريحك. سيتم مراجعته الآن من قبل مكتب الأمن.'
            : 'قام المدير برفض طلب تصريحك. يرجى التواصل معه للحصول على مزيد من المعلومات.';
        
        createNotification({
            user_id: permit.employee_id,
            permit_id: permit_id,
            title: title,
            message: message,
            type: action === 'approved' ? 'success' : 'warning'
        });
        
        res.json({
            success: true,
            message: 'تم إرسال الإشعار للموظف بنجاح'
        });
    });
});

// API: إرسال إشعار للأمن عند وصول تصريح جديد
app.post('/api/notifications/security', authenticateToken, authorizeRoles('manager', 'admin'), (req, res) => {
    const { permit_id, type } = req.body;
    
    if (!permit_id) {
        return res.status(400).json({
            success: false,
            message: 'بيانات غير مكتملة'
        });
    }
    
    db.get(`
        SELECT p.*, e.full_name, e.job_number 
        FROM permits p
        JOIN employees e ON p.employee_id = e.employee_id
        WHERE p.permit_id = ?
    `, [permit_id], (err, permit) => {
        if (err || !permit) {
            console.error('خطأ في جلب بيانات التصريح:', err);
            return res.status(404).json({
                success: false,
                message: 'التصريح غير موجود'
            });
        }
        
        const title = '📋 تصريح جديد بانتظار الموافقة الأمنية';
        const message = `تصريح جديد للموظف ${permit.full_name} (${permit.job_number}) بانتظار الموافقة الأمنية.`;
        
        notifyAllSecurityUsers(permit_id, title, message, 'warning');
        
        res.json({
            success: true,
            message: 'تم إرسال الإشعار لجميع مسؤولي الأمن والحراس'
        });
    });
});

// API: إرسال إشعار للموظف بعد قرار الأمن
app.post('/api/notifications/employee-security', authenticateToken, authorizeRoles('security', 'admin'), (req, res) => {
    const { permit_id, decision } = req.body;
    
    if (!permit_id || !decision) {
        return res.status(400).json({
            success: false,
            message: 'بيانات غير مكتملة'
        });
    }
    
    db.get(`
        SELECT p.*, e.employee_id, e.full_name, e.username 
        FROM permits p
        JOIN employees e ON p.employee_id = e.employee_id
        WHERE p.permit_id = ?
    `, [permit_id], (err, permit) => {
        if (err || !permit) {
            console.error('خطأ في جلب بيانات التصريح:', err);
            return res.status(404).json({
                success: false,
                message: 'التصريح غير موجود'
            });
        }
        
        const title = decision === 'allow' 
            ? '✅ تمت الموافقة النهائية على تصريحك' 
            : '❌ تم رفض تصريحك من قبل الأمن';
        
        const message = decision === 'allow'
            ? 'تمت الموافقة النهائية على طلب تصريحك من قبل مكتب الأمن. يمكنك الآن العمل في الوقت المحدد.'
            : 'تم رفض طلب تصريحك من قبل مكتب الأمن. يرجى التواصل مع المدير للحصول على مزيد من المعلومات.';
        
        createNotification({
            user_id: permit.employee_id,
            permit_id: permit_id,
            title: title,
            message: message,
            type: decision === 'allow' ? 'success' : 'warning'
        });
        
        if (decision === 'allow') {
            db.get('SELECT employee_id FROM employees WHERE employee_id = (SELECT manager_id FROM employees WHERE employee_id = ?)', 
            [permit.employee_id], (err, manager) => {
                if (!err && manager) {
                    createNotification({
                        user_id: manager.employee_id,
                        permit_id: permit_id,
                        title: '✅ تمت الموافقة النهائية على تصريح أحد الموظفين',
                        message: `تمت الموافقة النهائية على تصريح الموظف ${permit.full_name} من قبل مكتب الأمن.`,
                        type: 'info'
                    });
                }
            });
        }
        
        res.json({
            success: true,
            message: 'تم إرسال الإشعار بنجاح'
        });
    });
});

// API: إرسال التصريح للأمن بعد موافقة المدير
app.post('/api/permits/send-to-security', authenticateToken, authorizeRoles('manager', 'admin'), (req, res) => {
    const { permit_id, manager_username } = req.body;
    
    if (!permit_id || !manager_username) {
        return res.status(400).json({
            success: false,
            message: 'بيانات غير مكتملة'
        });
    }
    
    // ✅ تحديث: التصريح يجب أن يكون بحالة pending_security (بعد موافقة المدير)
    db.get(`SELECT * FROM permits WHERE permit_id = ? AND status = 'pending_security'`, [permit_id], (err, permit) => {
        if (err) {
            console.error('خطأ في التحقق من التصريح:', err);
            return res.status(500).json({
                success: false,
                message: 'حدث خطأ في الخادم'
            });
        }
        
        if (!permit) {
            return res.status(400).json({
                success: false,
                message: 'التصريح لم يوافق عليه المدير بعد أو تم معالجته مسبقاً'
            });
        }
        
        const query = `UPDATE permits SET manager_decision_date = CURRENT_TIMESTAMP WHERE permit_id = ?`;
        
        db.run(query, [permit_id], function(err) {
            if (err) {
                console.error('خطأ في تحديث التصريح:', err);
                return res.status(500).json({
                    success: false,
                    message: 'حدث خطأ في الخادم'
                });
            }
            
            notifyAllSecurityUsers(
                permit_id,
                '📋 تصريح جديد بانتظار الموافقة الأمنية',
                `تصريح جديد للموظف ${permit.full_name} (${permit.job_number}) بانتظار الموافقة الأمنية.`,
                'warning'
            );
            
            res.json({
                success: true,
                message: 'تم إرسال التصريح إلى مكتب الأمن بنجاح'
            });
        });
    });
});

// API: عرض جميع الأقسام
app.get('/api/departments', authenticateToken, authorizeRoles('admin', 'manager'), (req, res) => {
    console.log('📍 GET /api/departments - Request received');
    const query = `
        SELECT d.id, d.name, d.type, d.manager_id, d.parent_id, d.created_at,
               e.full_name as manager_name
        FROM departments d
        LEFT JOIN employees e ON d.manager_id = e.employee_id
        ORDER BY d.id
    `;

    db.all(query, [], (err, rows) => {
        if (err) {
            console.error('❌ خطأ في جلب الأقسام:', err);
            return res.status(500).json({ success: false, message: 'حدث خطأ في الخادم' });
        }
        console.log('✅ تم إرسال الأقسام:', rows?.length || 0);
        res.json({ success: true, departments: rows || [] });
    });
});

// API: تعيين مدير لقسم
app.post('/api/departments/:id/set-manager', authenticateToken, authorizeRoles('admin'), (req, res) => {
    const deptId = req.params.id;
    const { manager_username } = req.body;

    if (!manager_username) {
        return res.status(400).json({ success: false, message: 'يرجى تزويد manager_username' });
    }

    db.get('SELECT employee_id FROM employees WHERE username = ?', [manager_username], (err, employee) => {
        if (err) return res.status(500).json({ success: false, message: 'خطأ في الخادم' });
        if (!employee) return res.status(404).json({ success: false, message: 'الموظف غير موجود' });

        db.run('UPDATE departments SET manager_id = ? WHERE id = ?', [employee.employee_id, deptId], function(err) {
            if (err) return res.status(500).json({ success: false, message: 'خطأ في تعيين المدير' });
            return res.json({ success: true, message: 'تم تعيين المدير للقسم' });
        });
    });
});

// API: تعيين قسم للموظف
app.post('/api/employees/:username/set-department', authenticateToken, authorizeRoles('admin'), (req, res) => {
    const username = req.params.username;
    const { department_id } = req.body;

    if (!department_id) {
        return res.status(400).json({ success: false, message: 'يرجى تزويد department_id' });
    }

    db.get('SELECT * FROM departments WHERE id = ?', [department_id], (err, dept) => {
        if (err) return res.status(500).json({ success: false, message: 'خطأ في الخادم' });
        if (!dept) return res.status(404).json({ success: false, message: 'القسم غير موجود' });

        db.run('UPDATE employees SET department_id = ? WHERE username = ?', [department_id, username], function(err) {
            if (err) return res.status(500).json({ success: false, message: 'خطأ في تحديث قسم الموظف' });
            if (this.changes === 0) return res.status(404).json({ success: false, message: 'الموظف غير موجود' });
            return res.json({ success: true, message: 'تم تعيين القسم للموظف' });
        });
    });
});

// API: الربط الديناميكي التلقائي للمسؤولين بالأقسام
app.post('/api/auto-assign-managers', authenticateToken, authorizeRoles('admin'), (req, res) => {
    console.log('📍 POST /api/auto-assign-managers - بدء الربط الديناميكي التلقائي');
    
    db.all(`
        SELECT employee_id, full_name, department_id
        FROM employees
        WHERE user_type = 'manager' OR username IN ('manager1', 'admin')
        ORDER BY employee_id
    `, [], (err, managers) => {
        if (err) {
            console.error('❌ خطأ في جلب المسؤولين:', err);
            return res.status(500).json({ success: false, message: 'خطأ في جلب بيانات المسؤولين' });
        }

        db.all(`
            SELECT id, name
            FROM departments
            WHERE manager_id IS NULL
            ORDER BY id
        `, [], (err, departmentsWithoutManagers) => {
            if (err) {
                console.error('❌ خطأ في جلب الأقسام:', err);
                return res.status(500).json({ success: false, message: 'خطأ في جلب بيانات الأقسام' });
            }

            if (managers.length === 0) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'لا توجد موظفين مسؤولين متاحين للربط' 
                });
            }

            if (departmentsWithoutManagers.length === 0) {
                return res.json({ 
                    success: true, 
                    message: 'جميع الأقسام لها مسؤولين بالفعل',
                    assigned: 0
                });
            }

            let assignedCount = 0;
            const updates = [];

            departmentsWithoutManagers.forEach((dept, index) => {
                const managerIndex = index % managers.length;
                const manager = managers[managerIndex];
                updates.push({
                    deptId: dept.id,
                    managerId: manager.employee_id,
                    deptName: dept.name,
                    managerName: manager.full_name
                });
            });

            db.serialize(() => {
                updates.forEach(update => {
                    db.run(
                        'UPDATE departments SET manager_id = ? WHERE id = ?',
                        [update.managerId, update.deptId],
                        function(err) {
                            if (err) {
                                console.error(`❌ خطأ في تعيين المدير للقسم ${update.deptId}:`, err);
                            } else {
                                assignedCount++;
                                console.log(`✅ تم تعيين ${update.managerName} لقسم ${update.deptName}`);
                            }
                        }
                    );
                });

                setTimeout(() => {
                    console.log(`✅ اكتمل الربط الديناميكي: تم تعيين ${assignedCount} قسم`);
                    res.json({
                        success: true,
                        message: `تم ربط ${assignedCount} قسم تلقائيًا بالمسؤولين`,
                        assigned: assignedCount,
                        total_departments: departmentsWithoutManagers.length
                    });
                }, 500);
            });
        });
    });
});

// API: إعادة تعيين جميع المسؤولين
app.post('/api/reassign-all-managers', authenticateToken, authorizeRoles('admin'), (req, res) => {
    console.log('📍 POST /api/reassign-all-managers - بدء إعادة تعيين جميع المسؤولين');
    
    db.run('UPDATE departments SET manager_id = NULL', [], (err) => {
        if (err) {
            console.error('❌ خطأ في حذف التعيينات:', err);
            return res.status(500).json({ success: false, message: 'خطأ في حذف التعيينات' });
        }

        db.all(`
            SELECT employee_id, full_name
            FROM employees
            WHERE user_type = 'manager' OR username IN ('manager1', 'admin')
            ORDER BY employee_id
        `, [], (err, managers) => {
            if (err) {
                console.error('❌ خطأ في جلب المسؤولين:', err);
                return res.status(500).json({ success: false, message: 'خطأ في جلب بيانات المسؤولين' });
            }

            db.all(`SELECT id, name FROM departments ORDER BY id`, [], (err, departments) => {
                if (err) {
                    console.error('❌ خطأ في جلب الأقسام:', err);
                    return res.status(500).json({ success: false, message: 'خطأ في جلب بيانات الأقسام' });
                }

                if (managers.length === 0 || departments.length === 0) {
                    return res.status(400).json({ 
                        success: false, 
                        message: 'لا توجد موظفين مسؤولين أو أقسام' 
                    });
                }

                let assignedCount = 0;
                db.serialize(() => {
                    departments.forEach((dept, index) => {
                        const managerIndex = index % managers.length;
                        const manager = managers[managerIndex];
                        
                        db.run(
                            'UPDATE departments SET manager_id = ? WHERE id = ?',
                            [manager.employee_id, dept.id],
                            function(err) {
                                if (!err) assignedCount++;
                            }
                        );
                    });

                    setTimeout(() => {
                        console.log(`✅ اكتملت إعادة التعيين: تم تعيين ${assignedCount} قسم`);
                        res.json({
                            success: true,
                            message: `تم إعادة تعيين جميع الأقسام (${assignedCount} قسم)`,
                            assigned: assignedCount
                        });
                    }, 500);
                });
            });
        });
    });
});

// API: إرسال التصريح للحارس بعد موافقة الأمن
app.post('/api/permits/send-to-guard', authenticateToken, authorizeRoles('security', 'admin'), (req, res) => {
    const { permit_id, security_username } = req.body;
    
    if (!permit_id || !security_username) {
        return res.status(400).json({
            success: false,
            message: 'بيانات غير مكتملة'
        });
    }
    
    console.log(`🚀 محاولة إرسال التصريح ${permit_id} للحارس بواسطة ${security_username}`);
    
    db.get(`
        SELECT p.*, e.full_name, e.job_number 
        FROM permits p
        JOIN employees e ON p.employee_id = e.employee_id
        WHERE p.permit_id = ? AND p.status = 'approved_security'
    `, [permit_id], (err, permit) => {
        if (err) {
            console.error('❌ خطأ في التحقق من التصريح:', err);
            return res.status(500).json({
                success: false,
                message: 'حدث خطأ في الخادم'
            });
        }
        
        if (!permit) {
            return res.status(400).json({
                success: false,
                message: 'التصريح لم يوافق عليه الأمن بعد أو غير موجود'
            });
        }
        
        console.log(`✅ تم إرسال التصريح ${permit_id} للحارس`);
        console.log(`📋 تفاصيل التصريح: ${permit.full_name} (${permit.job_number})`);
        
        notifyAllSecurityUsers(
            permit_id,
            '👤 تصريح جديد جاهز للتسجيل',
            `تصريح للموظف ${permit.full_name} (${permit.job_number}) جاهز للتسجيل بنقطة الحراسة.`,
            'info'
        );
        
        res.json({
            success: true,
            message: 'تم إرسال التصريح إلى نقطة الحراسة بنجاح',
            permit: {
                id: permit.permit_id,
                employee_name: permit.full_name,
                job_number: permit.job_number
            }
        });
    });
});

// API للحصول على جميع الموظفين (محمي)
app.get('/api/users/all', authenticateToken, authorizeRoles('admin'), (req, res) => {
    const query = `
        SELECT 
            employee_id,
            username,
            full_name,
            user_type,
            job_number,
            directorate,
            email,
            phone,
            is_active,
            created_at
        FROM employees 
        ORDER BY employee_id
    `;
    
    db.all(query, [], (err, users) => {
        if (err) {
            console.error('خطأ في جلب المستخدمين:', err);
            return res.status(500).json({
                success: false,
                message: 'حدث خطأ في الخادم'
            });
        }
        
        res.json({
            success: true,
            users: users || [],
            count: users ? users.length : 0
        });
    });
});

// API للحصول على إشعارات المستخدم
app.get('/api/notifications/:username', authenticateToken, (req, res) => {
    const { username } = req.params;
    
    // التحقق أن المستخدم يطلب إشعاراته فقط
    if (req.user.username !== username && req.user.role !== 'admin') {
        return res.status(403).json({
            success: false,
            message: 'غير مصرح لك بالوصول إلى إشعارات مستخدم آخر'
        });
    }
    
    // الحصول على employee_id من اسم المستخدم
    db.get('SELECT employee_id FROM employees WHERE username = ?', [username], (err, employee) => {
        if (err) {
            console.error('خطأ في البحث عن مستخدم:', err);
            return res.status(500).json({
                success: false,
                message: 'حدث خطأ في الخادم'
            });
        }
        
        if (!employee) {
            return res.json({
                success: true,
                notifications: [],
                unread_count: 0
            });
        }
        
        // استعلام مصحح: استخدام الأعمدة الصحيحة بناءً على الهيكل الجديد
        const query = `
            SELECT 
                n.*, 
                p.permit_id as permit_id,
                cep.permit_id as company_permit_id,
                COALESCE(p.status, cep.status) as permit_status,
                e.full_name as related_employee_name,
                n.type as notification_type
            FROM notifications n
            LEFT JOIN permits p ON n.permit_id = p.permit_id
            LEFT JOIN company_entry_permits cep ON n.company_permit_id = cep.permit_id
            LEFT JOIN employees e ON COALESCE(p.employee_id, cep.employee_id) = e.employee_id
            WHERE n.user_id = ?
            ORDER BY n.created_at DESC
            LIMIT 20
        `;
        
        // استعلام بديل أبسط (إذا استمر الخطأ)
        const simpleQuery = `
            SELECT 
                n.notification_id,
                n.user_id,
                n.permit_id,
                n.company_permit_id,
                n.title,
                n.message,
                n.type as notification_type,
                n.is_read,
                n.created_at
            FROM notifications n
            WHERE n.user_id = ?
            ORDER BY n.created_at DESC
            LIMIT 20
        `;
        
        db.all(simpleQuery, [employee.employee_id], (err, notifications) => {
            if (err) {
                console.error('خطأ في جلب الإشعارات:', err);
                // حاول باستخدام استعلام أبسط
                const fallbackQuery = `SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 20`;
                db.all(fallbackQuery, [employee.employee_id], (err2, simpleNotifications) => {
                    if (err2) {
                        return res.status(500).json({
                            success: false,
                            message: 'حدث خطأ في جلب الإشعارات: ' + err2.message
                        });
                    }
                    
                    const unreadQuery = `SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0`;
                    db.get(unreadQuery, [employee.employee_id], (err3, countResult) => {
                        res.json({
                            success: true,
                            notifications: simpleNotifications || [],
                            unread_count: countResult ? countResult.count : 0
                        });
                    });
                });
                return;
            }
            
            const unreadQuery = `SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0`;
            db.get(unreadQuery, [employee.employee_id], (err, countResult) => {
                if (err) {
                    return res.json({
                        success: true,
                        notifications: notifications || [],
                        unread_count: 0
                    });
                }
                
                res.json({
                    success: true,
                    notifications: notifications || [],
                    unread_count: countResult ? countResult.count : 0
                });
            });
        });
    });
});

// API لتحديد الإشعار كمقروء
app.post('/api/notifications/mark-read', authenticateToken, (req, res) => {
    const { notification_id, username } = req.body;
    
    if (!notification_id || !username) {
        return res.status(400).json({
            success: false,
            message: 'بيانات غير مكتملة'
        });
    }
    
    if (req.user.username !== username && req.user.role !== 'admin') {
        return res.status(403).json({
            success: false,
            message: 'غير مصرح لك بتحديث إشعارات مستخدم آخر'
        });
    }
    
    db.get('SELECT employee_id FROM employees WHERE username = ?', [username], (err, employee) => {
        if (err || !employee) {
            return res.status(404).json({
                success: false,
                message: 'المستخدم غير موجود'
            });
        }
        
        const query = `UPDATE notifications SET is_read = 1 WHERE notification_id = ? AND user_id = ?`;
        
        db.run(query, [notification_id, employee.employee_id], function(err) {
            if (err) {
                console.error('خطأ في تحديث الإشعار:', err);
                return res.status(500).json({
                    success: false,
                    message: 'حدث خطأ في الخادم'
                });
            }
            
            res.json({
                success: true,
                message: 'تم تحديث حالة الإشعار'
            });
        });
    });
});

// API لتحديد جميع الإشعارات كمقروءة
app.post('/api/notifications/mark-all-read', authenticateToken, (req, res) => {
    const { username } = req.body;
    
    if (!username) {
        return res.status(400).json({
            success: false,
            message: 'بيانات غير مكتملة'
        });
    }
    
    if (req.user.username !== username && req.user.role !== 'admin') {
        return res.status(403).json({
            success: false,
            message: 'غير مصرح لك بتحديث إشعارات مستخدم آخر'
        });
    }
    
    db.get('SELECT employee_id FROM employees WHERE username = ?', [username], (err, employee) => {
        if (err || !employee) {
            return res.status(404).json({
                success: false,
                message: 'المستخدم غير موجود'
            });
        }
        
        const query = `UPDATE notifications SET is_read = 1 WHERE user_id = ?`;
        
        db.run(query, [employee.employee_id], function(err) {
            if (err) {
                console.error('خطأ في تحديث الإشعارات:', err);
                return res.status(500).json({
                    success: false,
                    message: 'حدث خطأ في الخادم'
                });
            }
            
            res.json({
                success: true,
                message: 'تم تحديث جميع الإشعارات'
            });
        });
    });
});

// API للموافقة على التصريح من قبل المدير
app.post('/api/permits/manager-approve', authenticateToken, authorizeRoles('manager', 'admin'), (req, res) => {
    console.log('🔄 ========== طلب موافقة المدير ==========');
    console.log('📥 البيانات المستلمة:', JSON.stringify(req.body, null, 2));
    console.log('👤 مدير النظام:', req.body.manager_username);
    console.log('#️⃣ رقم التصريح:', req.body.permit_id);
    console.log('✅ القرار:', req.body.decision);
    
    const { permit_id, manager_username, decision, notes } = req.body;
    
    if (!permit_id || !manager_username || !decision) {
        console.log('❌ بيانات ناقصة!');
        return res.status(400).json({
            success: false,
            message: 'بيانات ناقصة: permit_id, manager_username, decision مطلوبة'
        });
    }
    
    // ✅ إصلاح: عند الموافقة تصبح الحالة pending_security (ليس approved_manager)
    const status = decision === 'approve' ? 'pending_security' : 'rejected_manager';
    console.log(`🔄 تحديث حالة التصريح إلى: ${status}`);
    
    const query = `
        UPDATE permits 
        SET status = ?, 
            manager_decision = ?,
            manager_decision_date = CURRENT_TIMESTAMP,
            manager_notes = ?,
            manager_username = ?
        WHERE permit_id = ? AND status = 'pending_manager'
    `;
    
    const params = [status, decision, notes || '', manager_username, permit_id];
    
    console.log('📝 تنفيذ الاستعلام:', query);
    console.log('🔢 المعاملات:', params);
    
    db.run(query, params, function(err) {
        if (err) {
            console.error('❌ خطأ في تحديث التصريح:', err.message);
            console.error('❌ تفاصيل الخطأ:', err.stack);
            return res.status(500).json({
                success: false,
                message: 'حدث خطأ في الخادم: ' + err.message
            });
        }
        
        console.log('✅ عدد الصفوف المتأثرة:', this.changes);
        
        if (this.changes === 0) {
            return res.status(404).json({
                success: false,
                message: 'التصريح غير موجود أو تم معالجته مسبقاً'
            });
        }
        
        if (decision === 'approve') {
            // ✅ إرسال إشعار لمكتب الأمن (وليس الحراس) عند موافقة المدير
            db.get(`
                SELECT p.*, e.full_name, e.job_number, e.employee_id
                FROM permits p
                JOIN employees e ON p.employee_id = e.employee_id
                WHERE p.permit_id = ?
            `, [permit_id], (err, permit) => {
                if (!err && permit) {
                    const title = '📋 تصريح جديد بانتظار الموافقة الأمنية';
                    const message = `تصريح للموظف ${permit.full_name} (${permit.job_number}) بانتظار الموافقة الأمنية.`;
                    
                    // ✅ إشعار لمكتب الأمن فقط (وليس الحراس)
                    notifyAllSecurityStaff(permit_id, title, message, 'warning');
                }
            });
        } else {
            // ✅ إرسال إشعار للموظف عند رفض المدير
            db.get(`
                SELECT p.*, e.full_name, e.employee_id
                FROM permits p
                JOIN employees e ON p.employee_id = e.employee_id
                WHERE p.permit_id = ?
            `, [permit_id], (err, permit) => {
                if (!err && permit) {
                    createNotification({
                        user_id: permit.employee_id,
                        permit_id: permit_id,
                        title: '❌ تم رفض طلب التصريح',
                        message: `تم رفض طلب التصريح الخاص بك من قبل المدير.${notes ? ' ملاحظات: ' + notes : ''}`,
                        type: 'error'
                    });
                }
            });
        }
        
        console.log('✅ تمت العملية بنجاح');
        
        res.json({
            success: true,
            message: decision === 'approve' 
                ? 'تمت الموافقة على التصريح وتم إرساله لمكتب الأمن' 
                : 'تم رفض التصريح'
        });
    });
});

// API للموافقة على التصريح من قبل الأمن
app.post('/api/permits/security-approve', authenticateToken, authorizeRoles('security', 'admin'), (req, res) => {
    const { permit_id, security_username, decision, notes } = req.body;
    
    if (!permit_id || !security_username || !decision) {
        return res.status(400).json({
            success: false,
            message: 'بيانات غير مكتملة'
        });
    }
    
    // ✅ إصلاح: الأمن يوافق على التصاريح بحالة pending_security (ليس approved_manager)
    const status = decision === 'allow' ? 'approved_security' : 'rejected_security';
    const query = `
        UPDATE permits 
        SET status = ?, 
            security_decision = ?,
            security_decision_date = CURRENT_TIMESTAMP,
            security_notes = ?,
            security_username = ?
        WHERE permit_id = ? AND status = 'pending_security'
    `;
    
    db.run(query, [status, decision, notes || '', security_username, permit_id], function(err) {
        if (err) {
            console.error('خطأ في تحديث التصريح:', err);
            return res.status(500).json({
                success: false,
                message: 'حدث خطأ في الخادم'
            });
        }
        
        if (this.changes === 0) {
            return res.status(404).json({
                success: false,
                message: 'التصريح غير موجود أو لم يوافق عليه المدير بعد'
            });
        }
        
        // ✅ إرسال إشعارات عند موافقة/رفض الأمن
        db.get(`
            SELECT p.*, e.full_name, e.job_number, e.employee_id
            FROM permits p
            JOIN employees e ON p.employee_id = e.employee_id
            WHERE p.permit_id = ?
        `, [permit_id], (err, permit) => {
            if (!err && permit) {
                if (decision === 'allow') {
                    // ✅ إشعار للموظف عند الموافقة
                    createNotification({
                        user_id: permit.employee_id,
                        permit_id: permit_id,
                        title: '✅ تمت الموافقة على التصريح',
                        message: `تمت الموافقة على تصريحك من قبل مكتب الأمن. يمكنك الآن تسجيل الدخول عند الحارس.${notes ? ' ملاحظات: ' + notes : ''}`,
                        type: 'success'
                    });
                    
                    // ✅ إشعار لجميع الحراس فقط (وليس مسؤولي الأمن) عند الموافقة
                    notifyAllGuards(
                        permit_id,
                        '📋 تصريح جديد جاهز للحراسة',
                        `تصريح جديد للموظف ${permit.full_name} (${permit.job_number}) جاهز لتسجيل الدخول.`,
                        'info'
                    );
                } else {
                    // ✅ إشعار للموظف عند الرفض
                    createNotification({
                        user_id: permit.employee_id,
                        permit_id: permit_id,
                        title: '❌ تم رفض التصريح من قبل الأمن',
                        message: `تم رفض تصريحك من قبل مكتب الأمن.${notes ? ' ملاحظات: ' + notes : ''}`,
                        type: 'error'
                    });
                }
            }
        });
        
        res.json({
            success: true,
            message: decision === 'allow' 
                ? 'تمت الموافقة على التصريح وتم إرساله للحارس' 
                : 'تم رفض التصريح'
        });
    });
});

// API للحصول على تصاريح الموظف
app.get('/api/permits/my/:username', authenticateToken, (req, res) => {
    const { username } = req.params;
    
    if (req.user.username !== username && req.user.role !== 'admin') {
        return res.status(403).json({
            success: false,
            message: 'غير مصرح لك بالوصول إلى تصاريح مستخدم آخر'
        });
    }
    
    db.get('SELECT employee_id FROM employees WHERE username = ?', [username], (err, employee) => {
        if (err || !employee) {
            return res.status(404).json({
                success: false,
                message: 'الموظف غير موجود'
            });
        }
        
        const query = `
            SELECT 
                p.*, 
                e.full_name, 
                e.job_number, 
                e.directorate,
                d.name as department_name,
                m.full_name as manager_name
            FROM permits p
            JOIN employees e ON p.employee_id = e.employee_id
            LEFT JOIN departments d ON e.department_id = d.id
            LEFT JOIN employees m ON e.manager_id = m.employee_id
            WHERE p.employee_id = ?
            ORDER BY p.request_date DESC
        `;
        
        db.all(query, [employee.employee_id], (err, permits) => {
            if (err) {
                console.error('خطأ في جلب التصاريح:', err);
                return res.status(500).json({
                    success: false,
                    message: 'حدث خطأ في الخادم'
                });
            }
            
            res.json({
                success: true,
                permits: permits || []
            });
        });
    });
});

// API للحصول على التصاريح المعلقة للمدير
app.get('/api/permits/pending/:managerUsername', authenticateToken, authorizeRoles('manager', 'admin'), (req, res) => {
    const { managerUsername } = req.params;
    
    db.get('SELECT employee_id FROM employees WHERE username = ?', [managerUsername], (err, manager) => {
        if (err || !manager) {
            return res.status(404).json({
                success: false,
                message: 'المدير غير موجود'
            });
        }
        
        const query = `
            SELECT 
                p.*, 
                e.full_name, 
                e.job_number, 
                e.directorate, 
                d.name as department_name,
                e.phone,
                e.email
            FROM permits p
            JOIN employees e ON p.employee_id = e.employee_id
            LEFT JOIN departments d ON e.department_id = d.id
            WHERE e.manager_id = ?
            AND p.status = 'pending_manager'
            ORDER BY p.request_date ASC
        `;
        
        db.all(query, [manager.employee_id], (err, permits) => {
            if (err) {
                console.error('خطأ في جلب التصاريح المعلقة:', err);
                return res.status(500).json({
                    success: false,
                    message: 'حدث خطأ في الخادم'
                });
            }
            
            res.json({
                success: true,
                permits: permits || []
            });
        });
    });
});

// API للحصول على التصاريح المعتمدة من المدير
app.get('/api/permits/approved/:managerUsername', authenticateToken, authorizeRoles('manager', 'admin'), (req, res) => {
    const { managerUsername } = req.params;
    
    db.get('SELECT employee_id FROM employees WHERE username = ?', [managerUsername], (err, manager) => {
        if (err || !manager) {
            return res.status(404).json({
                success: false,
                message: 'المدير غير موجود'
            });
        }
        
        const query = `
            SELECT 
                p.*, 
                e.full_name, 
                e.job_number, 
                e.directorate, 
                d.name as department_name,
                e.phone,
                e.email
            FROM permits p
            JOIN employees e ON p.employee_id = e.employee_id
            LEFT JOIN departments d ON e.department_id = d.id
            WHERE e.manager_id = ?
            AND p.status IN ('approved_manager', 'pending_security', 'approved_security')
            ORDER BY p.request_date DESC
            LIMIT 10
        `;
        
        db.all(query, [manager.employee_id], (err, permits) => {
            if (err) {
                console.error('خطأ في جلب التصاريح المعتمدة:', err);
                return res.status(500).json({
                    success: false,
                    message: 'حدث خطأ في الخادم'
                });
            }
            
            res.json({
                success: true,
                permits: permits || []
            });
        });
    });
});

// API للحصول على التصاريح المعلقة للأمن
app.get('/api/permits/security-pending', authenticateToken, authorizeRoles('security', 'admin'), (req, res) => {
    const query = `
        SELECT 
            p.*, 
            e.full_name, 
            e.job_number, 
            e.directorate, 
            d.name as department_name,
            e.phone, 
            e.email,
            m.full_name as manager_name
        FROM permits p
        JOIN employees e ON p.employee_id = e.employee_id
        LEFT JOIN departments d ON e.department_id = d.id
        LEFT JOIN employees m ON e.manager_id = m.employee_id
        WHERE p.status = 'pending_security'
        ORDER BY p.request_date ASC
    `;
    
    db.all(query, [], (err, permits) => {
        if (err) {
            console.error('خطأ في جلب تصاريح الأمن:', err);
            return res.status(500).json({
                success: false,
                message: 'حدث خطأ في الخادم'
            });
        }
        
        res.json({
            success: true,
            permits: permits || []
        });
    });
});

// API للحصول على إحصائيات النظام
app.get('/api/stats/:username', authenticateToken, (req, res) => {
    const { username } = req.params;
    
    if (req.user.username !== username && req.user.role !== 'admin') {
        return res.status(403).json({
            success: false,
            message: 'غير مصرح لك بالوصول إلى إحصائيات مستخدم آخر'
        });
    }
    
    db.get('SELECT user_type, employee_id FROM employees WHERE username = ?', [username], (err, user) => {
        if (err || !user) {
            return res.json({
                success: true,
                stats: {
                    pending_requests: 0,
                    active_passes: 0,
                    today_approved: 0,
                    today_rejected: 0
                }
            });
        }
        
        const today = new Date().toISOString().split('T')[0];
        
        let statsQuery = '';
        let params = [];
        
        if (user.user_type === 'manager') {
            statsQuery = `
                SELECT 
                    (SELECT COUNT(*) FROM permits p 
                     JOIN employees e ON p.employee_id = e.employee_id 
                     WHERE e.manager_id = ? AND p.status = 'pending_manager') as pending_requests,
                    (SELECT COUNT(*) FROM permits p 
                     JOIN employees e ON p.employee_id = e.employee_id 
                     WHERE e.manager_id = ? AND p.status = 'pending_security' 
                     AND DATE(p.manager_decision_date) = ?) as today_approved,
                    (SELECT COUNT(*) FROM permits p 
                     JOIN employees e ON p.employee_id = e.employee_id 
                     WHERE e.manager_id = ? AND p.status = 'rejected_manager' 
                     AND DATE(p.manager_decision_date) = ?) as today_rejected,
                    (SELECT COUNT(*) FROM permits p 
                     JOIN employees e ON p.employee_id = e.employee_id 
                     WHERE e.manager_id = ? AND p.status = 'approved_security'
                     AND DATE(p.start_date) <= DATE(?) AND DATE(p.end_date) >= DATE(?)) as active_passes
            `;
            params = [user.employee_id, user.employee_id, today, user.employee_id, today, user.employee_id, today, today];
        } else if (user.user_type === 'security' || user.user_type === 'security_guard') {
            statsQuery = `
                SELECT 
                    (SELECT COUNT(*) FROM permits WHERE status = 'pending_security') as pending_requests,
                    (SELECT COUNT(*) FROM permits WHERE status = 'approved_security' 
                     AND DATE(start_date) <= DATE(?) AND DATE(end_date) >= DATE(?)) as active_passes,
                    (SELECT COUNT(*) FROM permits WHERE status = 'approved_security' 
                     AND DATE(security_decision_date) = ?) as today_approved,
                    (SELECT COUNT(*) FROM permits WHERE status = 'rejected_security' 
                     AND DATE(security_decision_date) = ?) as today_rejected
            `;
            params = [today, today, today, today];
        } else {
            statsQuery = `
                SELECT 
                    (SELECT COUNT(*) FROM permits WHERE employee_id = ? AND status = 'pending_manager') as pending_requests,
                    (SELECT COUNT(*) FROM permits WHERE employee_id = ? AND status = 'approved_security' 
                     AND DATE(start_date) <= DATE(?) AND DATE(end_date) >= DATE(?)) as active_passes,
                    (SELECT COUNT(*) FROM permits WHERE employee_id = ? 
                     AND status = 'approved_security' 
                     AND DATE(request_date) = ?) as today_approved,
                    (SELECT COUNT(*) FROM permits WHERE employee_id = ? 
                     AND (status = 'rejected_manager' OR status = 'rejected_security') 
                     AND DATE(request_date) = ?) as today_rejected
            `;
            params = [user.employee_id, user.employee_id, today, today, user.employee_id, today, user.employee_id, today];
        }
        
        db.get(statsQuery, params, (err, stats) => {
            if (err) {
                console.error('خطأ في جلب الإحصائيات:', err);
                return res.json({
                    success: true,
                    stats: {
                        pending_requests: 0,
                        active_passes: 0,
                        today_approved: 0,
                        today_rejected: 0
                    }
                });
            }
            
            res.json({
                success: true,
                stats: stats || {
                    pending_requests: 0,
                    active_passes: 0,
                    today_approved: 0,
                    today_rejected: 0
                }
            });
        });
    });
});

// API للبحث عن تصاريح
app.get('/api/permits/search', authenticateToken, (req, res) => {
    const { q, type } = req.query;
    
    if (!q && !type) {
        const query = `
            SELECT 
                p.*, 
                e.full_name, 
                e.job_number, 
                e.directorate, 
                d.name as department_name
            FROM permits p
            JOIN employees e ON p.employee_id = e.employee_id
            LEFT JOIN departments d ON e.department_id = d.id
            WHERE p.status IN ('approved_manager', 'approved_security', 'rejected_manager', 'rejected_security')
            ORDER BY p.request_date DESC
            LIMIT 10
        `;
        
        db.all(query, [], (err, permits) => {
            if (err) {
                console.error('خطأ في البحث:', err);
                return res.status(500).json({
                    success: false,
                    message: 'حدث خطأ في الخادم'
                });
            }
            
            res.json({
                success: true,
                permits: permits || []
            });
        });
        return;
    }
    
    let query = '';
    let params = [`%${q}%`, `%${q}%`, `%${q}%`];
    
    if (type === 'security') {
        query = `
            SELECT 
                p.*, 
                e.full_name, 
                e.job_number, 
                e.directorate, 
                d.name as department_name
            FROM permits p
            JOIN employees e ON p.employee_id = e.employee_id
            LEFT JOIN departments d ON e.department_id = d.id
            WHERE (e.full_name LIKE ? OR e.job_number LIKE ? OR p.permit_id LIKE ?)
            AND p.status IN ('approved_manager', 'approved_security')
            ORDER BY p.request_date DESC
            LIMIT 20
        `;
    } else if (type === 'recent') {
        query = `
            SELECT 
                p.*, 
                e.full_name, 
                e.job_number, 
                e.directorate, 
                d.name as department_name
            FROM permits p
            JOIN employees e ON p.employee_id = e.employee_id
            LEFT JOIN departments d ON e.department_id = d.id
            WHERE p.status IN ('approved_manager', 'approved_security', 'rejected_manager', 'rejected_security')
            ORDER BY p.request_date DESC
            LIMIT 10
        `;
        params = [];
    } else {
        query = `
            SELECT 
                p.*, 
                e.full_name, 
                e.job_number, 
                e.directorate, 
                d.name as department_name
            FROM permits p
            JOIN employees e ON p.employee_id = e.employee_id
            LEFT JOIN departments d ON e.department_id = d.id
            WHERE e.full_name LIKE ? OR e.job_number LIKE ? OR p.permit_id LIKE ?
            ORDER BY p.request_date DESC
            LIMIT 20
        `;
    }
    
    db.all(query, params, (err, permits) => {
        if (err) {
            console.error('خطأ في البحث:', err);
            return res.status(500).json({
                success: false,
                message: 'حدث خطأ في الخادم'
            });
        }
        
        res.json({
            success: true,
            permits: permits || []
        });
    });
});

// API للحصول على التصاريح النشطة حالياً
app.get('/api/permits/active', authenticateToken, authorizeRoles('security', 'admin', 'manager', 'security_guard'), (req, res) => {
    const today = new Date().toISOString().split('T')[0];
    
    const query = `
        SELECT 
            p.*, 
            e.full_name, 
            e.job_number, 
            e.directorate, 
            d.name as department_name,
            e.phone
        FROM permits p
        JOIN employees e ON p.employee_id = e.employee_id
        LEFT JOIN departments d ON e.department_id = d.id
        WHERE p.status = 'approved_security'
        AND DATE(p.start_date) <= DATE(?)
        AND DATE(p.end_date) >= DATE(?)
        AND (p.actual_exit_time IS NULL OR p.actual_exit_time = '')
        ORDER BY p.expected_exit_time ASC
    `;
    
    db.all(query, [today, today], (err, permits) => {
        if (err) {
            console.error('خطأ في جلب التصاريح النشطة:', err);
            return res.status(500).json({
                success: false,
                message: 'حدث خطأ في الخادم'
            });
        }
        
        res.json({
            success: true,
            permits: permits || [],
            count: permits ? permits.length : 0
        });
    });
});

// API لإنهاء التصريح مبكراً
app.post('/api/permits/end-early', authenticateToken, authorizeRoles('security', 'admin'), (req, res) => {
    const { permit_id, actual_exit_time } = req.body;
    
    if (!permit_id || !actual_exit_time) {
        return res.status(400).json({
            success: false,
            message: 'بيانات غير مكتملة'
        });
    }
    
    if (!/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/.test(actual_exit_time)) {
        return res.status(400).json({
            success: false,
            message: 'تنسيق الوقت غير صحيح. استخدم الصيغة HH:MM'
        });
    }
    
    const query = `
        UPDATE permits 
        SET actual_exit_time = ?
        WHERE permit_id = ? AND status = 'approved_security'
    `;
    
    db.run(query, [actual_exit_time, permit_id], function(err) {
        if (err) {
            console.error('خطأ في إنهاء التصريح:', err);
            return res.status(500).json({
                success: false,
                message: 'حدث خطأ في الخادم'
            });
        }
        
        if (this.changes === 0) {
            return res.status(404).json({
                success: false,
                message: 'التصريح غير موجود أو غير نشط'
            });
        }
        
        db.get(`
            SELECT e.employee_id, e.full_name 
            FROM permits p
            JOIN employees e ON p.employee_id = e.employee_id
            WHERE p.permit_id = ?
        `, [permit_id], (err, result) => {
            if (!err && result) {
                createNotification({
                    user_id: result.employee_id,
                    permit_id: permit_id,
                    title: '🕒 تم تسجيل وقت الانصراف',
                    message: `تم تسجيل وقت انصرافك الفعلي: ${actual_exit_time}`,
                    type: 'info'
                });
            }
        });
        
        res.json({
            success: true,
            message: 'تم تسجيل وقت الانصراف بنجاح'
        });
    });
});

// API للحصول على التصاريح المعتمدة من الأمن (جاهزة للتسجيل)
app.get('/api/permits/guard-approved', authenticateToken, 
    authorizeRoles('security', 'security_guard', 'admin'), (req, res) => {
    const today = new Date().toISOString().split('T')[0];
    
    const query = `
        SELECT 
            p.*, 
            e.full_name, 
            e.job_number, 
            e.directorate, 
            d.name as department_name,
            e.phone,
            e.email
        FROM permits p
        JOIN employees e ON p.employee_id = e.employee_id
        LEFT JOIN departments d ON e.department_id = d.id
        WHERE p.status = 'approved_security'
        AND DATE(p.start_date) <= DATE(?)
        AND DATE(p.end_date) >= DATE(?)
        AND p.actual_entry_time IS NULL
        ORDER BY p.request_date ASC
    `;
    
    db.all(query, [today, today], (err, permits) => {
        if (err) {
            console.error('خطأ في جلب التصاريح المعتمدة:', err);
            return res.status(500).json({
                success: false,
                message: 'حدث خطأ في الخادم'
            });
        }
        
        res.json({
            success: true,
            permits: permits || [],
            count: permits ? permits.length : 0
        });
    });
});

// API لتسجيل دخول الموظف
app.post('/api/permits/guard-checkin', authenticateToken, 
    authorizeRoles('security', 'security_guard', 'admin'), (req, res) => {
    const { 
        permit_id, 
        guard_username, 
        actual_entry_time, 
        entry_notes 
    } = req.body;
    
    if (!permit_id || !guard_username || !actual_entry_time) {
        return res.status(400).json({
            success: false,
            message: 'بيانات غير مكتملة'
        });
    }
    
    if (!/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/.test(actual_entry_time)) {
        return res.status(400).json({
            success: false,
            message: 'تنسيق الوقت غير صحيح. استخدم الصيغة HH:MM'
        });
    }
    
    db.get(`
        SELECT status, employee_id 
        FROM permits 
        WHERE permit_id = ? AND status = 'approved_security'
    `, [permit_id], (err, permit) => {
        if (err) {
            console.error('خطأ في التحقق من التصريح:', err);
            return res.status(500).json({
                success: false,
                message: 'حدث خطأ في الخادم'
            });
        }
        
        if (!permit) {
            return res.status(404).json({
                success: false,
                message: 'التصريح غير موجود أو غير جاهز للتسجيل'
            });
        }
        
        const query = `
            UPDATE permits 
            SET status = 'checked_in',
                actual_entry_time = ?,
                entry_guard_username = ?,
                entry_notes = ?,
                checkin_timestamp = CURRENT_TIMESTAMP
            WHERE permit_id = ?
        `;
        
        db.run(query, [actual_entry_time, guard_username, entry_notes || '', permit_id], function(err) {
            if (err) {
                console.error('خطأ في تسجيل الدخول:', err);
                return res.status(500).json({
                    success: false,
                    message: 'حدث خطأ في الخادم'
                });
            }
            
            createNotification({
                user_id: permit.employee_id,
                permit_id: permit_id,
                title: '👤 تم تسجيل دخولك',
                message: `تم تسجيل دخولك بنقطة الحراسة في الساعة ${actual_entry_time}`,
                type: 'success'
            });
            
            db.get(`
                SELECT m.employee_id as manager_id
                FROM employees e
                LEFT JOIN employees m ON e.manager_id = m.employee_id
                WHERE e.employee_id = ?
            `, [permit.employee_id], (err, result) => {
                if (!err && result && result.manager_id) {
                    createNotification({
                        user_id: result.manager_id,
                        permit_id: permit_id,
                        title: '👤 تسجيل دخول موظف',
                        message: `تم تسجيل دخول أحد موظفيك بنقطة الحراسة`,
                        type: 'info'
                    });
                }
            });
            
            res.json({
                success: true,
                message: 'تم تسجيل الدخول بنجاح'
            });
        });
    });
});

// API لتسجيل خروج الموظف
app.post('/api/permits/guard-checkout', authenticateToken, 
    authorizeRoles('security', 'security_guard', 'admin'), (req, res) => {
    const { 
        permit_id, 
        guard_username, 
        actual_exit_time, 
        exit_notes 
    } = req.body;
    
    if (!permit_id || !guard_username || !actual_exit_time) {
        return res.status(400).json({
            success: false,
            message: 'بيانات غير مكتملة'
        });
    }
    
    if (!/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/.test(actual_exit_time)) {
        return res.status(400).json({
            success: false,
            message: 'تنسيق الوقت غير صحيح. استخدم الصيغة HH:MM'
        });
    }
    
    db.get(`
        SELECT status, employee_id, actual_entry_time, expected_exit_time
        FROM permits 
        WHERE permit_id = ? AND status = 'checked_in'
    `, [permit_id], (err, permit) => {
        if (err) {
            console.error('خطأ في التحقق من التصريح:', err);
            return res.status(500).json({
                success: false,
                message: 'حدث خطأ في الخادم'
            });
        }
        
        if (!permit) {
            return res.status(404).json({
                success: false,
                message: 'التصريح غير موجود أو الموظف لم يسجل دخول بعد'
            });
        }
        
        const query = `
            UPDATE permits 
            SET status = 'completed',
                actual_exit_time = ?,
                exit_guard_username = ?,
                exit_notes = ?,
                checkout_timestamp = CURRENT_TIMESTAMP
            WHERE permit_id = ?
        `;
        
        db.run(query, [actual_exit_time, guard_username, exit_notes || '', permit_id], function(err) {
            if (err) {
                console.error('خطأ في تسجيل الخروج:', err);
                return res.status(500).json({
                    success: false,
                    message: 'حدث خطأ في الخادم'
                });
            }
            
            const expectedTime = new Date(`2000-01-01T${permit.expected_exit_time}`);
            const actualTime = new Date(`2000-01-01T${actual_exit_time}`);
            const diffMinutes = (actualTime - expectedTime) / (1000 * 60);
            
            let notificationMessage = `تم تسجيل خروجك بنقطة الحراسة في الساعة ${actual_exit_time}`;
            if (diffMinutes > 15) {
                notificationMessage += ` (تأخر ${Math.abs(diffMinutes)} دقيقة)`;
            } else if (diffMinutes < -15) {
                notificationMessage += ` (خرجت مبكراً ${Math.abs(diffMinutes)} دقيقة)`;
            }
            
            createNotification({
                user_id: permit.employee_id,
                permit_id: permit_id,
                title: '🚪 تم تسجيل خروجك',
                message: notificationMessage,
                type: 'success'
            });
            
            // إرسال إشعار للمدير
            db.get(`
                SELECT m.employee_id as manager_id
                FROM employees e
                LEFT JOIN employees m ON e.manager_id = m.employee_id
                WHERE e.employee_id = ?
            `, [permit.employee_id], (err, result) => {
                if (!err && result && result.manager_id) {
                    createNotification({
                        user_id: result.manager_id,
                        permit_id: permit_id,
                        title: '🚪 تسجيل خروج موظف',
                        message: `تم تسجيل خروج أحد موظفيك بنقطة الحراسة`,
                        type: 'info'
                    });
                }
            });
            
            // إرسال إشعار لمكتب الأمن باسم الحارس المناوب وتوقيت الخروج
            notifyAllSecurityStaff(
                permit_id,
                '🚪 تسجيل خروج موظف',
                `تم تسجيل خروج موظف بنقطة الحراسة.\nالحارس المناوب: ${guard_username}\nوقت الخروج: ${actual_exit_time}${exit_notes ? '\nملاحظات: ' + exit_notes : ''}`,
                'info'
            );
            
            if (diffMinutes > 30) {
                db.run(`
                    INSERT INTO time_violations (permit_id, employee_id, violation_type, expected_time, actual_time, time_difference, severity)
                    VALUES (?, ?, 'late_checkout', ?, ?, ?, 'medium')
                `, [permit_id, permit.employee_id, permit.expected_exit_time, actual_exit_time, diffMinutes]);
                
                notifyAllSecurityUsers(
                    permit_id,
                    '⚠️ تأخر في الخروج',
                    `موظف تأخر في الخروج ${Math.round(diffMinutes)} دقيقة`,
                    'warning'
                );
            }
            
            res.json({
                success: true,
                message: 'تم تسجيل الخروج بنجاح'
            });
        });
    });
});

// API للحصول على التصاريح المسجلة دخول (داخل المبنى)
app.get('/api/permits/guard-checked-in', authenticateToken, 
    authorizeRoles('security', 'security_guard', 'admin'), (req, res) => {
    const today = new Date().toISOString().split('T')[0];
    
    const query = `
        SELECT 
            p.*, 
            e.full_name, 
            e.job_number, 
            e.directorate, 
            d.name as department_name,
            e.phone
        FROM permits p
        JOIN employees e ON p.employee_id = e.employee_id
        LEFT JOIN departments d ON e.department_id = d.id
        WHERE p.status = 'checked_in'
        AND DATE(p.start_date) <= DATE(?)
        AND DATE(p.end_date) >= DATE(?)
        ORDER BY p.actual_entry_time DESC
    `;
    
    db.all(query, [today, today], (err, permits) => {
        if (err) {
            console.error('خطأ في جلب التصاريح المسجلة:', err);
            return res.status(500).json({
                success: false,
                message: 'حدث خطأ في الخادم'
            });
        }
        
        res.json({
            success: true,
            permits: permits || [],
            count: permits ? permits.length : 0
        });
    });
});

// API للحصول على إحصائيات الحرس
app.get('/api/permits/guard-stats/:guard_username', authenticateToken, 
    authorizeRoles('security', 'security_guard', 'admin'), (req, res) => {
    const { guard_username } = req.params;
    const today = new Date().toISOString().split('T')[0];
    
    if (req.user.username !== guard_username && req.user.role !== 'admin') {
        return res.status(403).json({
            success: false,
            message: 'غير مصرح لك بالوصول إلى إحصائيات حارس آخر'
        });
    }
    
    const queries = [
        `SELECT COUNT(*) as count 
         FROM permits 
         WHERE status = 'approved_security'
         AND DATE(start_date) <= DATE(?)
         AND DATE(end_date) >= DATE(?)
         AND actual_entry_time IS NULL`,
         
        `SELECT COUNT(*) as count 
         FROM permits 
         WHERE status = 'checked_in'
         AND DATE(start_date) <= DATE(?)
         AND DATE(end_date) >= DATE(?)`,
         
        `SELECT COUNT(*) as count 
         FROM permits 
         WHERE status = 'completed'
         AND DATE(checkout_timestamp) = DATE(?)`,
         
        `SELECT COUNT(*) as count 
         FROM permits 
         WHERE (entry_guard_username = ? OR exit_guard_username = ?)
         AND DATE(checkin_timestamp) = DATE(?)`
    ];
    
    const params = [
        [today, today],
        [today, today],
        [today],
        [guard_username, guard_username, today]
    ];
    
    const results = {};
    
    db.serialize(() => {
        db.get(queries[0], params[0], (err, result) => {
            results.active_permits = result ? result.count : 0;
        });
        
        db.get(queries[1], params[1], (err, result) => {
            results.checked_in = result ? result.count : 0;
        });
        
        db.get(queries[2], params[2], (err, result) => {
            results.today_completed = result ? result.count : 0;
        });
        
        db.get(queries[3], params[3], (err, result) => {
            results.total_processed = result ? result.count : 0;
            
            setTimeout(() => {
                res.json({
                    success: true,
                    stats: results
                });
            }, 100);
        });
    });
});

// API لتقديم تصريح جديد (محمي)
app.post('/api/permits/new', authenticateToken, authorizeRoles('employee', 'admin', 'manager'), (req, res) => {
    try {
        const { 
            employee_username, 
            reason, 
            start_date, 
            end_date, 
            expected_exit_time,
            additional_notes 
        } = req.body;
        
        console.log('📨 استقبال طلب تصريح جديد:', req.body);
        
        if (!employee_username || !reason || !start_date || !end_date || !expected_exit_time) {
            return res.status(400).json({
                success: false,
                message: 'جميع الحقول الإلزامية مطلوبة'
            });
        }
        
        db.get('SELECT employee_id FROM employees WHERE username = ?', [employee_username], (err, employee) => {
            if (err) {
                console.error('خطأ في البحث عن الموظف:', err);
                return res.status(500).json({
                    success: false,
                    message: 'حدث خطأ في الخادم'
                });
            }
            
            if (!employee) {
                return res.status(404).json({
                    success: false,
                    message: 'الموظف غير موجود'
                });
            }
            
            const query = `
                INSERT INTO permits 
                (employee_id, reason, start_date, end_date, expected_exit_time, manager_notes, status)
                VALUES (?, ?, ?, ?, ?, ?, 'pending_manager')
            `;
            
            db.run(query, [
                employee.employee_id,
                reason,
                start_date,
                end_date,
                expected_exit_time,
                additional_notes || ''
            ], function(err) {
                if (err) {
                    console.error('خطأ في إدخال التصريح:', err);
                    return res.status(500).json({
                        success: false,
                        message: 'حدث خطأ في حفظ التصريح'
                    });
                }
                
                const permitId = this.lastID;
                
                // ✅ إشعار للموظف
                createNotification({
                    user_id: employee.employee_id,
                    permit_id: permitId,
                    title: '📨 تم تقديم طلب التصريح',
                    message: 'تم استلام طلب التصريح الخاص بك وسيتم مراجعته من قبل المدير قريباً.',
                    type: 'info'
                });
                
                // ✅ إشعار لجميع المديرين
                db.get('SELECT full_name, job_number FROM employees WHERE employee_id = ?', [employee.employee_id], (err, empInfo) => {
                    if (!err && empInfo) {
                        notifyAllManagers(
                            permitId,
                            '📋 طلب تصريح جديد بانتظار الموافقة',
                            `طلب تصريح جديد من الموظف ${empInfo.full_name} (${empInfo.job_number}) ينتظر موافقتك.`,
                            'warning'
                        );
                    } else {
                        notifyAllManagers(
                            permitId,
                            '📋 طلب تصريح جديد بانتظار الموافقة',
                            'هناك طلب تصريح جديد من أحد الموظفين ينتظر موافقتك.',
                            'warning'
                        );
                    }
                });
                
                res.json({
                    success: true,
                    message: 'تم تقديم طلب التصريح بنجاح',
                    permit_id: permitId,
                    timestamp: new Date().toISOString()
                });
            });
        });
        
    } catch (error) {
        console.error('خطأ في تقديم التصريح:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في الخادم'
        });
    }
});

// ============== Static files serving ==============
app.use(express.static(path.join(__dirname, '../frontend')));

// ============== صفحات HTML ==============

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/pages/login.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/pages/login.html'));
});

app.get('/dashboard.html', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/pages/dashboard.html'));
});

app.get('/pages/new-permit.html', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/pages/new-permit.html'));
});

app.get('/pages/manage-departments.html', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/pages/manage-departments.html'));
});

app.get('/pages/my-permits.html', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/pages/my-permits.html'));
});

app.get('/pages/security-dashboard.html', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/pages/security-dashboard.html'));
});

app.get('/pages/manager-dashboard.html', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/pages/manager-dashboard.html'));
});

app.get('/pages/security-guard.html', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/pages/security-guard.html'));
});

// صفحات تصاريح الشركات
app.get('/company-entry-permit', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/pages/company-entry-permit.html'));
});

app.get('/company-entry-my-permits', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/pages/company-entry-my-permits.html'));
});

app.get('/company-entry-manager', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/pages/company-entry-manager.html'));
});

app.get('/company-entry-security', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/pages/company-entry-security.html'));
});

app.get('/company-entry-guard', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/pages/company-entry-guard.html'));
});


// ثالثاً: أي مسار HTML آخر
app.get('*.html', (req, res) => {
    const filePath = path.join(__dirname, '../frontend', req.path);
    if (fs.existsSync(filePath)) {
        res.sendFile(filePath);
    } else {
        res.status(404).json({
            success: false,
            message: 'الصفحة غير موجودة',
            path: req.path
        });
    }
});

// رابعاً: التحقق من صحة API URLs
app.get('/api/*', (req, res) => {
    res.status(404).json({
        success: false,
        message: 'API غير موجود',
        path: req.path,
        method: req.method
    });
});

// ============== معالجة الأخطاء ==============

app.use((err, req, res, next) => {
    console.error('❌ خطأ في الخادم:', err.message);
    console.error('📁 المسار:', req.path);
    console.error('📝 الميثود:', req.method);
    
    res.status(500).json({ 
        success: false,
        error: 'حدث خطأ في الخادم',
        message: err.message 
    });
});

app.use((req, res) => {
    console.log('❌ 404 - مسار غير موجود:', req.path);
    
    // إذا كان المسار يبدأ بـ /api/، أرجِع JSON
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({
            success: false,
            message: 'API غير موجود',
            path: req.path,
            method: req.method
        });
    }
    
    // وإلا حاول إرجاع صفحة 404 HTML
    const errorPage = path.join(__dirname, '../frontend/pages/404.html');
    if (fs.existsSync(errorPage)) {
        return res.status(404).sendFile(errorPage);
    }
    
    // إذا لم توجد صفحة 404، أرجِع JSON
    res.status(404).json({
        success: false,
        message: 'الصفحة غير موجودة',
        path: req.path
    });
});

// ============== معالجة الأخطاء ==============

app.use((err, req, res, next) => {
    console.error('خطأ:', err);
    res.status(500).json({ 
        success: false,
        error: 'حدث خطأ في الخادم',
        message: err.message 
    });
});

app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'الصفحة غير موجودة',
        path: req.path
    });
});

// ============== تشغيل الخادم ==============

const PORT = process.env.PORT || 5050;

app.listen(PORT, () => {
    console.log('\n' + '='.repeat(60));
    console.log('🚀  نظام تصاريح العمل بعد الدوام الرسمي');
    console.log('='.repeat(60));
    console.log(`✅  الخادم يعمل على: http://localhost:${PORT}`);
    console.log(`🔗  رابط تسجيل الدخول: http://localhost:${PORT}/login`);
    console.log(`🎯  رابط لوحة التحكم: http://localhost:${PORT}/dashboard.html`);
    console.log(`💾  قاعدة البيانات: ${selectedDb}`);
    console.log('\n👤  بيانات الدخول للتجربة:');
    console.log('   📧  admin      / admin123  (مسؤول النظام)');
    console.log('   📧  manager1   / admin123  (مدير قسم)');
    console.log('   📧  employee1  / admin123  (موظف)');
    console.log('   📧  employee2  / admin123  (موظف)');
    console.log('   📧  security1  / admin123  (مسؤول أمن)');
    console.log('   📧  security2  / admin123  (حارس أمن) ⭐⭐ جديد ⭐⭐');
    console.log('\n' + '='.repeat(60));
    console.log('🔒  جميع APIs محمية الآن بصلاحيات المستخدمين');
    console.log('✅  APIs المفتوحة فقط:');
    console.log('   GET  /api/health                    - حالة الخادم');
    console.log('   POST /api/login                     - تسجيل الدخول');
    console.log('='.repeat(60));
    console.log('🎯  APIs الجديدة لتصاريح الشركات:');
    console.log('   GET  /api/permits/company-entry/pending/:username         - المعلقة للمدير');
    console.log('   GET  /api/permits/company-entry/security-pending          - المعلقة للأمن');
    console.log('   POST /api/permits/company-entry/approve                   - موافقة المدير');
    console.log('   POST /api/permits/company-entry/security-approve          - موافقة الأمن');
    console.log('   GET  /api/permits/company-entry/:id                       - تفاصيل تصريح');
    console.log('   POST /api/permits/company-entry/send-to-guard             - إرسال للحرس');
    console.log('   POST /api/permits/company-entry/new                       - تصريح جديد');
    console.log('   GET  /api/permits/company-entry/my/:username              - تصاريحي');
    console.log('   GET  /api/permits/company-entry/active                    - النشطة للحراسة');
    console.log('   POST /api/permits/company-entry/guard-checkin             - تسجيل دخول شركة');
    console.log('   POST /api/permits/company-entry/guard-checkout            - تسجيل خروج شركة');
    console.log('   GET  /api/permits/company-entry/checked-in                - داخل الموقع');
    console.log('   GET  /api/permits/company-entry/stats/:username           - إحصائيات');
    console.log('   DELETE /api/permits/company-entry/:id                     - حذف تصريح');
    console.log('   PUT /api/permits/company-entry/:id                        - تحديث تصريح');
    console.log('   GET  /api/permits/company-entry/search                    - بحث متقدم');
    
    // 🔥 أضف هنا APIs الجديدة التي طلبتها:
    console.log('   GET  /api/permits/company-entry/pending                    - تصاريح الشركات المعلقة');
    console.log('   GET  /api/permits/company-entry/approved                   - تصاريح الشركات المعتمدة');
    console.log('   POST /api/permits/company-entry/manager-approve            - موافقة المدير على تصريح شركة');
    console.log('   POST /api/permits/company-entry/manager-reject             - رفض المدير لتصريح شركة');
    console.log('   POST /api/permits/company-entry/to-security                - إرسال تصريح لمكتب الأمن');
    console.log('   GET  /api/permits/company-entry/stats                      - إحصائيات تصاريح الشركات');
    
    console.log('='.repeat(60));
    console.log('🎯  APIs الجديدة للحرس:');
    console.log('   GET  /api/permits/guard-approved    - التصاريح الجاهزة');
    console.log('   POST /api/permits/guard-checkin     - تسجيل دخول');
    console.log('   POST /api/permits/guard-checkout    - تسجيل خروج');
    console.log('   GET  /api/permits/guard-checked-in  - داخل المبنى');
    console.log('   GET  /api/permits/guard-stats/:username - إحصائيات');
    console.log('='.repeat(60));
    console.log('💡  اضغط Ctrl + C لإيقاف الخادم');
    console.log('='.repeat(60) + '\n');
});