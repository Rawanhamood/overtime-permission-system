const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

// مسار قاعدة البيانات
const dbPath = path.join(__dirname, 'overtime.db');

console.log('🚀 بدء إعادة بناء قاعدة البيانات من الصفر...');
console.log(`📁 المسار: ${dbPath}`);

// تأكد من وجود المجلد
const dbDir = path.dirname(dbPath);
if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
}

// إذا كان الملف موجوداً، انقله كنسخة احتياطية
if (fs.existsSync(dbPath)) {
    const backupPath = dbPath + '.backup-' + Date.now();
    fs.copyFileSync(dbPath, backupPath);
    console.log(`📂 تم إنشاء نسخة احتياطية: ${path.basename(backupPath)}`);
}

// إنشاء اتصال جديد بقاعدة البيانات
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('❌ خطأ في الاتصال:', err.message);
        process.exit(1);
    }
    console.log('✅ تم الاتصال بقاعدة البيانات');
    rebuildDatabase();
});

function rebuildDatabase() {
    console.log('🔥 إسقاط جميع الجداول القديمة...');
    
    // قائمة بجميع الجداول التي قد تكون موجودة
    const dropQueries = [
        'DROP TABLE IF EXISTS time_violations',
        'DROP TABLE IF EXISTS notifications',
        'DROP TABLE IF EXISTS company_entry_permits',
        'DROP TABLE IF EXISTS permits',
        'DROP TABLE IF EXISTS departments',
        'DROP TABLE IF EXISTS employees'
    ];
    
    let dropCount = 0;
    
    function dropNextTable() {
        if (dropCount < dropQueries.length) {
            db.run(dropQueries[dropCount], (err) => {
                if (err && !err.message.includes('no such table')) {
                    console.error(`❌ خطأ في إسقاط الجدول: ${err.message}`);
                } else {
                    console.log(`✅ تم إسقاط الجدول ${dropCount + 1}/${dropQueries.length}`);
                }
                dropCount++;
                setTimeout(dropNextTable, 100);
            });
        } else {
            console.log('✅ تم إسقاط جميع الجداول القديمة');
            createNewDatabase();
        }
    }
    
    dropNextTable();
}

function createNewDatabase() {
    console.log('🏗️  بناء قاعدة البيانات الجديدة...');
    
    // تفعيل دعم المفاتيح الأجنبية
    db.run(`PRAGMA foreign_keys = ON`);
    
    // إنشاء الجداول بالترتيب الصحيح
    const createQueries = [
        // 1. جدول الموظفين (أولاً لأنه أساسي)
        `CREATE TABLE employees (
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
            user_type VARCHAR(20) DEFAULT 'employee' CHECK(user_type IN ('admin', 'manager', 'employee', 'security', 'guard')),
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,
        
        // 2. جدول الأقسام
        `CREATE TABLE departments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(100) NOT NULL,
            type VARCHAR(50) NOT NULL,
            manager_id INTEGER,
            parent_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (manager_id) REFERENCES employees(employee_id)
        )`,
        
        // 3. جدول التصاريح الشخصية
        `CREATE TABLE permits (
            permit_id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            request_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reason TEXT NOT NULL,
            start_date DATE NOT NULL,
            end_date DATE NOT NULL,
            expected_exit_time TIME NOT NULL,
            type VARCHAR(20) DEFAULT 'exit' CHECK(type IN ('exit', 'entry', 'visit', 'delivery')),
            status VARCHAR(20) DEFAULT 'pending_manager' CHECK(status IN (
                'pending_manager', 
                'approved_manager', 
                'rejected_manager',
                'pending_security',
                'approved_security',
                'rejected_security'
            )),
            manager_decision VARCHAR(10),
            manager_decision_date TIMESTAMP,
            manager_notes TEXT,
            security_decision VARCHAR(10),
            security_decision_date TIMESTAMP,
            security_notes TEXT,
            actual_entry_time TIME,
            actual_exit_time TIME,
            entry_guard_username VARCHAR(50),
            exit_guard_username VARCHAR(50),
            entry_notes TEXT,
            exit_notes TEXT,
            checkin_timestamp TIMESTAMP,
            checkout_timestamp TIMESTAMP,
            manager_id INTEGER,
            security_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (employee_id) REFERENCES employees(employee_id),
            FOREIGN KEY (manager_id) REFERENCES employees(employee_id),
            FOREIGN KEY (security_id) REFERENCES employees(employee_id)
        )`,
        
        // 4. جدول تصاريح الشركات
        `CREATE TABLE company_entry_permits (
            permit_id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            company_name VARCHAR(200) NOT NULL,
            company_representative VARCHAR(100) NOT NULL,
            representative_phone VARCHAR(15),
            entry_purpose TEXT NOT NULL,
            number_of_visitors INTEGER DEFAULT 1,
            expected_entry_date DATE NOT NULL,
            expected_entry_time TIME NOT NULL,
            expected_exit_date DATE NOT NULL,
            expected_exit_time TIME NOT NULL,
            requesting_department TEXT,
            employees TEXT,
            additional_notes TEXT,
            status VARCHAR(20) DEFAULT 'pending_manager' CHECK(status IN (
                'pending_manager', 
                'approved_manager', 
                'rejected_manager',
                'approved_security',
                'rejected_security',
                'sent_to_guard',
                'checked_in',
                'checked_out'
            )),
            manager_decision VARCHAR(10),
            manager_decision_date TIMESTAMP,
            manager_notes TEXT,
            security_decision VARCHAR(10),
            security_decision_date TIMESTAMP,
            security_notes TEXT,
            guard_username VARCHAR(50),
            actual_entry_time TIME,
            actual_exit_time TIME,
            entry_notes TEXT,
            exit_notes TEXT,
            checkin_timestamp TIMESTAMP,
            checkout_timestamp TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
        )`,
        
`CREATE TABLE material_exit_permits (
    permit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INTEGER NOT NULL,
    employee_name TEXT NOT NULL,
    job_number TEXT,
    directorate TEXT,
    department TEXT,
    material_type TEXT NOT NULL,
    exit_reason TEXT NOT NULL,
    permit_date DATE NOT NULL,
    permit_time TIME NOT NULL,
    supervisor_name TEXT NOT NULL,
    status TEXT DEFAULT 'pending_manager' CHECK(status IN (
        'pending_manager', 
        'approved_manager', 
        'rejected_manager',
        'pending_security',
        'approved_security',
        'rejected_security',
        'sent_to_guard',
        'completed'
    )),
    
    -- معلومات المدير
    manager_username TEXT,
    manager_decision TEXT,
    manager_decision_date TIMESTAMP,
    manager_notes TEXT,
    
    -- معلومات الأمن
    security_username TEXT,
    security_decision TEXT,
    security_decision_date TIMESTAMP,
    security_notes TEXT,
    
    -- معلومات الحارس
    guard_username TEXT,
    guard_verification_date TIMESTAMP,
    guard_notes TEXT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
)`,
       // 5. جدول الإشعارات
`CREATE TABLE notifications (
    notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    permit_id INTEGER,
    company_permit_id INTEGER,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    type VARCHAR(20) DEFAULT 'info' CHECK(type IN ('info', 'warning', 'success', 'error')),
    is_read BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES employees(employee_id)
)`
    ];
    
    let createCount = 0;
    
    function createNextTable() {
        if (createCount < createQueries.length) {
            const tableNames = ['الموظفين', 'الأقسام', 'التصاريح الشخصية', 'تصاريح الشركات', 'الإشعارات'];
            
            db.run(createQueries[createCount], (err) => {
                if (err) {
                    console.error(`❌ خطأ في إنشاء جدول ${tableNames[createCount]}:`, err.message);
                    console.log('🔍 الاستعلام:', createQueries[createCount].substring(0, 100) + '...');
                } else {
                    console.log(`✅ تم إنشاء جدول ${tableNames[createCount]}`);
                }
                createCount++;
                setTimeout(createNextTable, 500);
            });
        } else {
            console.log('✅ تم إنشاء جميع الجداول بنجاح');
            createIndexes();
        }
    }
    
    createNextTable();
}

function createIndexes() {
    console.log('📊 جاري إنشاء فهارس تحسين الأداء...');
    
    const indexes = [
        // فهارس جدول الموظفين
        'CREATE INDEX idx_employees_username ON employees(username)',
        'CREATE INDEX idx_employees_user_type ON employees(user_type)',
        'CREATE INDEX idx_employees_manager_id ON employees(manager_id)',
        
        // فهارس جدول التصاريح الشخصية
        'CREATE INDEX idx_permits_employee_id ON permits(employee_id)',
        'CREATE INDEX idx_permits_status ON permits(status)',
        'CREATE INDEX idx_permits_start_date ON permits(start_date)',
        'CREATE INDEX idx_permits_end_date ON permits(end_date)',
        'CREATE INDEX idx_permits_type ON permits(type)',
        
        // فهارس جدول تصاريح الشركات
        'CREATE INDEX idx_company_permits_employee_id ON company_entry_permits(employee_id)',
        'CREATE INDEX idx_company_permits_status ON company_entry_permits(status)',
        'CREATE INDEX idx_company_permits_company_name ON company_entry_permits(company_name)',

                // فهارس جدول تصاريح المواد

        'CREATE INDEX idx_material_exit_employee_id ON material_exit_permits(employee_id)',
        'CREATE INDEX idx_material_exit_status ON material_exit_permits(status)',
        'CREATE INDEX idx_material_exit_date ON material_exit_permits(permit_date)',
        'CREATE INDEX idx_material_exit_material_type ON material_exit_permits(material_type)',
        
        // فهارس جدول الإشعارات
        'CREATE INDEX idx_notifications_user_id ON notifications(user_id)',
        'CREATE INDEX idx_notifications_is_read ON notifications(is_read)'
    ];
    
    let indexCount = 0;
    
    function createNextIndex() {
        if (indexCount < indexes.length) {
            db.run(indexes[indexCount], (err) => {
                if (err) {
                    console.error(`❌ خطأ في إنشاء الفهرس ${indexCount + 1}:`, err.message);
                } else {
                    console.log(`✅ تم إنشاء الفهرس ${indexCount + 1}/${indexes.length}`);
                }
                indexCount++;
                setTimeout(createNextIndex, 200);
            });
        } else {
            console.log('📊 تم إنشاء جميع الفهارس');
            insertInitialData();
        }
    }
    
    createNextIndex();
}

function insertInitialData() {
    console.log('👤 جاري إنشاء الموظفين الأساسيين...');
    
    const employees = [
        // username, password, full_name, job_number, directorate, department_id, position, email, phone, manager_id, user_type
        ['admin', 'admin123', 'مدير النظام', 'ADM001', 'الإدارة العامة', 1, 'مدير النظام', 'admin@company.com', '0500000000', null, 'admin'],
        ['manager1', 'admin123', 'أحمد علي', 'MGR001', 'مديرية الموارد البشرية', 2, 'مدير الموارد البشرية', 'manager1@company.com', '0500000001', 1, 'manager'],
        ['manager2', 'admin123', 'سالم محمد', 'MGR002', 'مديرية المالية', 3, 'مدير المالية', 'manager2@company.com', '0500000005', 1, 'manager'],
        ['employee1', 'admin123', 'محمد حسن', 'EMP001', 'مديرية الموارد البشرية', 2, 'موظف موارد بشرية', 'employee1@company.com', '0500000002', 2, 'employee'],
        ['employee2', 'admin123', 'خالد أحمد', 'EMP002', 'مديرية المالية', 3, 'محاسب', 'employee2@company.com', '0500000003', 3, 'employee'],
        ['security1', 'admin123', 'خالد أمين', 'SEC001', 'مكتب الأمن والسلامة', 5, 'مسؤول الأمن', 'security1@company.com', '0500000004', 1, 'security'],
        ['guard1', 'admin123', 'سالم علي', 'GARD001', 'مكتب الأمن والسلامة', 5, 'حارس أمن', 'guard1@company.com', '0500000007', 6, 'guard']
    ];
    
    let empCount = 0;
    
    employees.forEach(emp => {
        db.run(
            `INSERT INTO employees (username, password_hash, full_name, job_number, directorate, department_id, position, email, phone, manager_id, user_type) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            emp,
            function(err) {
                if (err) {
                    console.error(`❌ خطأ في إدخال ${emp[0]}:`, err.message);
                } else {
                    console.log(`✅ تم إدخال: ${emp[2]} (${emp[0]})`);
                }
                empCount++;
                
                if (empCount === employees.length) {
                    console.log('✅ تم إدخال جميع الموظفين');
                    createTestData();
                }
            }
        );
    });
}

function createTestData() {
    console.log('📋 جاري إنشاء بيانات تجريبية...');
    
    // الحصول على معرفات الموظفين
    db.all('SELECT employee_id, username, user_type FROM employees', (err, employees) => {
        if (err) {
            console.error('❌ خطأ في جلب الموظفين:', err.message);
            showSummary();
            return;
        }
        
        const employee1 = employees.find(e => e.username === 'employee1');
        const manager1 = employees.find(e => e.username === 'manager1');
        const security1 = employees.find(e => e.username === 'security1');
        
        if (!employee1 || !manager1 || !security1) {
            console.log('⚠️  بعض الموظفين غير موجودين لإنشاء بيانات تجريبية');
            showSummary();
            return;
        }
        
        const today = new Date();
        const tomorrow = new Date(today);
        tomorrow.setDate(tomorrow.getDate() + 1);
        
        // 1. إنشاء تصريح شخصي
        db.run(
            `INSERT INTO permits (employee_id, reason, start_date, end_date, expected_exit_time, type, status, request_date) 
             VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
            [employee1.employee_id, 'إكمال تقارير العمل', today.toISOString().split('T')[0], 
             today.toISOString().split('T')[0], '20:00', 'exit', 'pending_manager'],
            function(err) {
                if (err) {
                    console.error('❌ خطأ في إنشاء تصريح شخصي:', err.message);
                } else {
                    console.log(`✅ تم إنشاء تصريح شخصي #${this.lastID}`);
                }
                
                // 2. إنشاء تصريح شركة
                const companyData = {
                    directorate: "مديرية تقنية المعلومات",
                    department: "قسم البرمجة",
                    job_number: "EMP001",
                    supervisor_name: "أحمد علي"
                };
                
                const workers = [
                    { name: "علي محمد", profession: "مهندس شبكات", id_number: "1012345678" },
                    { name: "سارة أحمد", profession: "فني تركيب", id_number: "1023456789" }
                ];
                
                db.run(
                    `INSERT INTO company_entry_permits (employee_id, company_name, company_representative, representative_phone, 
                     entry_purpose, number_of_visitors, expected_entry_date, expected_entry_time,
                     expected_exit_date, expected_exit_time, requesting_department, employees,
                     additional_notes, status, created_at) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
                    [
                        employee1.employee_id,
                        'شركة التقنية المتقدمة',
                        'ماجد السعد',
                        '0501111111',
                        'تركيب نظام مراقبة جديد',
                        2,
                        today.toISOString().split('T')[0],
                        '10:00',
                        today.toISOString().split('T')[0],
                        '16:00',
                        JSON.stringify(companyData),
                        JSON.stringify(workers),
                        'يحتاجون إلى مرافقة أمنية',
                        'pending_manager'
                    ],
                    function(err) {
                        if (err) {
                            console.error('❌ خطأ في إنشاء تصريح شركة:', err.message);
                        } else {
                            console.log(`✅ تم إنشاء تصريح شركة #${this.lastID}`);
                        }
                        
                        // 3. إنشاء إشعارات تجريبية
                        createSampleNotifications(employees);
                    }
                );
            }
        );
    });
}


function createSampleNotifications(employees) {
    const notifications = [
        {
            user_id: employees.find(e => e.username === 'employee1').employee_id,
            title: 'مرحباً في نظام التصاريح',
            message: 'تم تسجيل دخولك بنجاح إلى نظام تصاريح العمل بعد الدوام',
            type: 'info'
        },
        {
            user_id: employees.find(e => e.username === 'manager1').employee_id,
            title: 'تصريح جديد مطلوب',
            message: 'يوجد تصريح عمل بعد الدوام يحتاج لمراجعتك',
            type: 'warning'
        }
    ];
    
    let notifCount = 0;
    
    notifications.forEach(notif => {
        db.run(
            `INSERT INTO notifications (user_id, title, message, type, is_read, created_at) 
             VALUES (?, ?, ?, ?, ?, datetime('now', '-30 minutes'))`,
            [notif.user_id, notif.title, notif.message, notif.type, 0],
            function(err) {
                if (err) {
                    console.error('❌ خطأ في إنشاء إشعار:', err.message);
                } else {
                    console.log(`✅ تم إنشاء إشعار #${this.lastID}`);
                }
                notifCount++;
                
                if (notifCount === notifications.length) {
                    console.log('✅ تم إنشاء جميع البيانات التجريبية');
                    showSummary();
                }
            }
        );
    });
}

function showSummary() {
    console.log('\n' + '='.repeat(70));
    console.log('🎉 تم بناء قاعدة البيانات بنجاح!');
    console.log('='.repeat(70));
    
    db.get(`SELECT COUNT(*) as count FROM employees`, (err, empResult) => {
        db.get(`SELECT COUNT(*) as count FROM permits`, (err, permitResult) => {
            db.get(`SELECT COUNT(*) as count FROM company_entry_permits`, (err, companyResult) => {
                db.get(`SELECT COUNT(*) as count FROM notifications`, (err, notifResult) => {
                    console.log('📊 إحصائيات قاعدة البيانات:');
                    console.log(`   👥 الموظفين: ${empResult?.count || 0}`);
                    console.log(`   📋 التصاريح الشخصية: ${permitResult?.count || 0}`);
                    console.log(`   🏢 تصاريح الشركات: ${companyResult?.count || 0}`);
                    console.log(`   🔔 الإشعارات: ${notifResult?.count || 0}`);
                    console.log('='.repeat(70));
                    console.log('👤 بيانات الدخول (كلمة المرور لجميع الحسابات: admin123):');
                    console.log('   📧 admin     - مسؤول النظام');
                    console.log('   📧 manager1  - مدير قسم');
                    console.log('   📧 employee1 - موظف');
                    console.log('   📧 security1 - مسؤول أمن');
                    console.log('   📧 guard1    - حارس أمن');
                    console.log('='.repeat(70));
                    console.log('🚀 يمكنك الآن تشغيل الخادم:');
                    console.log('   npm run dev');
                    console.log('='.repeat(70));
                    console.log('🌐 رابط التطبيق: http://localhost:5050');
                    console.log('='.repeat(70) + '\n');
                    
                    db.close();
                });
            });
        });
    });
}