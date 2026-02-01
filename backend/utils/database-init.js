// ============== Database Initialization ==============
const { db, query, run } = require('../database');

// التحقق من وجود الجداول
async function checkDatabaseTables() {
    try {
        const tables = await query(`
            SELECT name 
            FROM sqlite_master 
            WHERE type='table' 
            AND name NOT LIKE 'sqlite_%'
        `);
        
        const tableNames = tables.map(t => t.name);
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
            await initializeDatabase();
        } else {
            console.log('✅ جميع الجداول الأساسية موجودة');
            
            // التحقق من وجود بيانات أساسية
            const result = await query('SELECT COUNT(*) as count FROM employees');
            const count = result[0]?.count || 0;
            console.log(`👥 عدد الموظفين: ${count}`);
            
            if (count === 0) {
                console.log('🔄 لا توجد بيانات، جاري إضافة المستخدمين الأساسيين...');
                await addEssentialUsers();
            } else {
                console.log('✅ قاعدة البيانات تحتوي على بيانات');
                await updatePermitsTable();
            }
        }
    } catch (error) {
        console.error('❌ خطأ في التحقق من الجداول:', error.message);
        console.log('🔄 سأحاول إنشاء الجداول الأساسية...');
        await initializeDatabase();
    }
}

// إنشاء الجداول الأساسية
async function initializeDatabase() {
    console.log('🔨 جاري إنشاء الجداول الأساسية...');
    
    const tables = [
        // جدول الأقسام أولاً
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
            request_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,
        
        // جدول تصاريح الشركات
        `CREATE TABLE IF NOT EXISTS company_entry_permits (
            permit_id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            company_name TEXT NOT NULL,
            company_representative TEXT NOT NULL,
            representative_phone TEXT,
            entry_purpose TEXT NOT NULL,
            number_of_visitors INTEGER DEFAULT 1,
            expected_entry_date TEXT NOT NULL,
            expected_entry_time TEXT NOT NULL,
            expected_exit_date TEXT NOT NULL,
            expected_exit_time TEXT NOT NULL,
            requesting_department TEXT,
            employees TEXT,
            additional_notes TEXT,
            status TEXT DEFAULT 'pending_manager',
            manager_decision TEXT,
            manager_decision_date TEXT,
            manager_notes TEXT,
            manager_username TEXT,
            security_decision TEXT,
            security_decision_date TEXT,
            security_username TEXT,
            security_notes TEXT,
            guard_username TEXT,
            actual_entry_time TEXT,
            actual_exit_time TEXT,
            entry_notes TEXT,
            exit_notes TEXT,
            checkin_timestamp TEXT,
            checkout_timestamp TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,
        
        // جدول عمال الشركات
        `CREATE TABLE IF NOT EXISTS company_workers (
            worker_id INTEGER PRIMARY KEY AUTOINCREMENT,
            permit_id INTEGER NOT NULL,
            worker_name TEXT NOT NULL,
            worker_id_number TEXT,
            worker_profession TEXT,
            worker_phone TEXT,
            id_card_file_name TEXT,
            added_by TEXT,
            is_original INTEGER DEFAULT 0,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (permit_id) REFERENCES company_entry_permits(permit_id)
        )`,
        
        // جدول تصاريح إخراج المواد والأجهزة
        `CREATE TABLE IF NOT EXISTS material_exit_permits (
            permit_id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            employee_name TEXT NOT NULL,
            job_number TEXT NOT NULL,
            directorate TEXT NOT NULL,
            department TEXT NOT NULL,
            material_type TEXT NOT NULL,
            exit_reason TEXT NOT NULL,
            permit_date TEXT NOT NULL,
            permit_time TEXT NOT NULL,
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
            manager_username TEXT,
            manager_decision TEXT,
            manager_decision_date TEXT,
            manager_notes TEXT,
            security_username TEXT,
            security_decision TEXT,
            security_decision_date TEXT,
            security_notes TEXT,
            guard_username TEXT,
            guard_verification_date TEXT,
            guard_notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
        )`,
        
        // جدول الإشعارات
        `CREATE TABLE IF NOT EXISTS notifications (
            notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            permit_id INTEGER,
            company_permit_id INTEGER,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            type TEXT DEFAULT 'info',
            is_read BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,
        
        // جدول نوبات الحراس
        `CREATE TABLE IF NOT EXISTS guard_shifts (
            shift_id INTEGER PRIMARY KEY AUTOINCREMENT,
            guard_name TEXT NOT NULL,
            guard_username TEXT,
            shift_date TEXT NOT NULL,
            shift_start_time TEXT,
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`
    ];
    
    for (const tableSQL of tables) {
        await run(tableSQL);
    }
    
    console.log('✅ تم إنشاء جميع الجداول بنجاح');
}

// تحديث جدول التصاريح
async function updatePermitsTable() {
    try {
        const columns = await query(`PRAGMA table_info(permits)`);
        const columnNames = columns.map(col => col.name);
        
        const columnsToAdd = [
            { name: 'manager_status', type: 'TEXT DEFAULT "pending"' },
            { name: 'security_status', type: 'TEXT DEFAULT "pending"' }
        ];
        
        for (const col of columnsToAdd) {
            if (!columnNames.includes(col.name)) {
                await run(`ALTER TABLE permits ADD COLUMN ${col.name} ${col.type}`);
                console.log(`✅ تم إضافة العمود: ${col.name}`);
            }
        }
    } catch (error) {
        console.error('❌ خطأ في تحديث جدول التصاريح:', error.message);
    }
}

// إضافة المستخدمين الأساسيين
async function addEssentialUsers() {
    console.log('👤 جاري إضافة المستخدمين الأساسيين...');
    
    const users = [
        ['admin', 'admin123', 'مدير النظام', 'admin', 'ADM001', 'الإدارة العامة', 'admin@company.com', '0500000000'],
        ['employee1', 'admin123', 'محمد حسن', 'employee', 'EMP001', 'الإدارة العامة', 'employee1@company.com', '0500000001'],
        ['employee2', 'admin123', 'فاطمة علي', 'employee', 'EMP002', 'الإدارة العامة', 'employee2@company.com', '0500000002'],
        ['manager1', 'admin123', 'أحمد علي', 'manager', 'MGR001', 'الإدارة العامة', 'manager1@company.com', '0500000003'],
        ['security1', 'admin123', 'خالد أمين', 'security', 'SEC001', 'الأمن والسلامة', 'security1@company.com', '0500000004'],
        ['security2', 'admin123', 'حارس الأمن', 'guard', 'SEC002', 'الأمن والسلامة', 'security2@company.com', '0500000005']
    ];
    
    for (const user of users) {
        const existing = await query('SELECT employee_id FROM employees WHERE username = ?', [user[0]]);
        
        if (existing.length === 0) {
            await run(`
                INSERT INTO employees 
                (username, password_hash, full_name, user_type, job_number, directorate, email, phone)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `, user);
            console.log(`✅ تم إضافة: ${user[2]} (${user[0]})`);
        }
    }
    
    console.log('✅ تم إضافة جميع المستخدمين الأساسيين');
}

module.exports = {
    checkDatabaseTables,
    initializeDatabase,
    updatePermitsTable,
    addEssentialUsers
};

