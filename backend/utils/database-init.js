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
        // تمت إضافة جدول تصاريح إخراج المواد والأجهزة لضمان إنشائه إذا كان مفقوداً
        const essentialTables = [
            'employees',
            'permits',
            'departments',
            'material_exit_permits'
        ];
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
        await updateCompanyEntryPermitsTable();
        await ensureSecurityOfficeApproversTable();
        await updateEmployeesDeputyColumn();
        await ensureDeputyManagerDemoUser();
    } catch (error) {
        console.error('❌ خطأ في التحقق من الجداول:', error.message);
        console.log('🔄 سأحاول إنشاء الجداول الأساسية...');
        await initializeDatabase();
        await updateCompanyEntryPermitsTable();
        await ensureSecurityOfficeApproversTable();
        await updateEmployeesDeputyColumn();
        await ensureDeputyManagerDemoUser();
    }
}

/** نائب المدير: يرتبط بالمدير عبر deputy_for_manager_id */
async function updateEmployeesDeputyColumn() {
    try {
        const cols = await query(`PRAGMA table_info(employees)`);
        const names = cols.map((c) => c.name);
        if (!names.includes('deputy_for_manager_id')) {
            await run(`ALTER TABLE employees ADD COLUMN deputy_for_manager_id INTEGER REFERENCES employees(employee_id)`);
            console.log('✅ employees: تم إضافة العمود deputy_for_manager_id');
        }
    } catch (e) {
        console.error('❌ updateEmployeesDeputyColumn:', e.message);
    }
}

/**
 * قواعد قديمة تضع CHECK على user_type دون deputy_manager فيمنع إنشاء حساب النائب.
 * يعيد إنشاء الجدول بنفس الأعمدة دون ذلك القيد.
 */
async function migrateEmployeesRemoveRestrictiveUserTypeCheck() {
    try {
        const rows = await query(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'employees'`);
        const ddl = rows[0]?.sql || '';
        if (!/CHECK\s*\(\s*user_type/i.test(ddl)) return;

        console.log('🔧 ترحيل employees: إزالة قيد CHECK عن user_type لدعم نائب المدير…');

        const cols = await query(`PRAGMA table_info(employees)`);
        const colNames = cols.map((c) => c.name);
        const defs = cols.map((c) => {
            let line = `"${c.name}" ${c.type}`;
            if (c.name === 'employee_id') {
                line += ' PRIMARY KEY AUTOINCREMENT';
            } else {
                if (c.notnull) line += ' NOT NULL';
                if (c.dflt_value != null && String(c.dflt_value).trim() !== '') {
                    line += ` DEFAULT ${c.dflt_value}`;
                }
            }
            if (c.name === 'username') line += ' UNIQUE';
            if (c.name === 'job_number') line += ' UNIQUE';
            return line;
        });

        const tmp = 'employees__user_type_migration_tmp';
        await run('PRAGMA foreign_keys = OFF');
        await run('BEGIN IMMEDIATE');
        try {
            await run(`DROP TABLE IF EXISTS ${tmp}`);
            await run(`CREATE TABLE ${tmp} (\n${defs.join(',\n')}\n)`);
            const quotedCols = colNames.map((n) => `"${n}"`).join(', ');
            await run(`INSERT INTO ${tmp} (${quotedCols}) SELECT ${quotedCols} FROM employees`);
            await run('DROP TABLE employees');
            await run(`ALTER TABLE ${tmp} RENAME TO employees`);
            const seqRows = await query(`SELECT MAX(employee_id) AS m FROM employees`);
            const maxId = seqRows[0]?.m;
            if (maxId != null && Number(maxId) > 0) {
                await run(`DELETE FROM sqlite_sequence WHERE name = 'employees'`).catch(() => {});
                await run(`INSERT INTO sqlite_sequence (name, seq) VALUES ('employees', ?)`, [Number(maxId)]);
            }
            await run('COMMIT');
            console.log('✅ employees: اكتمل الترحيل (user_type بدون CHECK مقيّد)');
        } catch (e) {
            await run('ROLLBACK').catch(() => {});
            throw e;
        } finally {
            await run('PRAGMA foreign_keys = ON');
        }
    } catch (e) {
        console.error('❌ migrateEmployeesRemoveRestrictiveUserTypeCheck:', e.message);
    }
}

async function ensureDeputyManagerDemoUser() {
    try {
        await updateEmployeesDeputyColumn();
        await migrateEmployeesRemoveRestrictiveUserTypeCheck();
        const mgr = await query(`SELECT employee_id FROM employees WHERE username = 'manager1'`);
        if (!mgr.length) {
            console.warn('⚠️ ensureDeputyManagerDemoUser: لا يوجد manager1 — تخطي إنشاء deputy_manager1');
            return;
        }
        const mid = mgr[0].employee_id;
        const ex = await query(`SELECT employee_id FROM employees WHERE username = 'deputy_manager1'`);
        if (!ex.length) {
            await run(
                `INSERT INTO employees 
                (username, password_hash, full_name, user_type, job_number, directorate, email, phone, deputy_for_manager_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                ['deputy_manager1', 'admin123', 'فيصل النائب', 'deputy_manager', 'DEP001', 'الإدارة العامة', 'deputy1@company.com', '0500000008', mid]
            );
            console.log('✅ تمت إضافة حساب تجريبي: deputy_manager1 (نائب عن manager1) — admin123');
            return;
        }
        await run(
            `UPDATE employees SET 
                password_hash = ?,
                user_type = 'deputy_manager',
                deputy_for_manager_id = ?,
                is_active = 1
             WHERE username = 'deputy_manager1'`,
            ['admin123', mid]
        );
        console.log('✅ تمت مزامنة حساب deputy_manager1 (كلمة المرور admin123، مرتبط بـ manager1)');
    } catch (e) {
        console.error('❌ ensureDeputyManagerDemoUser:', e.message);
    }
}

/** حسابان إضافيان لمكتب الأمن (مع security1 = ثلاثة معتمدين) */
async function ensureExtraSecurityOfficeEmployees() {
    const extra = [
        ['security_office_2', 'admin123', 'سعد العتيبي', 'security', 'SEC003', 'الأمن والسلامة', 'sec.office2@company.com', '0500000006'],
        ['security_office_3', 'admin123', 'فهد الدوسري', 'security', 'SEC004', 'الأمن والسلامة', 'sec.office3@company.com', '0500000007']
    ];
    for (const user of extra) {
        const existing = await query('SELECT employee_id FROM employees WHERE username = ?', [user[0]]);
        if (existing.length === 0) {
            await run(
                `INSERT INTO employees 
                (username, password_hash, full_name, user_type, job_number, directorate, email, phone)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                user
            );
            console.log(`✅ تمت إضافة حساب مكتب أمن: ${user[0]} (${user[2]})`);
        }
    }
}

/** ربط security1 + security_office_2 + security_office_3 كمعتمدين عند فراغ الجدول أو عند وجود مسؤول واحد فقط (security1) */
async function syncSecurityOfficeApproversToDefaultThree() {
    const targets = ['security1', 'security_office_2', 'security_office_3'];
    const ids = [];
    for (const un of targets) {
        const r = await query(
            `SELECT employee_id FROM employees WHERE username = ? AND user_type = 'security' AND (is_active IS NULL OR is_active = 1)`,
            [un]
        );
        if (r.length) ids.push(r[0].employee_id);
    }
    if (ids.length !== 3) return;

    const cntRow = await query('SELECT COUNT(*) as c FROM security_office_approvers');
    const cnt = cntRow[0]?.c || 0;

    if (cnt === 0) {
        for (let i = 0; i < 3; i++) {
            await run('INSERT INTO security_office_approvers (sort_order, employee_id) VALUES (?, ?)', [i + 1, ids[i]]);
        }
        console.log('✅ ربط الحسابات الثلاثة لمكتب الأمن (security1، security_office_2، security_office_3) كمعتمدين');
        return;
    }

    if (cnt === 1) {
        const only = await query('SELECT employee_id FROM security_office_approvers');
        const sec1 = await query(`SELECT employee_id FROM employees WHERE username = 'security1'`);
        if (only.length && sec1.length && only[0].employee_id === sec1[0].employee_id) {
            await run('DELETE FROM security_office_approvers');
            for (let i = 0; i < 3; i++) {
                await run('INSERT INTO security_office_approvers (sort_order, employee_id) VALUES (?, ?)', [i + 1, ids[i]]);
            }
            console.log('✅ تم توسيع معتمدي مكتب الأمن من حساب واحد إلى الثلاثة الافتراضية');
        }
    }
}

/** ثلاثة مسؤولي مكتب الأمن المعتمدين للموافقة على التصاريح واستلام إشعارات الطابور */
async function ensureSecurityOfficeApproversTable() {
    try {
        await run(`
            CREATE TABLE IF NOT EXISTS security_office_approvers (
                sort_order INTEGER PRIMARY KEY CHECK (sort_order >= 1 AND sort_order <= 3),
                employee_id INTEGER NOT NULL UNIQUE,
                FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
            )
        `);
        await ensureExtraSecurityOfficeEmployees();
        await syncSecurityOfficeApproversToDefaultThree();

        const cnt = await query('SELECT COUNT(*) as c FROM security_office_approvers');
        if ((cnt[0]?.c || 0) > 0) return;

        const sec = await query(`
            SELECT employee_id FROM employees
            WHERE user_type = 'security' AND (is_active IS NULL OR is_active = 1)
            ORDER BY employee_id ASC
            LIMIT 3
        `);
        let order = 1;
        for (const row of sec || []) {
            await run(
                'INSERT OR IGNORE INTO security_office_approvers (sort_order, employee_id) VALUES (?, ?)',
                [order++, row.employee_id]
            );
        }
        if ((sec || []).length > 0) {
            console.log(`✅ تهيئة مسؤولي مكتب الأمن الافتراضيين: ${sec.length} مستخدم(ين) من نوع security`);
        }
    } catch (e) {
        console.error('❌ ensureSecurityOfficeApproversTable:', e.message);
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
            entry_guard_username TEXT,
            exit_guard_username TEXT,
            actual_visitors_count INTEGER,
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
            company_name TEXT,
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

/**
 * نسخ قديمة من جدول permits تضع CHECK(status IN (...)) بدون checked_in / completed
 * فيفشل تسجيل دخول الحارس عند SET status = 'checked_in'. نعيد بناء الجدول بنفس الأعمدة بدون القيد.
 */
async function migratePermitsTableRemoveRestrictiveStatusCheck() {
    try {
        const rows = await query(`SELECT sql FROM sqlite_master WHERE type='table' AND name='permits'`);
        const ddl = rows[0]?.sql || '';
        if (!ddl) return;

        const hasStatusInCheck = /CHECK\s*\([^)]*\bstatus\b[^)]*\bIN\b/i.test(ddl);
        const allowsGuardFlow = /'checked_in'/.test(ddl) && /'completed'/.test(ddl);
        if (!hasStatusInCheck || allowsGuardFlow) return;

        console.log('🔧 ترحيل جدول permits: إزالة قيد CHECK على status لدعم تسجيل الدخول/الخروج عند الحارس…');

        const cols = await query('PRAGMA table_info(permits)');
        if (!cols.length) return;

        const colNames = cols.map((c) => c.name).join(', ');
        const colDefs = cols
            .map((c) => {
                const type = (c.type && String(c.type).trim()) || 'TEXT';
                if (c.pk === 1 && c.name === 'permit_id') {
                    return 'permit_id INTEGER PRIMARY KEY AUTOINCREMENT';
                }
                let def = `${c.name} ${type}`;
                if (c.notnull && c.pk !== 1) def += ' NOT NULL';
                if (c.dflt_value != null && c.dflt_value !== '') def += ` DEFAULT ${c.dflt_value}`;
                return def;
            })
            .join(', ');

        await run('PRAGMA foreign_keys = OFF');
        await run('BEGIN TRANSACTION');
        try {
            await run('DROP TABLE IF EXISTS permits__migration_tmp');
            await run(`CREATE TABLE permits__migration_tmp (${colDefs})`);
            await run(`INSERT INTO permits__migration_tmp (${colNames}) SELECT ${colNames} FROM permits`);
            await run('DROP TABLE permits');
            await run('ALTER TABLE permits__migration_tmp RENAME TO permits');
            await run('COMMIT');
            try {
                const maxRows = await query('SELECT MAX(permit_id) AS m FROM permits');
                const seq = maxRows[0]?.m || 0;
                await run(`DELETE FROM sqlite_sequence WHERE name = 'permits'`);
                if (seq > 0) {
                    await run(`INSERT INTO sqlite_sequence (name, seq) VALUES ('permits', ?)`, [seq]);
                }
            } catch (seqErr) {
                console.warn('⚠️ ملاحظة sqlite_sequence بعد ترحيل permits:', seqErr.message);
            }
            console.log('✅ اكتمل ترحيل permits (بدون قيد حالة يمنع checked_in)');
        } catch (inner) {
            await run('ROLLBACK').catch(() => {});
            throw inner;
        } finally {
            await run('PRAGMA foreign_keys = ON');
        }
    } catch (error) {
        console.error('❌ تعذر ترحيل جدول permits:', error.message);
    }
}

// تصاريح قديمة/إدراجات بدون تعبئة: permit_id يبقى NULL بينما rowid موجود — يكسر لوحة المدير والـ API
async function backfillPermitIdFromRowid() {
    try {
        const missing = await query(
            `SELECT COUNT(*) AS c FROM permits WHERE permit_id IS NULL OR CAST(permit_id AS TEXT) = ''`
        );
        const n = missing[0]?.c || 0;
        if (n === 0) return;
        const result = await run(
            `UPDATE permits SET permit_id = rowid WHERE permit_id IS NULL OR CAST(permit_id AS TEXT) = ''`
        );
        console.log(`✅ تم تعبئة permit_id من rowid لـ ${result?.changes ?? n} صف في permits`);
    } catch (error) {
        console.error('⚠️ تعذر تعبئة permit_id:', error.message);
    }
}

/**
 * نسخ قديمة من company_entry_permits تضع CHECK(status IN (...)) بـ checked_out دون completed
 * فيفشل guard-checkout عند SET status = 'completed'. نعيد بناء الجدول بنفس الأعمدة بدون القيد.
 */
async function migrateCompanyEntryPermitsRemoveRestrictiveStatusCheck() {
    try {
        const rows = await query(`SELECT sql FROM sqlite_master WHERE type='table' AND name='company_entry_permits'`);
        const ddl = rows[0]?.sql || '';
        if (!ddl) return;

        const hasStatusInCheck = /CHECK\s*\([^)]*\bstatus\b[^)]*\bIN\b/i.test(ddl);
        const allowsCompletedCheckout = /'checked_in'/.test(ddl) && /'completed'/.test(ddl);
        if (!hasStatusInCheck || allowsCompletedCheckout) return;

        console.log('🔧 ترحيل company_entry_permits: إزالة قيد CHECK على status لدعم إتمام الزيارة (completed)…');

        const cols = await query('PRAGMA table_info(company_entry_permits)');
        if (!cols.length) return;

        const colNames = cols.map((c) => c.name).join(', ');
        const colDefs = cols
            .map((c) => {
                const type = (c.type && String(c.type).trim()) || 'TEXT';
                if (c.pk === 1 && c.name === 'permit_id') {
                    return 'permit_id INTEGER PRIMARY KEY AUTOINCREMENT';
                }
                let def = `${c.name} ${type}`;
                if (c.notnull && c.pk !== 1) def += ' NOT NULL';
                if (c.dflt_value != null && c.dflt_value !== '') def += ` DEFAULT ${c.dflt_value}`;
                return def;
            })
            .join(', ');

        await run('PRAGMA foreign_keys = OFF');
        await run('BEGIN TRANSACTION');
        try {
            await run('DROP TABLE IF EXISTS company_entry_permits__migration_tmp');
            await run(`CREATE TABLE company_entry_permits__migration_tmp (${colDefs})`);
            await run(`INSERT INTO company_entry_permits__migration_tmp (${colNames}) SELECT ${colNames} FROM company_entry_permits`);
            await run('DROP TABLE company_entry_permits');
            await run('ALTER TABLE company_entry_permits__migration_tmp RENAME TO company_entry_permits');
            await run(`UPDATE company_entry_permits SET status = 'completed' WHERE status = 'checked_out'`);
            await run('COMMIT');
            try {
                const maxRows = await query('SELECT MAX(permit_id) AS m FROM company_entry_permits');
                const seq = maxRows[0]?.m || 0;
                await run(`DELETE FROM sqlite_sequence WHERE name = 'company_entry_permits'`);
                if (seq > 0) {
                    await run(`INSERT INTO sqlite_sequence (name, seq) VALUES ('company_entry_permits', ?)`, [seq]);
                }
            } catch (seqErr) {
                console.warn('⚠️ sqlite_sequence بعد ترحيل company_entry_permits:', seqErr.message);
            }
            console.log('✅ اكتمل ترحيل company_entry_permits (بدون قيد يمنع completed)');
        } catch (inner) {
            await run('ROLLBACK').catch(() => {});
            throw inner;
        } finally {
            await run('PRAGMA foreign_keys = ON');
        }
    } catch (error) {
        console.error('❌ تعذر ترحيل company_entry_permits:', error.message);
    }
}

/** أعمدة مطلوبة لـ POST guard-checkin / guard-checkout على تصاريح الشركات (قواعد قديمة بدونها) */
async function updateCompanyEntryPermitsTable() {
    try {
        const exists = await query(
            `SELECT name FROM sqlite_master WHERE type='table' AND name='company_entry_permits'`
        );
        if (!exists.length) return;

        await migrateCompanyEntryPermitsRemoveRestrictiveStatusCheck();

        const columns = await query(`PRAGMA table_info(company_entry_permits)`);
        const columnNames = columns.map((col) => col.name);

        const columnsToAdd = [
            { name: 'entry_guard_username', type: 'TEXT' },
            { name: 'exit_guard_username', type: 'TEXT' },
            { name: 'actual_visitors_count', type: 'INTEGER' }
        ];

        for (const col of columnsToAdd) {
            if (!columnNames.includes(col.name)) {
                await run(`ALTER TABLE company_entry_permits ADD COLUMN ${col.name} ${col.type}`);
                console.log(`✅ company_entry_permits: تم إضافة العمود ${col.name}`);
            }
        }
    } catch (error) {
        console.error('❌ خطأ في تحديث جدول company_entry_permits:', error.message);
    }
}

// تحديث جدول التصاريح
async function updatePermitsTable() {
    try {
        await migratePermitsTableRemoveRestrictiveStatusCheck();
        await backfillPermitIdFromRowid();

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
    updateCompanyEntryPermitsTable,
    migratePermitsTableRemoveRestrictiveStatusCheck,
    migrateCompanyEntryPermitsRemoveRestrictiveStatusCheck,
    addEssentialUsers,
    ensureSecurityOfficeApproversTable,
    updateEmployeesDeputyColumn,
    migrateEmployeesRemoveRestrictiveUserTypeCheck,
    ensureDeputyManagerDemoUser
};

