-- ============================================
-- نظام تصاريح العمل - قاعدة البيانات
-- مع تحديثات مكتب الأمن ونقطة الحراسة
-- ============================================

-- جدول الأقسام (يجب أن يكون أولاً لوجود مفتاح أجنبي)
CREATE TABLE IF NOT EXISTS departments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) NOT NULL,
    type VARCHAR(50) NOT NULL,
    manager_id INTEGER,
    parent_id INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (manager_id) REFERENCES employees(employee_id),
    FOREIGN KEY (parent_id) REFERENCES departments(id)
);

-- جدول الموظفين
CREATE TABLE IF NOT EXISTS employees (
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
    
    -- أنواع المستخدمين (تم تحديثها)
    user_type VARCHAR(20) DEFAULT 'employee' CHECK (
        user_type IN ('employee', 'manager', 'security', 'security_guard', 'admin')
    ),
    
    is_active BOOLEAN DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- معلومات إضافية للحرس
    guard_shift VARCHAR(50),
    guard_location VARCHAR(100),
    
    FOREIGN KEY (department_id) REFERENCES departments(id),
    FOREIGN KEY (manager_id) REFERENCES employees(employee_id)
);

-- جدول التصاريح (مع جميع الحقول الجديدة)
CREATE TABLE IF NOT EXISTS permits (
    permit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INTEGER NOT NULL,
    request_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reason TEXT NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    expected_exit_time TIME NOT NULL,
    
    -- حالات التصريح (تم تحديثها)
    status VARCHAR(30) DEFAULT 'pending_manager' CHECK (
        status IN (
            'pending_manager',      -- بانتظار المدير
            'pending_security',     -- بانتظار مكتب الأمن
            'approved_security',    -- وافق الأمن (جاهز للحارس) ✅ جديد
            'checked_in',          -- مسجل دخول
            'completed',           -- مكتمل
            'rejected_manager',    -- مرفوض من المدير
            'rejected_security'    -- مرفوض من الأمن
        )
    ),
    
    -- موافقة المدير
    manager_username VARCHAR(50),
    manager_decision VARCHAR(10) CHECK (manager_decision IN ('allow', 'reject', NULL)),
    manager_decision_date TIMESTAMP,
    manager_notes TEXT,
    
    -- موافقة الأمن
    security_username VARCHAR(50),
    security_decision VARCHAR(10) CHECK (security_decision IN ('allow', 'reject', NULL)),
    security_decision_date TIMESTAMP,
    security_notes TEXT,
    
    -- تسجيل الحارس ✅ حقول جديدة
    actual_entry_time TIME,
    actual_exit_time TIME,
    entry_guard_username VARCHAR(50),
    exit_guard_username VARCHAR(50),
    entry_notes TEXT,
    exit_notes TEXT,
    checkin_timestamp TIMESTAMP,
    checkout_timestamp TIMESTAMP,
    
    -- معلومات إضافية
    emergency_contact VARCHAR(15),
    work_location VARCHAR(100),
    
    -- تواريخ النظام
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (employee_id) REFERENCES employees(employee_id),
    FOREIGN KEY (manager_username) REFERENCES employees(username),
    FOREIGN KEY (security_username) REFERENCES employees(username),
    FOREIGN KEY (entry_guard_username) REFERENCES employees(username),
    FOREIGN KEY (exit_guard_username) REFERENCES employees(username)
);

-- جدول إشعارات النظام
CREATE TABLE IF NOT EXISTS notifications (
    notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title VARCHAR(200) NOT NULL,
    message TEXT NOT NULL,
    notification_type VARCHAR(20) NOT NULL CHECK (
        notification_type IN ('info', 'warning', 'success', 'error', 'alert')
    ),
    related_permit_id INTEGER,
    is_read BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- معلومات الإرسال
    sent_by VARCHAR(50),
    priority INTEGER DEFAULT 1 CHECK (priority BETWEEN 1 AND 5),
    
    FOREIGN KEY (user_id) REFERENCES employees(employee_id),
    FOREIGN KEY (related_permit_id) REFERENCES permits(permit_id)
);

-- جدول سجل الحراسة (للتدقيق)
CREATE TABLE IF NOT EXISTS guard_logs (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    permit_id INTEGER NOT NULL,
    guard_username VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL CHECK (
        action IN ('checkin', 'checkout', 'verify', 'reject', 'note')
    ),
    action_time TIME NOT NULL,
    action_date DATE NOT NULL,
    notes TEXT,
    location VARCHAR(100),
    ip_address VARCHAR(45),
    device_info TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (permit_id) REFERENCES permits(permit_id),
    FOREIGN KEY (guard_username) REFERENCES employees(username)
);

-- جدول مخالفات التوقيت
CREATE TABLE IF NOT EXISTS time_violations (
    violation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    permit_id INTEGER NOT NULL,
    employee_id INTEGER NOT NULL,
    violation_type VARCHAR(50) CHECK (
        violation_type IN ('early_checkin', 'late_checkout', 'unauthorized', 'mismatch')
    ),
    expected_time TIME,
    actual_time TIME,
    time_difference INTEGER, -- بالدقائق
    severity VARCHAR(20) CHECK (severity IN ('low', 'medium', 'high')),
    notes TEXT,
    reported_by VARCHAR(50),
    resolved BOOLEAN DEFAULT 0,
    resolved_by VARCHAR(50),
    resolved_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (permit_id) REFERENCES permits(permit_id),
    FOREIGN KEY (employee_id) REFERENCES employees(employee_id),
    FOREIGN KEY (reported_by) REFERENCES employees(username),
    FOREIGN KEY (resolved_by) REFERENCES employees(username)
);

-- جدول نوبات الحراس
CREATE TABLE IF NOT EXISTS guard_shifts (
    shift_id INTEGER PRIMARY KEY AUTOINCREMENT,
    guard_username VARCHAR(50) NOT NULL,
    shift_date DATE NOT NULL,
    shift_type VARCHAR(20) CHECK (shift_type IN ('morning', 'evening', 'night', 'custom')),
    start_time TIME NOT NULL,
    end_time TIME NOT NULL,
    location VARCHAR(100) NOT NULL,
    status VARCHAR(20) DEFAULT 'scheduled' CHECK (
        status IN ('scheduled', 'active', 'completed', 'cancelled')
    ),
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(guard_username, shift_date, shift_type),
    FOREIGN KEY (guard_username) REFERENCES employees(username)
);

-- جدول إحصائيات الحراسة
CREATE TABLE IF NOT EXISTS guard_statistics (
    stat_id INTEGER PRIMARY KEY AUTOINCREMENT,
    guard_username VARCHAR(50) NOT NULL,
    stat_date DATE NOT NULL,
    total_permits INTEGER DEFAULT 0,
    checked_in_count INTEGER DEFAULT 0,
    checked_out_count INTEGER DEFAULT 0,
    violations_count INTEGER DEFAULT 0,
    avg_checkin_time TIME,
    avg_checkout_time TIME,
    total_hours DECIMAL(5,2) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(guard_username, stat_date),
    FOREIGN KEY (guard_username) REFERENCES employees(username)
);

-- ============================================
-- البيانات الأولية
-- ============================================

-- إدخال بيانات الأقسام الافتراضية
INSERT OR IGNORE INTO departments (id, name, type) VALUES
(1, 'الإدارة العامة', 'admin'),
(2, 'قسم تقنية المعلومات', 'technical'),
(3, 'قسم الموارد البشرية', 'hr'),
(4, 'قسم المالية', 'finance'),
(5, 'قسم الأمن والسلامة', 'security');

-- إدخال بيانات مسؤول النظام
INSERT OR IGNORE INTO employees (
    username, password_hash, full_name, job_number, directorate, department_id, 
    position, email, phone, user_type
) VALUES (
    'admin', 
    '$2b$10$YourHashedPasswordHere', -- استبدلها بكلمة مرور مشفرة
    'مسؤول النظام', 
    'ADMIN001', 
    'الإدارة العامة', 
    1, 
    'مسؤول النظام',
    'admin@company.com',
    '0555000001',
    'admin'
);

-- إدخال بيانات حراس الأمن
INSERT OR IGNORE INTO employees (
    username, password_hash, full_name, job_number, directorate, department_id,
    position, email, phone, user_type, guard_shift, guard_location
) VALUES
(
    'guard1',
    '$2b$10$YourHashedPasswordHere',
    'حارس أمن ١',
    'SEC001',
    'الإدارة العامة',
    5,
    'حارس أمن',
    'guard1@company.com',
    '0555111222',
    'security_guard',
    'morning',
    'البوابة الرئيسية'
),
(
    'guard2',
    '$2b$10$YourHashedPasswordHere',
    'حارس أمن ٢',
    'SEC002',
    'الإدارة العامة',
    5,
    'حارس أمن',
    'guard2@company.com',
    '0555111333',
    'security_guard',
    'evening',
    'البوابة الرئيسية'
),
(
    'guard3',
    '$2b$10$YourHashedPasswordHere',
    'حارس أمن ٣',
    'SEC003',
    'الإدارة العامة',
    5,
    'حارس أمن',
    'guard3@company.com',
    '0555111444',
    'security_guard',
    'night',
    'البوابة الجانبية'
);

-- إدخال بيانات مسؤول أمن
INSERT OR IGNORE INTO employees (
    username, password_hash, full_name, job_number, directorate, department_id,
    position, email, phone, user_type
) VALUES (
    'security',
    '$2b$10$YourHashedPasswordHere',
    'مسؤول الأمن',
    'SEC004',
    'الإدارة العامة',
    5,
    'رئيس قسم الأمن',
    'security@company.com',
    '0555111555',
    'security'
);

-- ============================================
-- الفهارس لتحسين الأداء
-- ============================================

CREATE INDEX IF NOT EXISTS idx_permits_status ON permits(status);
CREATE INDEX IF NOT EXISTS idx_permits_employee ON permits(employee_id);
CREATE INDEX IF NOT EXISTS idx_permits_dates ON permits(start_date, end_date);
CREATE INDEX IF NOT EXISTS idx_permits_entry_time ON permits(actual_entry_time);
CREATE INDEX IF NOT EXISTS idx_permits_security ON permits(security_username, security_decision_date);
CREATE INDEX IF NOT EXISTS idx_permits_guard ON permits(entry_guard_username, exit_guard_username);

CREATE INDEX IF NOT EXISTS idx_employees_usertype ON employees(user_type);
CREATE INDEX IF NOT EXISTS idx_employees_department ON employees(department_id);
CREATE INDEX IF NOT EXISTS idx_employees_username ON employees(username);

CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, is_read);
CREATE INDEX IF NOT EXISTS idx_notifications_permit ON notifications(related_permit_id);

CREATE INDEX IF NOT EXISTS idx_guard_logs_permit ON guard_logs(permit_id);
CREATE INDEX IF NOT EXISTS idx_guard_logs_guard ON guard_logs(guard_username, action_date);

CREATE INDEX IF NOT EXISTS idx_violations_permit ON time_violations(permit_id);
CREATE INDEX IF NOT EXISTS idx_violations_employee ON time_violations(employee_id, resolved);

-- ============================================
-- المشغلات (Triggers)
-- ============================================

-- تحديث updated_at تلقائياً
CREATE TRIGGER IF NOT EXISTS update_permits_timestamp 
AFTER UPDATE ON permits
BEGIN
    UPDATE permits SET updated_at = CURRENT_TIMESTAMP WHERE permit_id = NEW.permit_id;
END;

-- تسجيل سجل الحراسة عند التسجيل
CREATE TRIGGER IF NOT EXISTS log_guard_checkin 
AFTER UPDATE OF actual_entry_time ON permits
WHEN NEW.actual_entry_time IS NOT NULL AND OLD.actual_entry_time IS NULL
BEGIN
    INSERT INTO guard_logs (permit_id, guard_username, action, action_time, action_date, notes, location)
    VALUES (
        NEW.permit_id,
        NEW.entry_guard_username,
        'checkin',
        NEW.actual_entry_time,
        DATE(NEW.checkin_timestamp),
        NEW.entry_notes,
        'نقطة الحراسة الرئيسية'
    );
END;

CREATE TRIGGER IF NOT EXISTS log_guard_checkout 
AFTER UPDATE OF actual_exit_time ON permits
WHEN NEW.actual_exit_time IS NOT NULL AND OLD.actual_exit_time IS NULL
BEGIN
    INSERT INTO guard_logs (permit_id, guard_username, action, action_time, action_date, notes, location)
    VALUES (
        NEW.permit_id,
        NEW.exit_guard_username,
        'checkout',
        NEW.actual_exit_time,
        DATE(NEW.checkout_timestamp),
        NEW.exit_notes,
        'نقطة الحراسة الرئيسية'
    );
END;

-- التحقق من تأخر الخروج وإضافة مخالفة
CREATE TRIGGER IF NOT EXISTS check_late_checkout 
AFTER UPDATE OF actual_exit_time ON permits
WHEN NEW.actual_exit_time IS NOT NULL AND NEW.expected_exit_time IS NOT NULL
BEGIN
    -- حساب الفرق بالدقائق
    WITH time_diff AS (
        SELECT 
            (strftime('%s', NEW.actual_exit_time) - strftime('%s', NEW.expected_exit_time)) / 60 AS diff_minutes
    )
    INSERT OR IGNORE INTO time_violations (
        permit_id, employee_id, violation_type, expected_time, actual_time, 
        time_difference, severity, reported_by
    )
    SELECT 
        NEW.permit_id,
        NEW.employee_id,
        'late_checkout',
        NEW.expected_exit_time,
        NEW.actual_exit_time,
        diff_minutes,
        CASE 
            WHEN diff_minutes > 60 THEN 'high'
            WHEN diff_minutes > 30 THEN 'medium'
            ELSE 'low'
        END,
        NEW.exit_guard_username
    FROM time_diff
    WHERE diff_minutes > 15; -- إذا تأخر أكثر من 15 دقيقة
END;

-- ============================================
-- البيانات التجريبية للاختبار
-- ============================================

-- موظفين تجريبيين
INSERT OR IGNORE INTO employees (
    username, password_hash, full_name, job_number, directorate, department_id,
    position, email, phone, user_type, manager_id
) VALUES
(
    'employee1',
    '$2b$10$YourHashedPasswordHere',
    'أحمد محمد',
    'EMP001',
    'الإدارة العامة',
    2,
    'مبرمج',
    'ahmed@company.com',
    '0555222111',
    'employee',
    1
),
(
    'manager1',
    '$2b$10$YourHashedPasswordHere',
    'سالم العلي',
    'MGR001',
    'الإدارة العامة',
    2,
    'مدير قسم',
    'manager@company.com',
    '0555222333',
    'manager',
    NULL
);

-- تصريح تجريبي معتمد من المدير وبانتظار الأمن
INSERT OR IGNORE INTO permits (
    employee_id, reason, start_date, end_date, expected_exit_time,
    status, manager_username, manager_decision, manager_decision_date,
    manager_notes
) VALUES (
    6, -- employee1
    'إكمال مشروع نظام التصاريح',
    DATE('now'),
    DATE('now'),
    '20:00:00',
    'pending_security',
    'manager1',
    'allow',
    DATETIME('now', '-1 hour'),
    'موافق - العمل ضروري'
);

-- تصريح تجريبي معتمد من الأمن وجاهز للحارس
INSERT OR IGNORE INTO permits (
    employee_id, reason, start_date, end_date, expected_exit_time,
    status, manager_username, manager_decision, manager_decision_date,
    security_username, security_decision, security_decision_date
) VALUES (
    6, -- employee1
    'عمل إضافي عاجل',
    DATE('now'),
    DATE('now'),
    '19:30:00',
    'approved_security',
    'manager1',
    'allow',
    DATETIME('now', '-2 hours'),
    'security',
    'allow',
    DATETIME('now', '-1 hour')
);

-- ============================================
-- عرض جداول قاعدة البيانات
-- ============================================

-- .tables
-- SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;

PRAGMA foreign_keys = ON;

-- ============================================
-- نهاية ملف schema.sql
-- ============================================