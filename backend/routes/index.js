const express = require('express');
const router = express.Router();
const { query, run } = require('../database');

// ========== 1. مسار الإحصائيات (للمدير والأمن) ==========
router.get('/stats/:username', async (req, res) => {
    try {
        const { username } = req.params;
        console.log(`📊 جلب إحصائيات: ${username}`);
        
        // جلب دور المستخدم
        const user = await query('SELECT role, department_name FROM employees WHERE username = ?', [username]);
        
        if (user.length === 0) {
            return res.json({ 
                success: true, 
                stats: {
                    pending_requests: 0,
                    today_approved: 0,
                    today_rejected: 0
                },
                user_role: 'unknown'
            });
        }
        
        const userRole = user[0].role;
        const department = user[0].department_name;
        
        let stats = {};
        
        // ===== إذا كان مدير أو أمن =====
        if (userRole === 'manager' || userRole === 'security_admin') {
            // 1. التصاريح المعلقة في القسم
            const pendingResult = await query(`
                SELECT COUNT(*) as count 
                FROM permits p
                JOIN employees e ON p.employee_username = e.username
                WHERE p.status = 'pending' 
                  AND e.department_name = ?
            `, [department]);
            
            // 2. التصاريح المعتمدة اليوم
            const today = new Date().toISOString().split('T')[0];
            const approvedResult = await query(`
                SELECT COUNT(*) as count 
                FROM permits p
                JOIN employees e ON p.employee_username = e.username
                WHERE (p.status = 'approved_manager' OR p.status = 'approved_security')
                  AND DATE(p.manager_action_date) = ?
                  AND e.department_name = ?
            `, [today, department]);
            
            // 3. التصاريح المرفوضة اليوم
            const rejectedResult = await query(`
                SELECT COUNT(*) as count 
                FROM permits p
                JOIN employees e ON p.employee_username = e.username
                WHERE p.status = 'rejected'
                  AND DATE(p.manager_action_date) = ?
                  AND e.department_name = ?
            `, [today, department]);
            
            stats = {
                pending_requests: pendingResult[0]?.count || 0,
                today_approved: approvedResult[0]?.count || 0,
                today_rejected: rejectedResult[0]?.count || 0
            };
            
        } 
        // ===== إذا كان حارس =====
        else if (userRole === 'security_guard') {
            const currentTime = new Date().toLocaleTimeString('en-US', { hour12: false });
            
            // التصاريح النشطة خلال نوبة الحارس
            const activePermitsResult = await query(`
                SELECT COUNT(*) as count 
                FROM permits p
                WHERE p.status = 'approved_security'
                  AND TIME(p.end_time) >= TIME(?)
            `, [currentTime]);
            
            // الموظفين الموجودين حالياً
            const presentEmployeesResult = await query(`
                SELECT COUNT(DISTINCT p.employee_username) as count 
                FROM permits p
                WHERE p.status = 'approved_security'
                  AND p.actual_check_in IS NOT NULL
                  AND p.actual_check_out IS NULL
            `);
            
            stats = {
                active_permits: activePermitsResult[0]?.count || 0,
                present_employees: presentEmployeesResult[0]?.count || 0,
                pending_requests: 0, // الحارس لا يرى الطلبات المعلقة
                today_rejected: 0    // الحارس لا يرى المرفوضات
            };
        }
        
        console.log('📈 الإحصائيات:', stats, 'الدور:', userRole);
        
        res.json({ 
            success: true, 
            stats: stats,
            user_role: userRole
        });
        
    } catch (error) {
        console.error('❌ خطأ في جلب الإحصائيات:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في جلب الإحصائيات' 
        });
    }
});

// ========== 2. مسار البحث في التصاريح (للجميع) ==========
router.get('/permits/search', async (req, res) => {
    try {
        const { q = '', type = 'all', username } = req.query;
        console.log(`🔍 بحث في التصاريح: ${q}, نوع: ${type}, مستخدم: ${username}`);
        
        // جلب دور المستخدم
        let userRole = 'employee';
        if (username) {
            const user = await query('SELECT role FROM employees WHERE username = ?', [username]);
            if (user.length > 0) {
                userRole = user[0].role;
            }
        }
        
        let sql = `
            SELECT p.*, e.full_name, e.job_number, e.directorate, e.department_name
            FROM permits p
            JOIN employees e ON p.employee_username = e.username
            WHERE 1=1
        `;
        
        const params = [];
        
        // ===== تصفية حسب دور المستخدم =====
        if (userRole === 'security_guard') {
            // الحارس يرى فقط التصاريح النشطة والمقبولة
            sql += ` AND p.status = 'approved_security'`;
            
            // فقط التصاريح التي لم تنتهِ وقتها
            const currentTime = new Date().toLocaleTimeString('en-US', { hour12: false });
            sql += ` AND TIME(p.end_time) >= TIME(?)`;
            params.push(currentTime);
        }
        else if (userRole === 'manager') {
            // المدير يرى فقط تصاريح قسمه
            const user = await query('SELECT department_name FROM employees WHERE username = ?', [username]);
            if (user.length > 0) {
                sql += ` AND e.department_name = ?`;
                params.push(user[0].department_name);
            }
        }
        
        // تطبيق عوامل التصفية الإضافية
        if (q) {
            sql += ` AND (
                e.full_name LIKE ? OR 
                e.job_number LIKE ? OR 
                p.reason LIKE ? OR
                p.permit_id LIKE ?
            )`;
            const searchTerm = `%${q}%`;
            params.push(searchTerm, searchTerm, searchTerm, searchTerm);
        }
        
        if (type === 'recent') {
            sql += ` ORDER BY p.request_date DESC LIMIT 10`;
        } else if (type === 'pending') {
            sql += ` AND p.status = 'pending'`;
        } else if (type === 'approved') {
            sql += ` AND (p.status = 'approved_manager' OR p.status = 'approved_security')`;
        }
        
        console.log('📝 استعلام SQL:', sql);
        
        const permits = await query(sql, params);
        
        res.json({ 
            success: true, 
            permits: permits,
            count: permits.length,
            user_role: userRole
        });
        
    } catch (error) {
        console.error('❌ خطأ في البحث:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في البحث' 
        });
    }
});

// ========== 3. مسار الإشعارات ==========
router.get('/notifications/:username', async (req, res) => {
    try {
        const { username } = req.params;
        console.log(`📢 جلب إشعارات: ${username}`);
        
        // جلب دور المستخدم
        const user = await query('SELECT role FROM employees WHERE username = ?', [username]);
        const userRole = user.length > 0 ? user[0].role : 'employee';
        
        // أولاً: تحقق من وجود جدول notifications
        const tableCheck = await query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='notifications'"
        );
        
        if (tableCheck.length === 0) {
            // إشعارات افتراضية حسب الدور
            let defaultNotification = {
                notification_id: 1,
                title: 'مرحباً بك في النظام',
                message: 'يمكنك الآن إدارة تصاريح الموظفين',
                type: 'info',
                created_at: new Date().toISOString(),
                is_read: 0
            };
            
            if (userRole === 'security_guard') {
                defaultNotification = {
                    notification_id: 1,
                    title: 'مرحباً بك حارس الآمن',
                    message: 'يمكنك الآن مراقبة التصاريح النشطة وتسجيل دخول الموظفين',
                    type: 'info',
                    created_at: new Date().toISOString(),
                    is_read: 0
                };
            }
            
            return res.json({
                success: true,
                notifications: [defaultNotification],
                unread_count: 1
            });
        }
        
        // جلب الإشعارات من الجدول
        const notifications = await query(`
            SELECT * FROM notifications 
            WHERE username = ? 
            ORDER BY created_at DESC 
            LIMIT 20
        `, [username]);
        
        // عد الإشعارات غير المقروءة
        const unreadCount = await query(`
            SELECT COUNT(*) as count 
            FROM notifications 
            WHERE username = ? AND is_read = 0
        `, [username]);
        
        console.log(`✅ تم العثور على ${notifications.length} إشعار`);
        
        res.json({
            success: true,
            notifications: notifications,
            unread_count: unreadCount[0]?.count || 0
        });
        
    } catch (error) {
        console.error('❌ خطأ في جلب الإشعارات:', error);
        
        // في حالة الخطأ، أرجع بيانات تجريبية
        res.json({
            success: true,
            notifications: [],
            unread_count: 0
        });
    }
});

// ========== 4. تحديث حالة الإشعار ==========
router.post('/notifications/mark-read', async (req, res) => {
    try {
        const { notification_id, username } = req.body;
        console.log(`📌 تحديث إشعار: ${notification_id} لـ ${username}`);
        
        // تحقق من وجود الجدول أولاً
        const tableCheck = await query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='notifications'"
        );
        
        if (tableCheck.length === 0) {
            return res.json({ success: true, message: 'تم المحاكاة' });
        }
        
        await run(`
            UPDATE notifications 
            SET is_read = 1 
            WHERE notification_id = ? AND username = ?
        `, [notification_id, username]);
        
        res.json({ success: true, message: 'تم تحديث الإشعار' });
        
    } catch (error) {
        console.error('❌ خطأ في تحديث الإشعار:', error);
        res.json({ success: true, message: 'تم المحاكاة' });
    }
});

// ========== 5. تحديث كل الإشعارات ==========
router.post('/notifications/mark-all-read', async (req, res) => {
    try {
        const { username } = req.body;
        console.log(`📌 تحديث كل إشعارات: ${username}`);
        
        // تحقق من وجود الجدول أولاً
        const tableCheck = await query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='notifications'"
        );
        
        if (tableCheck.length === 0) {
            return res.json({ success: true, message: 'تم المحاكاة' });
        }
        
        await run(`
            UPDATE notifications 
            SET is_read = 1 
            WHERE username = ?
        `, [username]);
        
        res.json({ success: true, message: 'تم تحديث جميع الإشعارات' });
        
    } catch (error) {
        console.error('❌ خطأ في تحديث الإشعارات:', error);
        res.json({ success: true, message: 'تم المحاكاة' });
    }
});

// ========== 6. مسارات خاصة بالحارس ==========

// جلب التصاريح النشطة للحارس
router.get('/guard/active-permits/:username', async (req, res) => {
    try {
        const { username } = req.params;
        console.log(`👮 جلب تصاريح الحارس النشطة: ${username}`);
        
        const currentTime = new Date().toLocaleTimeString('en-US', { hour12: false });
        const today = new Date().toISOString().split('T')[0];
        
        const activePermits = await query(`
            SELECT 
                p.permit_id,
                p.employee_username,
                e.full_name as employee_name,
                e.job_number,
                e.directorate,
                e.department_name,
                p.reason,
                p.start_time,
                p.end_time,
                p.status,
                p.actual_check_in,
                p.actual_check_out,
                p.request_date
            FROM permits p
            JOIN employees e ON p.employee_username = e.username
            WHERE p.status = 'approved_security'
              AND DATE(p.request_date) = ?
              AND TIME(p.end_time) >= TIME(?)
            ORDER BY p.end_time ASC
        `, [today, currentTime]);
        
        // جلب معلومات الحارس
        const guardInfo = await query(`
            SELECT g.*, e.full_name
            FROM guards g
            JOIN employees e ON g.username = e.username
            WHERE g.username = ?
        `, [username]);
        
        console.log(`✅ عدد التصاريح النشطة: ${activePermits.length}`);
        
        res.json({ 
            success: true, 
            permits: activePermits,
            guard_info: guardInfo[0] || { full_name: 'حارس الآمن' }
        });
        
    } catch (error) {
        console.error('❌ خطأ في جلب تصاريح الحارس:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في جلب التصاريح' 
        });
    }
});

// تسجيل دخول/خروج الموظف
router.post('/guard/log-action', async (req, res) => {
    try {
        const { permit_id, action, guard_username } = req.body;
        
        console.log(`📝 تسجيل ${action} للتصريح: ${permit_id} بواسطة: ${guard_username}`);
        
        // التحقق من أن التصريح موجود ونشط
        const permitCheck = await query(`
            SELECT p.* FROM permits p
            WHERE p.permit_id = ?
              AND p.status = 'approved_security'
        `, [permit_id]);
        
        if (permitCheck.length === 0) {
            return res.json({ 
                success: false, 
                message: 'التصريح غير موجود أو غير مفعل' 
            });
        }
        
        const permit = permitCheck[0];
        
        // التحقق من الوقت
        const currentTime = new Date();
        const endTime = new Date(`${new Date().toISOString().split('T')[0]}T${permit.end_time}`);
        
        if (currentTime > endTime) {
            return res.json({ 
                success: false, 
                message: 'انتهى وقت التصريح' 
            });
        }
        
        // تحديث حقل الدخول أو الخروج
        let updateField = '';
        let actionArabic = '';
        
        if (action === 'check_in') {
            if (permit.actual_check_in) {
                return res.json({ 
                    success: false, 
                    message: 'تم تسجيل الدخول مسبقاً' 
                });
            }
            updateField = 'actual_check_in';
            actionArabic = 'دخول';
        } else if (action === 'check_out') {
            if (!permit.actual_check_in) {
                return res.json({ 
                    success: false, 
                    message: 'يجب تسجيل الدخول أولاً' 
                });
            }
            if (permit.actual_check_out) {
                return res.json({ 
                    success: false, 
                    message: 'تم تسجيل الخروج مسبقاً' 
                });
            }
            updateField = 'actual_check_out';
            actionArabic = 'خروج';
        } else {
            return res.json({ 
                success: false, 
                message: 'إجراء غير صالح' 
            });
        }
        
        // تنفيذ التحديث
        await run(`
            UPDATE permits 
            SET ${updateField} = DATETIME('now')
            WHERE permit_id = ?
        `, [permit_id]);
        
        // تسجيل في سجل الحراس
        await run(`
            INSERT INTO guard_logs (permit_id, guard_username, action, action_time)
            VALUES (?, ?, ?, DATETIME('now'))
        `, [permit_id, guard_username, action]);
        
        console.log(`✅ تم ${action} بنجاح للتصريح: ${permit_id}`);
        
        res.json({ 
            success: true, 
            message: `تم تسجيل ${actionArabic} الموظف بنجاح`,
            permit: {
                ...permit,
                [updateField]: new Date().toISOString()
            }
        });
        
    } catch (error) {
        console.error('❌ خطأ في تسجيل الإجراء:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في التسجيل' 
        });
    }
});

// جلب سجل الحراس
router.get('/guard/logs/:username', async (req, res) => {
    try {
        const { username } = req.params;
        const { limit = 20 } = req.query;
        
        console.log(`📋 جلب سجل الحراس: ${username}`);
        
        const logs = await query(`
            SELECT 
                gl.*,
                p.employee_username,
                e.full_name as employee_name,
                p.permit_id,
                p.reason
            FROM guard_logs gl
            JOIN permits p ON gl.permit_id = p.permit_id
            JOIN employees e ON p.employee_username = e.username
            WHERE gl.guard_username = ?
            ORDER BY gl.action_time DESC
            LIMIT ?
        `, [username, parseInt(limit)]);
        
        res.json({ 
            success: true, 
            logs: logs,
            count: logs.length
        });
        
    } catch (error) {
        console.error('❌ خطأ في جلب سجل الحراس:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في جلب السجل' 
        });
    }
});

// جلب الموظفين الموجودين حالياً
router.get('/guard/present-employees', async (req, res) => {
    try {
        console.log('👥 جلب الموظفين الموجودين حالياً');
        
        const presentEmployees = await query(`
            SELECT 
                p.permit_id,
                p.employee_username,
                e.full_name,
                e.job_number,
                e.department_name,
                p.actual_check_in,
                p.start_time,
                p.end_time,
                p.reason
            FROM permits p
            JOIN employees e ON p.employee_username = e.username
            WHERE p.status = 'approved_security'
              AND p.actual_check_in IS NOT NULL
              AND p.actual_check_out IS NULL
              AND TIME(p.end_time) >= TIME(?)
            ORDER BY p.actual_check_in DESC
        `, [new Date().toLocaleTimeString('en-US', { hour12: false })]);
        
        res.json({ 
            success: true, 
            employees: presentEmployees,
            count: presentEmployees.length
        });
        
    } catch (error) {
        console.error('❌ خطأ في جلب الموظفين الموجودين:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في جلب الموظفين' 
        });
    }
    // ========== 7. نظام التنبيهات ==========

// // ========== 7. نظام التنبيهات ==========

// إرسال تنبيه للحارس عندما يوافق مكتب الأمن على تصريح
router.post('/notify/guard', async (req, res) => {
    try {
        const { permit_id, employee_name, end_time, security_username } = req.body;
        
        console.log(`📢 إرسال تنبيه للحارس بخصوص التصريح: ${permit_id}`);
        
        // 1. الحصول على الحارس المناوب حالياً
        const currentTime = new Date().toLocaleTimeString('en-US', { hour12: false });
        
        const onDutyGuard = await query(`
            SELECT g.username, e.full_name 
            FROM guards g
            JOIN employees e ON g.username = e.username
            WHERE TIME(?) BETWEEN TIME(g.shift_start) AND TIME(g.shift_end)
            LIMIT 1
        `, [currentTime]);
        
        if (onDutyGuard.length === 0) {
            return res.json({ 
                success: false, 
                message: 'لا يوجد حارس مناوب حالياً' 
            });
        }
        
        const guard = onDutyGuard[0];
        
        // 2. إنشاء تنبيه للحارس
        await run(`
            INSERT INTO notifications (username, title, message, type, related_id, created_at)
            VALUES (?, ?, ?, ?, ?, DATETIME('now'))
        `, [
            guard.username,
            'تصريح جديد',
            `تمت الموافقة على تصريح للموظف ${employee_name} حتى ${end_time}`,
            'permit_approved',
            permit_id
        ]);
        
        // 3. إرسال تنبيه للموظف
        const employee = await query(
            'SELECT username FROM permits WHERE permit_id = ?',
            [permit_id]
        );
        
        if (employee.length > 0) {
            await run(`
                INSERT INTO notifications (username, title, message, type, related_id, created_at)
                VALUES (?, ?, ?, ?, ?, DATETIME('now'))
            `, [
                employee[0].username,
                'تمت الموافقة على طلبك',
                `تمت الموافقة على تصريحك حتى ${end_time}. يرجى تسجيل الدخول عند الحارس`,
                'permit_approved',
                permit_id
            ]);
        }
        
        console.log(`✅ تم إرسال تنبيه للحارس: ${guard.full_name}`);
        
        res.json({ 
            success: true, 
            message: 'تم إرسال التنبيه للحارس',
            guard: guard.full_name
        });
        
    } catch (error) {
        console.error('❌ خطأ في إرسال التنبيه:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في إرسال التنبيه' 
        });
    }
});

// إرسال تنبيه لمكتب الأمن عندما يغادر الموظف
router.post('/notify/security', async (req, res) => {
    try {
        const { permit_id, employee_name, guard_name, check_out_time } = req.body;
        
        console.log(`📢 إرسال تنبيه لمكتب الأمن بخصوص خروج الموظف: ${employee_name}`);
        
        // 1. الحصول على موظفي الأمن
        const securityStaff = await query(`
            SELECT username FROM employees WHERE role = 'security'
        `);
        
        // 2. إرسال تنبيه لكل موظف أمن
        for (const staff of securityStaff) {
            await run(`
                INSERT INTO notifications (username, title, message, type, related_id, created_at)
                VALUES (?, ?, ?, ?, ?, DATETIME('now'))
            `, [
                staff.username,
                'خروج موظف',
                `غادر الموظف ${employee_name} الساعة ${check_out_time} (الحارس: ${guard_name})`,
                'employee_exited',
                permit_id
            ]);
        }
        
        // 3. تحديث حالة التصريح
        await run(`
            UPDATE permits 
            SET status = 'completed', 
                security_notified = 1 
            WHERE permit_id = ?
        `, [permit_id]);
        
        console.log(`✅ تم إرسال تنبيه لـ ${securityStaff.length} من موظفي الأمن`);
        
        res.json({ 
            success: true, 
            message: 'تم إرسال التنبيه لمكتب الأمن',
            notified_count: securityStaff.length
        });
        
    } catch (error) {
        console.error('❌ خطأ في إرسال التنبيه:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في إرسال التنبيه' 
        });
    }
});

// الحصول على تنبيهات غير مقروءة
router.get('/notifications/unread/:username', async (req, res) => {
    try {
        const { username } = req.params;
        
        const notifications = await query(`
            SELECT * FROM notifications 
            WHERE username = ? AND is_read = 0
            ORDER BY created_at DESC
        `, [username]);
        
        res.json({ 
            success: true, 
            notifications: notifications,
            count: notifications.length
        });
        
    } catch (error) {
        console.error('❌ خطأ في جلب التنبيهات:', error);
        res.json({ 
            success: true, 
            notifications: [],
            count: 0
        });
    }
});

module.exports = router;