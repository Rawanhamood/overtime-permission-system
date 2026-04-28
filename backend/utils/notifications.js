// ============== Notification Utilities ==============
const { query, run } = require('../database');

// دالة إنشاء إشعار واحد
async function createNotification(notification) {
    try {
        const {
            user_id,
            permit_id = null,
            company_permit_id = null,
            title,
            message,
            type = 'info',
            is_read = 0
        } = notification;

        // التحقق من أن type صالح
        const validTypes = ['info', 'warning', 'success', 'error'];
        const validType = validTypes.includes(type) ? type : 'info';
        
        if (!validTypes.includes(type)) {
            console.warn(`⚠️ تحذير: type غير صالح "${type}"، سيتم استخدام "info" بدلاً منه`);
        }

        const sql = `
            INSERT INTO notifications 
            (user_id, permit_id, company_permit_id, title, message, type, is_read, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        `;

        const params = [user_id, permit_id, company_permit_id, title, message, validType, is_read];
        
        const result = await run(sql, params);
        console.log(`✅ تم إنشاء إشعار جديد (ID: ${result.lastID})`);
        return result.lastID;
    } catch (error) {
        console.error('❌ خطأ في إنشاء إشعار:', error.message);
        throw error;
    }
}

// دالة مساعدة للحصول على معرف المستخدم بالاسم
async function getUserIdByUsername(username) {
    try {
        const result = await query('SELECT employee_id FROM employees WHERE username = ?', [username]);
        return result.length > 0 ? result[0].employee_id : null;
    } catch (error) {
        console.error('❌ خطأ في جلب معرف المستخدم:', error.message);
        return null;
    }
}

// إرسال إشعار لجميع المديرين
async function notifyAllManagers(permit_id, title, message, type = 'warning', company_permit_id = null) {
    try {
        const managers = await query('SELECT employee_id FROM employees WHERE user_type = ?', ['manager']);
        
        const notifications = managers.map(manager => ({
            user_id: manager.employee_id,
            permit_id: permit_id,
            company_permit_id: company_permit_id,
            title: title,
            message: message,
            type: type
        }));

        for (const notif of notifications) {
            await createNotification(notif);
        }
        
        console.log(`✅ تم إرسال إشعار لـ ${managers.length} مدير`);
    } catch (error) {
        console.error('❌ خطأ في إرسال إشعار للمديرين:', error.message);
    }
}

/** معرفات الموظفين المعتمدين للموافقة الأمنية (حتى 3) — من الجدول أو أول 3 حسابات security */
async function getSecurityOfficeApproverEmployeeIds() {
    try {
        const rows = await query(
            `SELECT soa.employee_id FROM security_office_approvers soa
             JOIN employees e ON e.employee_id = soa.employee_id
             WHERE (e.is_active IS NULL OR e.is_active = 1)
             ORDER BY soa.sort_order ASC`
        );
        const ids = (rows || []).map((r) => r.employee_id);
        if (ids.length > 0) return ids;
        const fallback = await query(
            `SELECT employee_id FROM employees
             WHERE user_type = 'security' AND (is_active IS NULL OR is_active = 1)
             ORDER BY employee_id ASC LIMIT 3`
        );
        return (fallback || []).map((r) => r.employee_id);
    } catch (error) {
        console.error('❌ خطأ في getSecurityOfficeApproverEmployeeIds:', error.message);
        return [];
    }
}

async function isSecurityOfficeApprover(employeeId) {
    if (employeeId == null || employeeId === '') return false;
    const ids = await getSecurityOfficeApproverEmployeeIds();
    if (ids.length === 0) {
        const r = await query(
            `SELECT 1 FROM employees WHERE employee_id = ? AND user_type = 'security' AND (is_active IS NULL OR is_active = 1)`,
            [employeeId]
        );
        return r.length > 0;
    }
    return ids.includes(Number(employeeId));
}

/** إشعار مسؤولي مكتب الأمن المعتمدين فقط (طابور الموافقة) */
async function notifySecurityOfficeApprovers(permit_id, title, message, type = 'info', company_permit_id = null) {
    const ids = await getSecurityOfficeApproverEmployeeIds();
    if (ids.length === 0) {
        console.warn('⚠️ لا يوجد مسؤولو مكتب أمن معيّنون — إرسال إشعار لجميع حسابات security');
        const fb = await query(
            `SELECT employee_id FROM employees WHERE user_type = 'security' AND (is_active IS NULL OR is_active = 1)`
        );
        for (const r of fb || []) {
            await createNotification({
                user_id: r.employee_id,
                permit_id,
                company_permit_id,
                title,
                message,
                type
            });
        }
        return;
    }
    for (const user_id of ids) {
        await createNotification({
            user_id,
            permit_id,
            company_permit_id,
            title,
            message,
            type
        });
    }
    console.log(`✅ تم إرسال إشعار طابور الأمن لـ ${ids.length} مسؤول معتمد`);
}

/** إبلاغ باقي المعتمدين أن أحدهم أنهى الطلب (موافقة أو رفض) */
async function notifyOtherSecurityOfficeApprovers(excludeEmployeeId, payload) {
    const {
        permit_id = null,
        company_permit_id = null,
        title,
        message,
        type = 'info'
    } = payload;
    const ids = await getSecurityOfficeApproverEmployeeIds();
    const ex = Number(excludeEmployeeId);
    for (const user_id of ids) {
        if (user_id === ex) continue;
        await createNotification({
            user_id,
            permit_id,
            company_permit_id,
            title,
            message,
            type
        });
    }
}

/** إشعار موظفي مكتب الأمن فقط (user_type = security) — الحارس منفصل ولا يُدرج هنا */
async function notifyAllSecurityStaff(permit_id, title, message, type = 'info', company_permit_id = null) {
    try {
        const securityUsers = await query(
            `SELECT employee_id FROM employees WHERE user_type = 'security' AND (is_active IS NULL OR is_active = 1)`
        );
        
        const notifications = securityUsers.map(security => ({
            user_id: security.employee_id,
            permit_id: permit_id,
            company_permit_id: company_permit_id,
            title: title,
            message: message,
            type: type
        }));

        for (const notif of notifications) {
            await createNotification(notif);
        }
        
        console.log(`✅ تم إرسال إشعار لمكتب الأمن (${securityUsers.length} مستخدم security)`);
    } catch (error) {
        console.error('❌ خطأ في إرسال إشعار لمكتب الأمن:', error.message);
    }
}

// إرسال إشعار لجميع الحرس
async function notifyAllGuards(permit_id, title, message, type = 'info', company_permit_id = null) {
    try {
        const guards = await query(
            'SELECT employee_id FROM employees WHERE user_type IN (?, ?)', 
            ['guard', 'security_guard']
        );
        
        const notifications = guards.map(guard => ({
            user_id: guard.employee_id,
            permit_id: permit_id,
            company_permit_id: company_permit_id,
            title: title,
            message: message,
            type: type
        }));

        for (const notif of notifications) {
            await createNotification(notif);
        }
        
        console.log(`✅ تم إرسال إشعار لـ ${guards.length} حارس`);
    } catch (error) {
        console.error('❌ خطأ في إرسال إشعار للحرس:', error.message);
    }
}

module.exports = {
    createNotification,
    getUserIdByUsername,
    notifyAllManagers,
    notifyAllSecurityStaff,
    notifySecurityOfficeApprovers,
    notifyOtherSecurityOfficeApprovers,
    getSecurityOfficeApproverEmployeeIds,
    isSecurityOfficeApprover,
    notifyAllGuards
};

