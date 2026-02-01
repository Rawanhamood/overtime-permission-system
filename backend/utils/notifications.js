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

// إرسال إشعار لجميع موظفي الأمن
async function notifyAllSecurityStaff(permit_id, title, message, type = 'info', company_permit_id = null) {
    try {
        const securityUsers = await query(
            'SELECT employee_id FROM employees WHERE user_type IN (?, ?)', 
            ['security', 'security_guard']
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
        
        console.log(`✅ تم إرسال إشعار لـ ${securityUsers.length} من موظفي الأمن`);
    } catch (error) {
        console.error('❌ خطأ في إرسال إشعار لموظفي الأمن:', error.message);
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

// إرسال إشعار لجميع مسؤولي الأمن والحراس
async function notifyAllSecurityUsers(permit_id, title, message, type = 'info', company_permit_id = null) {
    try {
        const securityUsers = await query(
            'SELECT employee_id FROM employees WHERE user_type IN (?, ?) AND is_active = 1', 
            ['security', 'guard']
        );
        
        const notifications = securityUsers.map(user => ({
            user_id: user.employee_id,
            permit_id: permit_id,
            company_permit_id: company_permit_id,
            title: title,
            message: message,
            type: type
        }));

        for (const notif of notifications) {
            await createNotification(notif);
        }
        
        console.log(`✅ تم إرسال إشعار لـ ${securityUsers.length} من مسؤولي الأمن والحراس`);
    } catch (error) {
        console.error('❌ خطأ في إرسال إشعار لمسؤولي الأمن:', error.message);
    }
}

module.exports = {
    createNotification,
    getUserIdByUsername,
    notifyAllManagers,
    notifyAllSecurityStaff,
    notifyAllGuards,
    notifyAllSecurityUsers
};

