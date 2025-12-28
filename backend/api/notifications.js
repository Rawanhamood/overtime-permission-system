const express = require('express');
const router = express.Router();
const { query, run } = require('../database');

// ========== جلب إشعارات مستخدم ==========
router.get('/:username', async (req, res) => {
    try {
        const { username } = req.params;
        console.log(`📢 جلب إشعارات المستخدم: ${username}`);
        
        // جلب الإشعارات
        const notifications = await query(`
            SELECT n.*, p.permit_id, p.status as permit_status
            FROM notifications n
            LEFT JOIN permits p ON n.permit_id = p.permit_id
            WHERE n.username = ?
            ORDER BY n.created_at DESC
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
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في جلب الإشعارات',
            error: error.message
        });
    }
});

// ========== تحديد إشعار كمقروء ==========
router.post('/mark-read', async (req, res) => {
    try {
        const { notification_id, username } = req.body;
        console.log(`📌 تحديد إشعار كمقروء: ${notification_id} للمستخدم: ${username}`);
        
        await run(`
            UPDATE notifications 
            SET is_read = 1 
            WHERE notification_id = ? AND username = ?
        `, [notification_id, username]);
        
        res.json({ success: true, message: 'تم تحديث حالة الإشعار' });
        
    } catch (error) {
        console.error('❌ خطأ في تحديث الإشعار:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في تحديث الإشعار'
        });
    }
});

// ========== تحديد كل الإشعارات كمقروءة ==========
router.post('/mark-all-read', async (req, res) => {
    try {
        const { username } = req.body;
        console.log(`📌 تحديد كل إشعارات ${username} كمقروءة`);
        
        await run(`
            UPDATE notifications 
            SET is_read = 1 
            WHERE username = ?
        `, [username]);
        
        res.json({ success: true, message: 'تم تحديث جميع الإشعارات' });
        
    } catch (error) {
        console.error('❌ خطأ في تحديث الإشعارات:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في تحديث الإشعارات'
        });
    }
});

// ========== إنشاء إشعار جديد ==========
router.post('/create', async (req, res) => {
    try {
        const { username, title, message, type, permit_id } = req.body;
        console.log(`➕ إنشاء إشعار جديد للمستخدم: ${username}`);
        
        await run(`
            INSERT INTO notifications (username, title, message, type, permit_id)
            VALUES (?, ?, ?, ?, ?)
        `, [username, title, message, type || 'info', permit_id || null]);
        
        res.json({ success: true, message: 'تم إنشاء الإشعار' });
        
    } catch (error) {
        console.error('❌ خطأ في إنشاء الإشعار:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في إنشاء الإشعار'
        });
    }
});

module.exports = router;