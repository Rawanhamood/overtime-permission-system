const express = require('express');
const router = express.Router();
const { query, run } = require('../database');

// ========== جلب التصاريح المعلقة للمدير ==========
router.get('/pending/:manager_username', async (req, res) => {
    try {
        const { manager_username } = req.params;
        console.log(`📋 جلب تصاريح معلقة للمدير: ${manager_username}`);
        
        // بدلاً من البحث بقسم المدير، أرجع كل التصاريح المعلقة
        const permits = await query(`
            SELECT p.*, e.full_name, e.job_number, e.directorate, e.department_name, e.phone, e.email
            FROM permits p
            JOIN employees e ON p.employee_username = e.username
            WHERE p.status = 'pending'
            ORDER BY p.request_date DESC
        `);
        
        console.log(`✅ تم العثور على ${permits.length} تصريح معلق`);
        
        res.json({ success: true, permits });
        
    } catch (error) {
        console.error('❌ خطأ في جلب التصاريح المعلقة:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في جلب التصاريح' 
        });
    }
});

// ========== موافقة/رفض المدير (نسخة مبسطة) ==========
router.post('/manager-approve', async (req, res) => {
    console.log('🔄 ========== طلب موافقة المدير ==========');
    console.log('📥 البيانات المستلمة:', JSON.stringify(req.body, null, 2));
    
    try {
        const { permit_id, manager_username, decision, notes } = req.body;
        
        if (!permit_id || !manager_username || !decision) {
            return res.status(400).json({ 
                success: false, 
                message: 'بيانات ناقصة' 
            });
        }
        
        // الحالة الجديدة
        const status = decision === 'approve' ? 'approved_manager' : 'rejected';
        
        console.log(`🔄 تحديث التصريح ${permit_id} إلى: ${status}`);
        
        // استعلام مبسط
        const sql = `
            UPDATE permits 
            SET status = ?,
                manager_approved = ?,
                manager_username = ?,
                manager_action_date = CURRENT_TIMESTAMP,
                manager_notes = ?
            WHERE permit_id = ?
        `;
        
        const params = [
            status, 
            decision === 'approve' ? 1 : 0, 
            manager_username, 
            notes || '', 
            permit_id
        ];
        
        await run(sql, params);
        console.log('✅ تم تحديث التصريح بنجاح');
        
        res.json({ 
            success: true, 
            message: `تم ${decision === 'approve' ? 'قبول' : 'رفض'} التصريح بنجاح`,
            permit_id: permit_id,
            status: status
        });
        
    } catch (error) {
        console.error('❌ خطأ في موافقة المدير:', error);
        console.error('❌ تفاصيل الخطأ:', error.message);
        
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في الخادم',
            error: error.message
        });
    }
});

module.exports = router;