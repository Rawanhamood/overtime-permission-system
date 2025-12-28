const express = require('express');
const router = express.Router();
const db = require('../db');
const { authenticateToken } = require('../middleware/auth');

// التصاريح المعتمدة من الأمن (جاهزة للحارس)
router.get('/approved-permits', authenticateToken, async (req, res) => {
    try {
        const query = `
            SELECT p.*, e.full_name, e.job_number, d.department_name
            FROM permits p
            JOIN employees e ON p.employee_id = e.employee_id
            LEFT JOIN departments d ON e.department_id = d.department_id
            WHERE p.status = 'approved_security'
            AND DATE(p.start_date) <= CURDATE()
            AND DATE(p.end_date) >= CURDATE()
            AND p.actual_entry_time IS NULL
            ORDER BY p.request_date DESC
        `;
        
        const [permits] = await db.query(query);
        
        res.json({ success: true, permits });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ success: false, message: 'خطأ في الخادم' });
    }
});

// تسجيل دخول الموظف
router.post('/checkin', authenticateToken, async (req, res) => {
    const { permit_id, guard_username, actual_entry_time, entry_notes } = req.body;
    
    try {
        // التحقق من صلاحية التصريح
        const [permit] = await db.query(
            'SELECT status FROM permits WHERE permit_id = ?',
            [permit_id]
        );
        
        if (permit[0].status !== 'approved_security') {
            return res.json({ 
                success: false, 
                message: 'التصريح غير جاهز للتسجيل' 
            });
        }
        
        // تحديث التصريح
        await db.query(
            `UPDATE permits 
             SET status = 'checked_in',
                 actual_entry_time = ?,
                 entry_guard_username = ?,
                 entry_notes = ?,
                 checkin_timestamp = NOW()
             WHERE permit_id = ?`,
            [actual_entry_time, guard_username, entry_notes, permit_id]
        );
        
        res.json({ success: true, message: 'تم تسجيل الدخول بنجاح' });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ success: false, message: 'خطأ في الخادم' });
    }
});

// ... باقي endpoints الحارس