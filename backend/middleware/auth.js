// ============== Authentication & Authorization Middleware ==============

// التحقق من التوكن
const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'غير مصرح، يرجى تسجيل الدخول أولاً'
        });
    }
    
    try {
        // فك التوكن (في نظامك الحالي، التوكن هو مجرد base64)
        const decoded = JSON.parse(Buffer.from(token, 'base64').toString());
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({
            success: false,
            message: 'توكن غير صالح'
        });
    }
};

// التحقق من الصلاحيات حسب الأدوار
const authorizeRoles = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(403).json({
                success: false,
                message: 'ليس لديك صلاحية للوصول'
            });
        }
        
        const userRole = req.user.role;
        
        // السماح للحارس (guard) بالوصول لـ APIs محددة فقط
        if (userRole === 'guard' || userRole === 'security_guard') {
            const guardAllowedAPIs = ['security', 'security_guard', 'admin'];
            if (!guardAllowedAPIs.some(allowedRole => roles.includes(allowedRole))) {
                return res.status(403).json({
                    success: false,
                    message: 'ليس لديك صلاحية للوصول'
                });
            }
        } else if (!roles.includes(userRole)) {
            return res.status(403).json({
                success: false,
                message: 'ليس لديك صلاحية للوصول'
            });
        }
        next();
    };
};

// middleware خاص للحارس (security_guard)
const checkGuardPermissions = (req, res, next) => {
    if (req.user && (req.user.role === 'guard' || req.user.role === 'security_guard')) {
        const blockedPaths = [
            '/api/permits/security-approve',
            '/api/permits/end-early',
            '/api/departments',
            '/api/auto-assign-managers',
            '/api/reassign-all-managers'
        ];
        
        if (blockedPaths.some(path => req.path.startsWith(path))) {
            return res.status(403).json({
                success: false,
                message: 'الحارس ليس لديه صلاحية لهذا الإجراء'
            });
        }
    }
    next();
};

// اختصارات للأدوار الشائعة
const checkManagerRole = (req, res, next) => {
    const userRole = req.user?.role;
    if (userRole !== 'manager' && userRole !== 'admin') {
        return res.status(403).json({
            success: false,
            message: 'غير مصرح لك بتنفيذ هذه العملية'
        });
    }
    next();
};

const checkSecurityRole = (req, res, next) => {
    const userRole = req.user?.role;
    if (userRole !== 'security' && userRole !== 'admin') {
        return res.status(403).json({
            success: false,
            message: 'غير مصرح لك بتنفيذ هذه العملية'
        });
    }
    next();
};

module.exports = {
    authenticateToken,
    authorizeRoles,
    checkGuardPermissions,
    checkManagerRole,
    checkSecurityRole
};

