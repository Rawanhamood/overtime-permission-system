// frontend/js/auth.js

// دالة للحصول على التوكن
function getToken() {
    return localStorage.getItem('token');
}

// دالة للحصول على بيانات المستخدم
function getUser() {
    const userStr = localStorage.getItem('user');
    return userStr ? JSON.parse(userStr) : null;
}

// دالة للتحقق من المصادقة
function checkAuth() {
    const token = getToken();
    const user = getUser();
    
    if (!token || !user) {
        window.location.href = '/login';
        return false;
    }
    return true;
}

// دالة للحصول على headers للمصادقة
function getAuthHeaders() {
    return {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + getToken()
    };
}

// دالة لإضافة معلومات المستخدم للصفحة
function loadUserInfo() {
    const user = getUser();
    if (!user) return;
    
    // إظهار الاسم
    const nameElements = document.querySelectorAll('.user-name, #userName');
    nameElements.forEach(el => {
        if (el) el.textContent = user.name;
    });
    
    // إظهار الدور
    const roleElements = document.querySelectorAll('.user-role, #userRole');
    roleElements.forEach(el => {
        if (el) {
            const roles = {
                'admin': 'مسؤول النظام',
                'manager': 'مدير قسم',
                'employee': 'موظف',
                'security': 'مسؤول أمن'

            };
            el.textContent = roles[user.role] || user.role;
        }
    });
    
    // إخفاء العناصر حسب الصلاحية
    document.querySelectorAll('[data-role]').forEach(el => {
        const requiredRole = el.getAttribute('data-role');
        if (requiredRole && !requiredRole.split(',').includes(user.role)) {
            el.style.display = 'none';
        }
    });
}

// دالة تسجيل الخروج
function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = '/login';
}

// تهيئة عند تحميل الصفحة
document.addEventListener('DOMContentLoaded', function() {
    // الصفحات التي تحتاج مصادقة (كل الصفحات ما عدا login)
    const currentPage = window.location.pathname;
    const isLoginPage = currentPage.includes('login') || currentPage === '/';
    
    if (!isLoginPage) {
        if (!checkAuth()) return;
        loadUserInfo();
    }
    
    // إضافة حدث لزر الخروج
    document.querySelectorAll('.logout-btn, #logoutBtn').forEach(btn => {
        btn.addEventListener('click', logout);
    });
});

// جعل الدوال متاحة عالمياً
window.auth = {
    getToken,
    getUser,
    checkAuth,
    getAuthHeaders,
    logout
};