const sqlite3 = require('sqlite3');
const path = require('path');
const dbPath = path.join(__dirname, '../backend/database/overtime.db');
const db = new sqlite3.Database(dbPath);

console.log('\n📊 فحص الروابط بين الجداول:\n');

// عرض الأقسام والمديرين
db.all(`
  SELECT d.id, d.name, d.manager_id, e.full_name as manager_name 
  FROM departments d 
  LEFT JOIN employees e ON d.manager_id = e.employee_id 
  ORDER BY d.id 
  LIMIT 10
`, (err, depts) => {
  if (err) {
    console.error('خطأ:', err);
    process.exit(1);
  }
  console.log('✅ الأقسام والمديرين المسؤولين:');
  console.table(depts);
  
  // عرض الموظفين والأقسام
  db.all(`
    SELECT e.employee_id, e.full_name, e.user_type, e.department_id, d.name as dept_name
    FROM employees e 
    LEFT JOIN departments d ON e.department_id = d.id 
    ORDER BY e.employee_id 
    LIMIT 10
  `, (err, emps) => {
    if (err) {
      console.error('خطأ:', err);
      process.exit(1);
    }
    console.log('\n✅ الموظفين والأقسام المسندة إليهم:');
    console.table(emps);
    
    process.exit();
  });
});
