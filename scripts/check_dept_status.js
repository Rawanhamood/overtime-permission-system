const sqlite3 = require('sqlite3');
const db = new sqlite3.Database('./database/overtime.db');

console.log('\n📊 فحص حالة الأقسام:\n');

db.all(`
  SELECT COUNT(*) as total FROM departments
`, (err, total) => {
  console.log('إجمالي الأقسام:', total[0].total);
  
  db.all(`
    SELECT COUNT(*) as with_manager FROM departments WHERE manager_id IS NOT NULL
  `, (err, withMgr) => {
    console.log('الأقسام التي لها مدير:', withMgr[0].with_manager);
    console.log('الأقسام بدون مدير:', total[0].total - withMgr[0].with_manager);
    
    db.all(`
      SELECT d.id, d.name, d.manager_id, e.full_name 
      FROM departments d 
      LEFT JOIN employees e ON d.manager_id = e.employee_id
      ORDER BY d.id
      LIMIT 10
    `, (err, depts) => {
      console.log('\n✅ الأقسام العشرة الأولى:');
      console.table(depts);
      process.exit();
    });
  });
});
