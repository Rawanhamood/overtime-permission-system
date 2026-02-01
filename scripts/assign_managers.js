const sqlite3 = require('sqlite3');
const path = require('path');
const dbPath = path.join(__dirname, '../backend/database/overtime.db');
const db = new sqlite3.Database(dbPath);

db.run('PRAGMA foreign_keys = ON');

console.log('\n🔄 تعيين المديرين للأقسام...\n');

// الحصول على المديرين
db.all(`
  SELECT employee_id, full_name 
  FROM employees 
  WHERE user_type = 'manager'
`, (err, managers) => {
  if (err) {
    console.error('❌ خطأ:', err);
    process.exit(1);
  }
  
  console.log(`✅ وجدنا ${managers.length} مدير:`);
  managers.forEach(m => console.log(`   - ${m.full_name} (ID: ${m.employee_id})`));
  
  // تعيين المديرين تلقائياً للأقسام
  db.all(`SELECT id FROM departments WHERE manager_id IS NULL LIMIT ?`, [managers.length], (err, depts) => {
    if (!depts || depts.length === 0) {
      console.log('✅ جميع الأقسام لها مديرين بالفعل');
      process.exit();
    }
    
    console.log(`\n🔗 تعيين ${depts.length} قسم للمديرين...\n`);
    
    let count = 0;
    depts.forEach((dept, idx) => {
      const mgr = managers[idx % managers.length];
      db.run(
        'UPDATE departments SET manager_id = ? WHERE id = ?',
        [mgr.employee_id, dept.id],
        (err) => {
          count++;
          if (err) {
            console.error(`❌ خطأ في تعيين قسم ${dept.id}:`, err);
          } else {
            console.log(`✅ تم تعيين قسم #${dept.id} للمدير: ${mgr.full_name}`);
          }
          if (count === depts.length) {
            console.log('\n✅ انتهى التعيين بنجاح!');
            process.exit();
          }
        }
      );
    });
  });
});
