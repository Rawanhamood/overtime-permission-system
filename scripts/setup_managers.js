const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, '../database/overtime.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('❌ خطأ في الاتصال:', err);
    process.exit(1);
  }
  
  db.run('PRAGMA foreign_keys = ON', () => {
    console.log('\n🔄 تعيين المديرين للأقسام...\n');

    db.all(`
      SELECT employee_id, full_name 
      FROM employees 
      WHERE user_type = 'manager'
    `, (err, managers) => {
      if (err) {
        console.error('❌ خطأ:', err);
        db.close();
        process.exit(1);
      }
      
      if (!managers || managers.length === 0) {
        console.log('❌ لا توجد مديرين في قاعدة البيانات');
        db.close();
        process.exit(1);
      }
      
      console.log(`✅ وجدنا ${managers.length} مدير:`);
      managers.forEach(m => console.log(`   - ${m.full_name} (ID: ${m.employee_id})`));
      
      db.all(`SELECT id FROM departments WHERE manager_id IS NULL`, (err, depts) => {
        if (err) {
          console.error('❌ خطأ:', err);
          db.close();
          process.exit(1);
        }
        
        if (!depts || depts.length === 0) {
          console.log('✅ جميع الأقسام لها مديرين بالفعل');
          db.close();
          process.exit(0);
        }
        
        console.log(`\n🔗 تعيين ${depts.length} قسم للمديرين...\n`);
        
        let count = 0;
        depts.forEach((dept, idx) => {
          const mgr = managers[idx % managers.length];
          db.run(
            'UPDATE departments SET manager_id = ? WHERE id = ?',
            [mgr.employee_id, dept.id],
            (err) => {
              if (err) {
                console.error(`❌ خطأ في تعيين قسم ${dept.id}:`, err);
              } else {
                console.log(`✅ تم تعيين قسم #${dept.id} للمدير: ${mgr.full_name}`);
              }
              count++;
              if (count === depts.length) {
                console.log('\n✅ انتهى التعيين بنجاح!');
                db.close();
                process.exit(0);
              }
            }
          );
        });
      });
    });
  });
});
