const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

// مسار قاعدة البيانات الموحد
const dbPath = path.join(__dirname, 'database', 'overtime.db');

// التأكد من وجود مجلد قاعدة البيانات
const dbDir = path.dirname(dbPath);
if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
}

/** يمنع تشغيل نسختين من الخادم على نفس الملف — السبب الأشهر لـ SQLITE_BUSY وخطأ 500 */
const instanceLockPath = path.join(dbDir, 'server.sqlite.lock');

function releaseInstanceLock() {
    try {
        if (!fs.existsSync(instanceLockPath)) return;
        const owner = fs.readFileSync(instanceLockPath, 'utf8').trim();
        if (owner === String(process.pid)) {
            fs.unlinkSync(instanceLockPath);
        }
    } catch (_) {
        /* ignore */
    }
}

function acquireInstanceLock() {
    if (process.env.OVERTIME_SKIP_DB_LOCK === '1') {
        return;
    }
    for (let attempt = 0; attempt < 3; attempt++) {
        try {
            const fd = fs.openSync(instanceLockPath, 'wx');
            fs.writeSync(fd, `${process.pid}\n`);
            fs.closeSync(fd);
            process.on('exit', releaseInstanceLock);
            process.on('SIGINT', () => {
                releaseInstanceLock();
                process.exit(0);
            });
            process.on('SIGTERM', () => {
                releaseInstanceLock();
                process.exit(0);
            });
            return;
        } catch (e) {
            if (e.code !== 'EEXIST') {
                console.error('❌ تعذر إنشاء قفل التطبيق:', e.message);
                process.exit(1);
            }
            let otherPid = NaN;
            try {
                otherPid = parseInt(fs.readFileSync(instanceLockPath, 'utf8').trim(), 10);
            } catch (_) {
                /* stale */
            }
            let otherAlive = false;
            if (!Number.isNaN(otherPid)) {
                try {
                    process.kill(otherPid, 0);
                    otherAlive = true;
                } catch (_) {
                    otherAlive = false;
                }
            }
            if (otherAlive) {
                console.error('');
                console.error(
                    `❌ خادم آخر يستخدم قاعدة البيانات (PID ${otherPid}). لا تشغّل نسختين — يسبب خطأ SQLITE_BUSY وفشل حفظ التصاريح.`
                );
                console.error('   أوقف العملية الأخرى (أو أغلق نافذة الطرفية القديمة) ثم أعد التشغيل.');
                console.error('   للصيانة فقط: ضع المتغير OVERTIME_SKIP_DB_LOCK=1');
                console.error('');
                process.exit(1);
            }
            try {
                fs.unlinkSync(instanceLockPath);
            } catch (_) {
                /* ignore */
            }
        }
    }
}

acquireInstanceLock();

// إنشاء اتصال بقاعدة البيانات
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('❌ خطأ في الاتصال بقاعدة البيانات:', err.message);
        console.error('📁 المسار:', dbPath);
        process.exit(1);
    }
    console.log('✅ تم الاتصال بقاعدة البيانات:', dbPath);
    // انتظار داخل SQLite لكل محاولة + withBusyRetry في الطبقة العليا
    db.configure('busyTimeout', 8000);
    db.serialize(() => {
        db.run('PRAGMA foreign_keys = ON', (e) => {
            if (e) console.warn('⚠️ PRAGMA foreign_keys:', e.message);
        });
        db.run('PRAGMA journal_mode = WAL', (e) => {
            if (e) console.warn('⚠️ تعذر تفعيل WAL (سيتم المتابعة بالوضع الافتراضي):', e.message);
        });
        db.run('PRAGMA synchronous = NORMAL', (e) => {
            if (e) console.warn('⚠️ PRAGMA synchronous:', e.message);
        });
    });
});

db.on('error', (err) => {
    console.error('❌ خطأ غير متوقع على اتصال SQLite:', err.message);
});

function isSqliteBusy(err) {
    if (!err) return false;
    if (err.code === 'SQLITE_BUSY') return true;
    const msg = String(err.message || '');
    return msg.includes('SQLITE_BUSY') || msg.includes('database is locked');
}

/** إعادة محاولة محدودة عند SQLITE_BUSY (مع busyTimeout أعلاه ≈ بضع ثوانٍ لكل استعلام كحد أقصى) */
const BUSY_MAX_ATTEMPTS = 6;
const BUSY_MAX_BACKOFF_MS = 400;

async function withBusyRetry(operation) {
    let lastErr;
    for (let attempt = 0; attempt < BUSY_MAX_ATTEMPTS; attempt++) {
        try {
            return await operation();
        } catch (err) {
            lastErr = err;
            if (!isSqliteBusy(err) || attempt === BUSY_MAX_ATTEMPTS - 1) {
                throw err;
            }
            const delay = Math.min(50 * (attempt + 1), BUSY_MAX_BACKOFF_MS);
            await new Promise((resolve) => setTimeout(resolve, delay));
        }
    }
    throw lastErr;
}

// دالة query للاستعلامات التي ترجع بيانات
function query(sql, params = []) {
    return withBusyRetry(
        () =>
            new Promise((resolve, reject) => {
                db.all(sql, params, (err, rows) => {
                    if (err) {
                        console.error('❌ خطأ في الاستعلام:', err.message);
                        console.error('📝 SQL:', sql);
                        console.error('📋 المعاملات:', params);
                        reject(err);
                    } else {
                        resolve(rows || []);
                    }
                });
            })
    );
}

// دالة run للاستعلامات التي تعدل البيانات
function run(sql, params = []) {
    return withBusyRetry(
        () =>
            new Promise((resolve, reject) => {
                db.run(sql, params, function (err) {
                    if (err) {
                        console.error('❌ خطأ في التنفيذ:', err.message);
                        console.error('📝 SQL:', sql);
                        console.error('📋 المعاملات:', params);
                        reject(err);
                    } else {
                        resolve({
                            lastID: this.lastID,
                            changes: this.changes
                        });
                    }
                });
            })
    );
}

// دالة get للاستعلامات التي ترجع صف واحد
function get(sql, params = []) {
    return withBusyRetry(
        () =>
            new Promise((resolve, reject) => {
                db.get(sql, params, (err, row) => {
                    if (err) {
                        console.error('❌ خطأ في الاستعلام:', err.message);
                        console.error('📝 SQL:', sql);
                        console.error('📋 المعاملات:', params);
                        reject(err);
                    } else {
                        resolve(row || null);
                    }
                });
            })
    );
}

// تصدير الدوال وكائن قاعدة البيانات
module.exports = {
    db,
    query,
    run,
    get
};

