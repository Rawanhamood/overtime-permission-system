# إيقاف العملية على المنفذ 5050
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "    إيقاف العملية على المنفذ 5050" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$port = 5050

# البحث عن العملية التي تستخدم المنفذ
try {
    $connection = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
    if ($connection) {
        $processId = $connection.OwningProcess | Select-Object -Unique
        Write-Host "تم العثور على العملية PID: $processId" -ForegroundColor Yellow
        
        foreach ($pid in $processId) {
            Write-Host "إيقاف العملية $pid..." -ForegroundColor Yellow
            Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
            Write-Host "تم إيقاف العملية $pid بنجاح!" -ForegroundColor Green
        }
    } else {
        Write-Host "لا توجد عملية تستخدم المنفذ $port" -ForegroundColor Yellow
    }
} catch {
    Write-Host "خطأ في البحث عن العملية: $_" -ForegroundColor Red
}

# إيقاف جميع عمليات Node.js
Write-Host ""
Write-Host "إيقاف جميع عمليات Node.js..." -ForegroundColor Yellow
Get-Process -Name "node" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Get-Process -Name "nodemon" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "    تم التنظيف بنجاح!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""

