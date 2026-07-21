/**
 * سجل موحّد لتصاريح مكتب الأمن — موظفون، شركات، إخراج مواد
 */

function pad2(n) {
    return String(n).padStart(2, '0');
}

function toYmd(d) {
    return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
}

/** حساب نطاق التاريخ من معاملات الطلب */
function resolveDateRange(query) {
    const period = String(query.period || 'month').toLowerCase();
    const now = new Date();
    const today = toYmd(now);

    if (period === 'all') {
        return { from: null, to: null, label: 'الكل' };
    }

    if (period === 'custom') {
        const from = query.from ? String(query.from).slice(0, 10) : null;
        const to = query.to ? String(query.to).slice(0, 10) : null;
        return { from, to, label: from && to ? `${from} — ${to}` : 'مخصص' };
    }

    if (period === 'week') {
        const start = new Date(now);
        const day = start.getDay();
        const diff = day === 0 ? 6 : day - 1;
        start.setDate(start.getDate() - diff);
        return { from: toYmd(start), to: today, label: 'هذا الأسبوع' };
    }

    if (period === 'year') {
        const y = parseInt(query.year, 10) || now.getFullYear();
        return { from: `${y}-01-01`, to: `${y}-12-31`, label: `سنة ${y}` };
    }

    // month (default)
    const y = parseInt(query.year, 10) || now.getFullYear();
    const m = parseInt(query.month, 10) || (now.getMonth() + 1);
    const lastDay = new Date(y, m, 0).getDate();
    return {
        from: `${y}-${pad2(m)}-01`,
        to: `${y}-${pad2(m)}-${pad2(lastDay)}`,
        label: `${y}-${pad2(m)}`
    };
}

function statusLabelEmployee(status) {
    const map = {
        pending_manager: 'بانتظار المدير',
        approved_manager: 'معتمد من المدير',
        pending_security: 'بانتظار الأمن',
        approved_security: 'معتمد من الأمن',
        rejected_manager: 'مرفوض من المدير',
        rejected_security: 'مرفوض من الأمن',
        checked_in: 'داخل المبنى',
        completed: 'مكتمل'
    };
    return map[status] || status || '—';
}

function statusLabelCompany(status) {
    const map = {
        pending_manager: 'بانتظار المدير',
        approved_manager: 'بانتظار الأمن',
        pending_security: 'بانتظار الأمن',
        approved_security: 'معتمد من الأمن',
        rejected_manager: 'مرفوض من المدير',
        rejected_security: 'مرفوض من الأمن',
        checked_in: 'داخل المبنى',
        completed: 'مكتمل'
    };
    return map[status] || status || '—';
}

function statusLabelMaterial(status) {
    const map = {
        pending_manager: 'بانتظار المدير',
        approved_manager: 'بانتظار الأمن',
        pending_security: 'بانتظار الأمن',
        sent_to_guard: 'عند الحارس',
        completed: 'تم الإخراج',
        rejected_manager: 'مرفوض من المدير',
        rejected_security: 'مرفوض من الأمن'
    };
    return map[status] || status || '—';
}

function fmtDateTime(ts, time) {
    if (ts) {
        try {
            const d = new Date(ts);
            if (!Number.isNaN(d.getTime())) {
                return d.toLocaleString('ar-SA', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
            }
        } catch (_) { /* ignore */ }
        return String(ts);
    }
    return time ? String(time) : '—';
}

function mapEmployeeRow(row) {
    const id = row.permit_id != null ? row.permit_id : row.rowid;
    const sortAt = row.checkin_timestamp || row.security_decision_date || row.request_date || row.created_at || '';
    return {
        kind: 'employee',
        permit_id: id,
        primary_label: row.full_name || '—',
        secondary_label: [row.job_number, row.department_name].filter(Boolean).join(' | ') || '—',
        status: row.status || '',
        status_label: statusLabelEmployee(row.status),
        request_date: row.request_date || row.created_at || '',
        planned_entry: [row.start_date, row.expected_exit_time ? `من ${String(row.expected_exit_time).split(/\s*[-–—]\s*/)[0] || row.expected_exit_time}` : ''].filter(Boolean).join(' '),
        planned_exit: [row.end_date, row.expected_exit_time || ''].filter(Boolean).join(' '),
        actual_entry: fmtDateTime(row.checkin_timestamp, row.actual_entry_time),
        actual_exit: fmtDateTime(row.checkout_timestamp, row.actual_exit_time),
        actual_entry_raw: row.actual_entry_time || '',
        actual_exit_raw: row.actual_exit_time || '',
        checkin_timestamp: row.checkin_timestamp || '',
        checkout_timestamp: row.checkout_timestamp || '',
        entry_guard: row.entry_guard_username || '',
        exit_guard: row.exit_guard_username || '',
        sort_at: sortAt,
        can_approve: row.status === 'pending_security',
        can_print: ['approved_security', 'checked_in', 'completed'].includes(row.status)
    };
}

function mapCompanyRow(row) {
    const id = row.permit_id != null ? row.permit_id : row.rowid;
    const sortAt = row.checkin_timestamp || row.security_decision_date || row.expected_entry_date || row.created_at || '';
    const plannedIn = [row.expected_entry_date, row.expected_entry_time].filter(Boolean).join(' ');
    const plannedOut = [row.expected_exit_date, row.expected_exit_time].filter(Boolean).join(' ');
    return {
        kind: 'company',
        permit_id: id,
        primary_label: row.company_name || '—',
        secondary_label: row.company_representative || row.company_supervisor || '—',
        status: row.status || '',
        status_label: statusLabelCompany(row.status),
        request_date: row.created_at || row.request_date || '',
        planned_entry: plannedIn || '—',
        planned_exit: plannedOut || '—',
        actual_entry: fmtDateTime(row.checkin_timestamp, row.actual_entry_time),
        actual_exit: fmtDateTime(row.checkout_timestamp, row.actual_exit_time),
        actual_entry_raw: row.actual_entry_time || '',
        actual_exit_raw: row.actual_exit_time || '',
        checkin_timestamp: row.checkin_timestamp || '',
        checkout_timestamp: row.checkout_timestamp || '',
        entry_guard: row.entry_guard_username || '',
        exit_guard: row.exit_guard_username || '',
        sort_at: sortAt,
        can_approve: row.status === 'approved_manager',
        can_print: ['approved_security', 'checked_in', 'completed'].includes(row.status)
    };
}

function mapMaterialRow(row) {
    const id = row.permit_id != null ? row.permit_id : row.rowid;
    const sortAt = row.guard_verification_date || row.security_decision_date || row.permit_date || row.created_at || '';
    const exitDisplay = row.guard_verification_date
        ? fmtDateTime(row.guard_verification_date, row.permit_time)
        : (row.permit_date && row.permit_time ? `${row.permit_date} ${row.permit_time}` : row.permit_date || '—');
    return {
        kind: 'material',
        permit_id: id,
        primary_label: row.employee_name || row.full_name || '—',
        secondary_label: row.material_type || '—',
        status: row.status || '',
        status_label: statusLabelMaterial(row.status),
        request_date: row.created_at || row.permit_date || '',
        planned_entry: '—',
        planned_exit: row.permit_date && row.permit_time ? `${row.permit_date} ${row.permit_time}` : (row.permit_date || '—'),
        actual_entry: '—',
        actual_exit: row.status === 'completed' ? exitDisplay : '—',
        actual_entry_raw: '',
        actual_exit_raw: row.guard_verification_date || row.permit_time || '',
        checkin_timestamp: '',
        checkout_timestamp: row.guard_verification_date || '',
        entry_guard: '',
        exit_guard: row.guard_username || '',
        sort_at: sortAt,
        can_approve: row.status === 'pending_security',
        can_print: ['sent_to_guard', 'completed'].includes(row.status)
    };
}

function dateInRange(sortAt, from, to) {
    if (!from && !to) return true;
    if (!sortAt) return false;
    const d = String(sortAt).slice(0, 10);
    if (from && d < from) return false;
    if (to && d > to) return false;
    return true;
}

function matchesEntryExitFilters(item, query) {
    const entryFrom = query.entry_from ? String(query.entry_from).slice(0, 10) : null;
    const entryTo = query.entry_to ? String(query.entry_to).slice(0, 10) : null;
    const exitFrom = query.exit_from ? String(query.exit_from).slice(0, 10) : null;
    const exitTo = query.exit_to ? String(query.exit_to).slice(0, 10) : null;
    const hasEntry = query.has_entry === '1' || query.has_entry === 'true';
    const hasExit = query.has_exit === '1' || query.has_exit === 'true';

    const entryTs = item.checkin_timestamp || item.actual_entry_raw || '';
    const exitTs = item.checkout_timestamp || item.actual_exit_raw || '';

    if (hasEntry && !entryTs && item.kind !== 'material') return false;
    if (hasExit && !exitTs) return false;

    if (entryFrom || entryTo) {
        const ed = String(entryTs).slice(0, 10);
        if (!ed || ed === '—') return false;
        if (entryFrom && ed < entryFrom) return false;
        if (entryTo && ed > entryTo) return false;
    }
    if (exitFrom || exitTo) {
        const xd = String(exitTs).slice(0, 10);
        if (!xd || xd === '—') return false;
        if (exitFrom && xd < exitFrom) return false;
        if (exitTo && xd > exitTo) return false;
    }
    return true;
}

function matchesText(item, q) {
    if (!q) return true;
    const hay = [
        item.primary_label, item.secondary_label, item.status_label,
        String(item.permit_id), item.actual_entry, item.actual_exit,
        item.entry_guard, item.exit_guard
    ].join(' ').toLowerCase();
    return hay.includes(q.toLowerCase());
}

function sortItems(items) {
    return items.sort((a, b) => {
        const ta = new Date(a.sort_at || 0).getTime();
        const tb = new Date(b.sort_at || 0).getTime();
        return tb - ta;
    });
}

function buildCounts(items) {
    return {
        total: items.length,
        employee: items.filter(i => i.kind === 'employee').length,
        company: items.filter(i => i.kind === 'company').length,
        material: items.filter(i => i.kind === 'material').length
    };
}

function kindLabel(kind) {
    if (kind === 'employee') return 'موظف (بعد الدوام)';
    if (kind === 'company') return 'دخول شركة';
    if (kind === 'material') return 'إخراج مواد';
    return kind;
}

function escapeCsvCell(val) {
    const s = val == null ? '' : String(val);
    if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
    return s;
}

function itemsToCsv(items) {
    const headers = [
        'النوع', 'رقم التصريح', 'الاسم / الشركة', 'التفاصيل', 'الحالة',
        'تاريخ الطلب', 'دخول مخطط', 'خروج مخطط',
        'وقت الدخول الفعلي', 'وقت الخروج الفعلي', 'حارس الدخول', 'حارس الخروج'
    ];
    const rows = items.map(it => [
        kindLabel(it.kind),
        it.permit_id,
        it.primary_label,
        it.secondary_label,
        it.status_label,
        it.request_date,
        it.planned_entry,
        it.planned_exit,
        it.actual_entry,
        it.actual_exit,
        it.entry_guard,
        it.exit_guard
    ].map(escapeCsvCell).join(','));
    return '\uFEFF' + [headers.join(','), ...rows].join('\n');
}

module.exports = {
    resolveDateRange,
    mapEmployeeRow,
    mapCompanyRow,
    mapMaterialRow,
    dateInRange,
    matchesEntryExitFilters,
    matchesText,
    sortItems,
    buildCounts,
    kindLabel,
    itemsToCsv
};
