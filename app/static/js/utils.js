/* ─────────────────────────────────────────
   utils.js  —  Shared helpers (every page)
   ───────────────────────────────────────── */

// ── XSS sanitiser ──────────────────────────────────────────
// ALWAYS use esc() on any user-supplied data before injecting into innerHTML
const _escDiv = document.createElement('div');
function esc(str) {
  if (str === null || str === undefined) return '—';
  _escDiv.textContent = String(str);
  return _escDiv.innerHTML;
}

// Safe version of innerHTML setter — escapes all string values in a template
// Usage: same as template literals, but wrap user data with esc()
// e.g. `<td>${esc(user.name)}</td>`

// ── Skeleton rows (loading state for tables) ───────────────
function skeletonRows(cols, count = 5) {
  const widths = [60, 90, 70, 80, 50, 65, 75, 55];
  return Array.from({ length: count }, () =>
    `<tr class="skeleton-row">${
      Array.from({ length: cols }, (_, i) =>
        `<td><span class="skeleton" style="width:${widths[i % widths.length]}%"></span></td>`
      ).join('')
    }</tr>`
  ).join('');
}

// ── Clock ──────────────────────────────────────────────────
(function initClock() {
  const el = document.getElementById('clock');
  if (!el) return;
  const tick = () => el.textContent = new Date().toLocaleTimeString('en-GB', { hour12: false });
  tick();
  setInterval(tick, 1000);
})();

// ── Sidebar collapse ────────────────────────────────────────
(function initSidebar() {
  const btn     = document.getElementById('sidebarToggle');
  const sidebar = document.getElementById('sidebar');
  const main    = document.getElementById('mainContent');
  if (!btn || !sidebar) return;
  btn.addEventListener('click', () => sidebar.classList.toggle('collapsed'));
})();

// ── Global search (Ctrl+K) ──────────────────────────────────
(function initGlobalSearch() {
  const input = document.getElementById('globalSearch');
  if (!input) return;
  document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      input.focus();
    }
  });
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter' && input.value.trim()) {
      window.location.href = '/search?q=' + encodeURIComponent(input.value.trim());
    }
  });
})();

// ── Risk pill (dashboard score → topbar) ────────────────────
function updateRiskPill(score) {
  const pill = document.getElementById('riskPill');
  const lbl  = document.getElementById('riskLabel');
  if (!pill || !lbl) return;
  pill.className = 'risk-pill';
  if      (score < 40) { pill.classList.add('risk-critical'); lbl.textContent = 'CRITICAL'; }
  else if (score < 60) { pill.classList.add('risk-high');     lbl.textContent = 'HIGH RISK'; }
  else if (score < 80) { pill.classList.add('risk-medium');   lbl.textContent = 'MEDIUM'; }
  else                 { pill.classList.add('risk-low');      lbl.textContent = 'LOW RISK'; }
}

// ── Load risk score on every page ───────────────────────────
(async function loadRiskPill() {
  try {
    const res  = await fetch('/api/summary');
    const data = await res.json();
    if (data.score !== undefined) updateRiskPill(data.score);
  } catch {}
})();

// ── Toast ────────────────────────────────────────────────────
function showToast(msg, type = 'info') {
  const el = document.getElementById('toast');
  if (!el) return;
  el.textContent = msg;
  el.className   = `toast toast-${type} show`;
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('show'), 3500);
}

// ── Modal ────────────────────────────────────────────────────
function showModal(title, bodyHtml) {
  document.getElementById('modalTitle').textContent = title;
  document.getElementById('modalBody').innerHTML    = bodyHtml;
  document.getElementById('modal').classList.add('open');
}
function closeModal() {
  document.getElementById('modal').classList.remove('open');
}

// ── setText helper ───────────────────────────────────────────
function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

// ── Days since date ──────────────────────────────────────────
function daysSince(dateStr) {
  return Math.floor((Date.now() - new Date(dateStr).getTime()) / 86_400_000);
}

// ── Badge helpers ────────────────────────────────────────────
function statusBadge(s) {
  return ({ active:'<span class="badge badge-ok">Active</span>',
             stale: '<span class="badge badge-danger">Stale</span>',
           disabled:'<span class="badge badge-dim">Disabled</span>' }[s]
         || `<span class="badge badge-dim">${s}</span>`);
}

function riskBadge(r) {
  return ({ critical:'<span class="badge badge-danger">Critical</span>',
                high:'<span class="badge badge-danger">High</span>',
              medium:'<span class="badge badge-warn">Medium</span>',
                 low:'<span class="badge badge-ok">Low</span>' }[r]
         || `<span class="badge badge-dim">${r}</span>`);
}

function typeBadge(t) {
  return ({ login:   '<span class="badge badge-info">Login</span>',
             modify: '<span class="badge badge-warn">Modify</span>',
             delete: '<span class="badge badge-danger">Delete</span>',
             create: '<span class="badge badge-ok">Create</span>',
           escalate: '<span class="badge badge-purple">Escalate</span>' }[t]
         || `<span class="badge badge-dim">${t}</span>`);
}

function resultBadge(r) {
  return r === 'success'
    ? '<span class="badge badge-ok">Success</span>'
    : '<span class="badge badge-danger">Failed</span>';
}

// ── Pager ─────────────────────────────────────────────────────
function renderPager(containerId, total, page, size, onPage) {
  const el = document.getElementById(containerId);
  if (!el) return;
  const pages = Math.max(1, Math.ceil(total / size));
  const from  = Math.min((page - 1) * size + 1, total);
  const to    = Math.min(page * size, total);
  const btns  = Array.from({ length: Math.min(pages, 7) }, (_, i) => i + 1)
    .map(p => `<button class="pager-btn ${p === page ? 'active' : ''}"
                       onclick="(${onPage.toString()})(${p})">${p}</button>`)
    .join('');
  el.innerHTML = `<span>Showing ${from}–${to} of ${total}</span>
                  <div class="pager-btns">${btns}</div>`;
}

// ── CSV export from a table tbody ─────────────────────────────
function exportTableCSV(tbodyId, filename) {
  const tbody = document.getElementById(tbodyId);
  if (!tbody) return;
  const rows = Array.from(tbody.querySelectorAll('tr')).map(tr =>
    Array.from(tr.querySelectorAll('td'))
        .map(td => `"${td.innerText.trim().replace(/"/g, '""')}"`)
        .join(',')
  );
  const csv  = rows.join('\r\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const a    = Object.assign(document.createElement('a'), {
    href: URL.createObjectURL(blob), download: filename
  });
  a.click();
  URL.revokeObjectURL(a.href);
  showToast('CSV downloaded: ' + filename, 'ok');
}
