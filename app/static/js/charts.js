/* ─────────────────────────────────────────
   charts.js  —  All Chart.js definitions
   Loaded only on pages that need charts.
   ───────────────────────────────────────── */

Chart.defaults.color     = '#607080';
Chart.defaults.font      = { family: "'JetBrains Mono', monospace", size: 11 };
Chart.defaults.animation = { duration: 500 };

const _charts = {};

function _destroy(id) {
  if (_charts[id]) { _charts[id].destroy(); delete _charts[id]; }
}

// ── Account Status — doughnut ───────────────────────────────
function renderStatusChart(breakdown) {
  _destroy('statusChart');
  const ctx = document.getElementById('statusChart');
  if (!ctx) return;
  _charts.statusChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Active', 'Stale', 'Disabled'],
      datasets: [{
        data: [breakdown.active, breakdown.stale, breakdown.disabled],
        backgroundColor: ['rgba(74,222,128,.65)', 'rgba(248,113,113,.65)', 'rgba(96,112,128,.45)'],
        borderColor:     ['#4ade80', '#f87171', '#607080'],
        borderWidth: 1.5,
        hoverOffset: 4,
      }]
    },
    options: {
      cutout: '68%',
      plugins: {
        legend: { position: 'bottom', labels: { padding: 12, usePointStyle: true, pointStyle: 'circle' } }
      }
    }
  });
}

// ── Risk trend — line ────────────────────────────────────────
function renderTrendChart(trend) {
  _destroy('trendChart');
  const ctx = document.getElementById('trendChart');
  if (!ctx) return;
  _charts.trendChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: trend.map(t => `D${t.day}`),
      datasets: [
        { label: 'Critical', data: trend.map(t => t.critical),
          borderColor: '#f87171', backgroundColor: 'rgba(248,113,113,.07)',
          tension: 0.4, fill: true, pointRadius: 0, borderWidth: 2 },
        { label: 'High',     data: trend.map(t => t.high),
          borderColor: '#fbbf24', backgroundColor: 'rgba(251,191,36,.05)',
          tension: 0.4, fill: true, pointRadius: 0, borderWidth: 1.5 },
        { label: 'Medium',   data: trend.map(t => t.medium),
          borderColor: '#38bdf8', backgroundColor: 'rgba(56,189,248,.04)',
          tension: 0.4, fill: true, pointRadius: 0, borderWidth: 1.5 },
      ]
    },
    options: {
      maintainAspectRatio: false,
      scales: {
        x: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { maxTicksLimit: 10 } },
        y: { grid: { color: 'rgba(255,255,255,0.04)' }, beginAtZero: true },
      },
      plugins: {
        legend: { position: 'top', align: 'end',
                  labels: { padding: 14, usePointStyle: true, pointStyle: 'circle' } }
      },
      interaction: { mode: 'index', intersect: false },
    }
  });
}

// ── Risk by department — bar ─────────────────────────────────
function renderDeptChart(deptRisk) {
  _destroy('deptChart');
  const ctx = document.getElementById('deptChart');
  if (!ctx) return;
  const depts = Object.keys(deptRisk);
  const pcts  = depts.map(d =>
    deptRisk[d].total ? Math.round((deptRisk[d].high / deptRisk[d].total) * 100) : 0
  );
  _charts.deptChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: depts,
      datasets: [{
        label: 'High Risk %',
        data: pcts,
        backgroundColor: pcts.map(p => p > 60 ? 'rgba(248,113,113,.65)' : p > 30 ? 'rgba(251,191,36,.65)' : 'rgba(74,222,128,.65)'),
        borderColor:     pcts.map(p => p > 60 ? '#f87171' : p > 30 ? '#fbbf24' : '#4ade80'),
        borderWidth: 1.5,
        borderRadius: 3,
      }]
    },
    options: {
      maintainAspectRatio: false,
      scales: {
        x: { grid: { display: false } },
        y: { grid: { color: 'rgba(255,255,255,0.04)' }, beginAtZero: true, max: 100,
             ticks: { callback: v => v + '%' } },
      },
      plugins: { legend: { display: false } },
    }
  });
}

// ── Privilege distribution — polar area ──────────────────────
function renderPrivChart(data) {
  _destroy('privChart');
  const ctx = document.getElementById('privChart');
  if (!ctx) return;
  const counts = { critical: 0, high: 0, medium: 0 };
  data.forEach(p => { if (p.risk in counts) counts[p.risk]++; });
  _charts.privChart = new Chart(ctx, {
    type: 'polarArea',
    data: {
      labels: ['Critical', 'High', 'Medium'],
      datasets: [{
        data: [counts.critical, counts.high, counts.medium],
        backgroundColor: ['rgba(248,113,113,.6)', 'rgba(251,191,36,.6)', 'rgba(56,189,248,.6)'],
        borderColor:     ['#f87171', '#fbbf24', '#38bdf8'],
        borderWidth: 1.5,
      }]
    },
    options: {
      scales: { r: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { display: false } } },
      plugins: { legend: { position: 'bottom', labels: { usePointStyle: true, padding: 10 } } },
    }
  });
}

// ── Threat vectors — doughnut ────────────────────────────────
function renderThreatChart(threats) {
  _destroy('threatChart');
  const ctx = document.getElementById('threatChart');
  if (!ctx) return;
  const types = {};
  threats.forEach(t => { types[t.type] = (types[t.type] || 0) + 1; });
  _charts.threatChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: Object.keys(types),
      datasets: [{
        data: Object.values(types),
        backgroundColor: [
          'rgba(248,113,113,.65)', 'rgba(251,191,36,.65)',
          'rgba(56,189,248,.65)',  'rgba(74,222,128,.65)',
          'rgba(167,139,250,.65)',
        ],
        borderWidth: 1.5,
      }]
    },
    options: {
      cutout: '60%',
      plugins: { legend: { position: 'bottom', labels: { usePointStyle: true, padding: 8, font: { size: 10 } } } }
    }
  });
}

// ── Policy compliance — radar ────────────────────────────────
function renderComplianceChart(policies) {
  _destroy('complianceChart');
  const ctx = document.getElementById('complianceChart');
  if (!ctx) return;
  _charts.complianceChart = new Chart(ctx, {
    type: 'radar',
    data: {
      labels: policies.map(p => p.name.split(' ').slice(0, 2).join(' ')),
      datasets: [{
        label: 'Compliance %',
        data: policies.map(p => p.pct),
        backgroundColor: 'rgba(56,189,248,0.12)',
        borderColor: '#38bdf8',
        borderWidth: 1.5,
        pointBackgroundColor: '#38bdf8',
        pointRadius: 3,
      }]
    },
    options: {
      scales: {
        r: {
          grid:        { color: 'rgba(255,255,255,0.05)' },
          angleLines:  { color: 'rgba(255,255,255,0.05)' },
          pointLabels: { font: { size: 9 } },
          beginAtZero: true, max: 100,
          ticks: { display: false },
        }
      },
      plugins: { legend: { display: false } },
    }
  });
}
