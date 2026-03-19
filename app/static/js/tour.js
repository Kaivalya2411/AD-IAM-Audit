/* ─────────────────────────────────────────────────────────
   tour.js  —  Interactive App Tour Engine
   AD/IAM Auditor v3
   ───────────────────────────────────────────────────────── */

const TOUR = (() => {

  // ── Tour steps definition ────────────────────────────────
  const STEPS = [
    {
      target:   '.sidebar-logo',
      title:    'AD/IAM Auditor',
      category: 'Welcome',
      desc:     'This is your Active Directory & Identity Management security console. Every feature is accessible from the left sidebar.',
      features: [
        'Real-time security monitoring across all AD users',
        'Audit log with full event history',
        'SOC 2 & ISO 27001 compliance tracking',
        'One-click CSV / PDF report exports',
      ],
      position: 'right',
    },
    {
      target:   '.topbar',
      title:    'Top Navigation Bar',
      category: 'Navigation',
      desc:     'The topbar shows your current section, a global search bar, live risk score, and the current time.',
      features: [
        'Ctrl+K opens global search from anywhere',
        'Risk pill updates automatically from live data',
        'Clock shows server UTC time',
      ],
      position: 'bottom',
    },
    {
      target:   '[href*="dashboard"], [href="/"], .nav-link[href="/dashboard"]',
      title:    'Security Dashboard',
      category: 'Monitor',
      desc:     'The dashboard gives you an instant security overview — KPI cards, 30-day risk trend, account status breakdown, and active findings.',
      features: [
        'Security Score out of 100 — calculated live',
        'Risk trend line shows Critical / High / Medium over 30 days',
        'Active findings list with colour-coded severity',
        'Recent events feed from the audit log',
      ],
      position: 'right',
      link:     '/dashboard',
    },
    {
      target:   '[href*="/users"]',
      title:    'User Management',
      category: 'Monitor',
      desc:     'Full directory of all AD users. Filter by status, risk level, or department. View detailed profiles and take actions directly.',
      features: [
        'Search across username, name, and department',
        'Filter by Active / Stale / Disabled status',
        'MFA status shown per user with badge',
        'Disable accounts and force password resets',
      ],
      position: 'right',
      link:     '/users',
    },
    {
      target:   '[href*="/groups"]',
      title:    'Group Management',
      category: 'Monitor',
      desc:     'View all AD security and distribution groups. Privileged groups are flagged. Nested group risks are highlighted.',
      features: [
        'Privileged groups marked with danger badge',
        'Nested group count warns of escalation paths',
        'Member count pulled live from the database',
      ],
      position: 'right',
      link:     '/groups',
    },
    {
      target:   '[href*="/passwords"]',
      title:    'Password Expiry Tracker',
      category: 'Identity',
      desc:     'Track password expiry status for every user. See who is expired, who is expiring soon, and force resets directly from this page.',
      features: [
        'Days remaining shown as positive or negative',
        'Expired passwords flagged in red',
        'Warning threshold: within 14 days',
        'Force reset button triggers a logged action',
      ],
      position: 'right',
      link:     '/passwords',
    },
    {
      target:   '[href*="/sessions"]',
      title:    'Session Monitor',
      category: 'Identity',
      desc:     'Live view of all active, expired, and blocked sessions. External IPs are flagged automatically. Sessions auto-refresh every 30 seconds.',
      features: [
        'External IPs highlighted with warning icon',
        'Terminate suspicious sessions with one click',
        'Blocked sessions from threat indicators shown',
        'Auto-refreshes every 30 seconds',
      ],
      position: 'right',
      link:     '/sessions',
    },
    {
      target:   '[href*="/access-review"]',
      title:    'Access Review Workflow',
      category: 'Identity',
      desc:     'Structured workflow for reviewing and certifying user access. Approve or revoke access assignments with a full audit trail.',
      features: [
        'Review due dates with overdue highlighting',
        'One-click Approve or Revoke decisions',
        'All decisions logged to the audit trail',
        'Filter by pending, approved, or revoked',
      ],
      position: 'right',
      link:     '/access-review',
    },
    {
      target:   '[href*="/privileges"]',
      title:    'Privilege Audit',
      category: 'Security',
      desc:     'Review all elevated access assignments. See how long each privilege has been held and identify over-provisioned users.',
      features: [
        'Days held counter flags long-running access',
        'Revoke privileges directly from the table',
        'Polar area chart shows critical / high / medium split',
        'Over-provisioned users flagged automatically',
      ],
      position: 'right',
      link:     '/privileges',
    },
    {
      target:   '[href*="/anomalies"]',
      title:    'Anomaly Detection',
      category: 'Investigate',
      desc:     'Automatically detected suspicious activity: brute force attacks, off-hours logins, privilege escalation attempts, TOR node access.',
      features: [
        'Brute force, phantom logins, TOR nodes detected',
        'Off-hours admin access flagged',
        'Investigate → Resolved workflow per anomaly',
        'Full description with source IP and timestamp',
      ],
      position: 'right',
      link:     '/anomalies',
    },
    {
      target:   '[href*="/audit"]',
      title:    'Audit Log',
      category: 'Investigate',
      desc:     'Complete paginated event log. Filter by event type (login, modify, delete, escalate) and result (success / failed).',
      features: [
        'Filter by type: login, modify, create, delete, escalate',
        'Filter by result: success or failed',
        'Source IP shown for every event',
        'Paginated with 15 events per page',
      ],
      position: 'right',
      link:     '/audit',
    },
    {
      target:   '[href*="/timeline"]',
      title:    'Audit Timeline',
      category: 'Investigate',
      desc:     'Visual chronological feed of all security events. Colour-coded by severity with category tags for fast scanning.',
      features: [
        'Visual timeline with severity colour coding',
        'Filter by category: Auth, Change, Security',
        'Detailed description per event with IP',
        'Paginated — loads 15 events at a time',
      ],
      position: 'right',
      link:     '/timeline',
    },
    {
      target:   '[href*="/threats"]',
      title:    'Threat Intelligence',
      category: 'Security',
      desc:     'Known threat indicators: brute force IPs, TOR nodes, phantom logins. Resolve or escalate each indicator with a click.',
      features: [
        'Critical indicators shown with hit count',
        'Attack vector breakdown doughnut chart',
        'Resolve threats and log the action',
        'Status: active → reviewing → resolved',
      ],
      position: 'right',
      link:     '/threats',
    },
    {
      target:   '[href*="/assets"]',
      title:    'Asset Inventory',
      category: 'Infrastructure',
      desc:     'All AD-connected assets: servers, workstations, VMs. EOL operating systems are automatically flagged in red.',
      features: [
        'EOL OS badge on Windows Server 2012 and below',
        'Stale assets inactive 90+ days highlighted',
        'Filter by type: DC, File Server, Workstation…',
        'Risk level per asset based on exposure',
      ],
      position: 'right',
      link:     '/assets',
    },
    {
      target:   '[href*="/soc-alerts"]',
      title:    'SOC Alert Queue',
      category: 'Infrastructure',
      desc:     'Centralised alert queue for the security team. Assign alerts to analysts, track through to resolution, export for reporting.',
      features: [
        'KPI cards show open / critical / high / resolved counts',
        'Assign alerts to team members',
        'Resolve alerts with automatic close timestamp',
        'Filter by severity and status',
      ],
      position: 'right',
      link:     '/soc-alerts',
    },
    {
      target:   '[href*="/policies"]',
      title:    'Security Policies',
      category: 'Output',
      desc:     'Policy compliance tracking with pass/fail counts and percentage scores. Visual progress bars show compliance at a glance.',
      features: [
        'Pass/fail counts per policy rule',
        'Compliance % with colour-coded bar',
        'Radar chart shows full policy landscape',
        '8 built-in policies across 4 categories',
      ],
      position: 'right',
      link:     '/policies',
    },
    {
      target:   '[href*="/compliance"]',
      title:    'Compliance Framework',
      category: 'Output',
      desc:     'SOC 2 and ISO 27001 control mapping. Track pass/fail per control, add evidence notes, and see overall framework scores.',
      features: [
        'SOC 2 and ISO 27001 frameworks built-in',
        'Score per framework shown as percentage',
        'Mark controls pass/fail with evidence',
        'Filter by framework or status',
      ],
      position: 'right',
      link:     '/compliance',
    },
    {
      target:   '[href*="/reports"]',
      title:    'Report Generator',
      category: 'Output',
      desc:     'Generate six types of reports — preview them inline or download as CSV or PDF. All data comes live from the SQLite database.',
      features: [
        'Stale Accounts, Privilege Audit, Threat, Compliance',
        'MFA Coverage and Full IAM Audit reports',
        'CSV download for spreadsheet analysis',
        'PDF opens the browser print dialog',
      ],
      position: 'right',
      link:     '/reports',
    },
    {
      target:   '[href*="/toolkit"]',
      title:    'Security Toolkit',
      category: 'Tools',
      desc:     '12 built-in security tools — no external websites needed. Everything runs in your browser.',
      features: [
        'Base64 encode/decode with file support',
        'MD5, SHA-1, SHA-256, SHA-512 hash generator',
        'JWT decoder with expiry check',
        'CIDR/IP calculator, Regex tester, JSON formatter',
        'Password strength checker + secure generator',
        'UUID/token generator, Timestamp converter, Text diff',
      ],
      position: 'right',
      link:     '/toolkit',
    },
    {
      target:   '[href*="/settings"]',
      title:    'Settings',
      category: 'Configuration',
      desc:     'Configure your Active Directory connection, audit rules, and notification thresholds. View live database stats.',
      features: [
        'Connect to real AD via LDAP (ldap3 library)',
        'Set stale account threshold (default 90 days)',
        'Toggle MFA enforcement and alert rules',
        'View DB record counts across all tables',
      ],
      position: 'right',
      link:     '/settings',
    },
  ];

  // ── State ────────────────────────────────────────────────
  let current   = 0;
  let active    = false;
  let maskEls   = [];

  // ── DOM elements (created once) ──────────────────────────
  let overlay, highlight, card, arrow, welcome, finish, launcher;

  // ── Init ─────────────────────────────────────────────────
  function init() {
    _buildDOM();
    _bindKeys();

    // Show welcome screen if first visit
    if (!localStorage.getItem('adaudit_tour_done')) {
      setTimeout(() => _showWelcome(), 600);
    }
  }

  // ── Build all DOM ─────────────────────────────────────────
  function _buildDOM() {
    // Welcome screen
    welcome = _el('div', { id: 'tourWelcome', class: 'tour-hidden' });
    welcome.innerHTML = `
      <div class="tour-welcome-card">
        <div class="tour-welcome-hero">
          <div class="tour-welcome-hexagon">
            <span class="tour-welcome-icon">⬡</span>
          </div>
          <div class="tour-welcome-title">AD/IAM AUDITOR</div>
          <div class="tour-welcome-sub">IAM Security Console — v3.0</div>
        </div>
        <div class="tour-welcome-body">
          <p class="tour-welcome-desc">
            Welcome! This console helps you audit Active Directory identities,
            detect threats, track compliance, and generate security reports.
          </p>
          <div class="tour-feature-grid">
            <div class="tour-feature-chip"><span class="tour-feature-chip-icon">👥</span>User & Group Audit</div>
            <div class="tour-feature-chip"><span class="tour-feature-chip-icon">🔐</span>Password Tracking</div>
            <div class="tour-feature-chip"><span class="tour-feature-chip-icon">🚨</span>SOC Alert Queue</div>
            <div class="tour-feature-chip"><span class="tour-feature-chip-icon">⚠</span>Anomaly Detection</div>
            <div class="tour-feature-chip"><span class="tour-feature-chip-icon">🛡</span>Compliance (SOC2)</div>
            <div class="tour-feature-chip"><span class="tour-feature-chip-icon">📋</span>Report Generator</div>
          </div>
          <div class="tour-welcome-actions">
            <button class="btn btn-primary tour-btn tour-btn-start tour-btn-finish" onclick="TOUR.start()">
              ▶ Start Guided Tour (${STEPS.length} stops)
            </button>
            <button class="tour-btn-nosee" onclick="TOUR.skipForever()">
              Don't show this again
            </button>
          </div>
        </div>
      </div>`;
    document.body.appendChild(welcome);

    // Overlay backdrop
    overlay = _el('div', { id: 'tourOverlay', class: 'tour-hidden' });
    document.body.appendChild(overlay);

    // Four mask panels
    maskEls = ['top','bottom','left','right'].map(side => {
      const m = _el('div', { class: `tour-mask tour-mask-${side} tour-hidden` });
      document.body.appendChild(m);
      return m;
    });

    // Spotlight highlight border
    highlight = _el('div', { id: 'tourHighlight', class: 'tour-hidden' });
    document.body.appendChild(highlight);

    // Arrow/caret
    arrow = _el('div', { id: 'tourArrow', class: 'tour-hidden' });
    document.body.appendChild(arrow);

    // Tour card
    card = _el('div', { id: 'tourCard', class: 'tour-hidden' });
    document.body.appendChild(card);

    // Finish card
    finish = _el('div', { id: 'tourFinish', class: 'tour-hidden' });
    finish.innerHTML = `
      <div class="tour-finish-card">
        <span class="tour-finish-icon">✓</span>
        <div class="tour-finish-title">Tour Complete!</div>
        <p class="tour-finish-desc">
          You've seen all ${STEPS.length} features of AD/IAM Auditor.
          Here are some shortcuts to get you started quickly.
        </p>
        <div class="tour-finish-shortcuts">
          <div class="tour-shortcut"><kbd>Ctrl+K</kbd><div>Global search</div></div>
          <div class="tour-shortcut"><kbd>/dashboard</kbd><div>Security overview</div></div>
          <div class="tour-shortcut"><kbd>/soc-alerts</kbd><div>Open alerts queue</div></div>
          <div class="tour-shortcut"><kbd>/reports</kbd><div>Generate a report</div></div>
        </div>
        <button class="btn btn-primary tour-btn tour-btn-finish" style="width:100%;justify-content:center" onclick="TOUR.closeFinal()">
          🚀 Start Using the App
        </button>
      </div>`;
    document.body.appendChild(finish);

    // Launcher button (always visible after first tour)
    launcher = _el('button', { id: 'tourLauncher' });
    launcher.innerHTML = `<span class="tour-launcher-dot">?</span> Guided Tour`;
    launcher.addEventListener('click', () => _showWelcome());
    document.body.appendChild(launcher);

    // Click outside mask to advance
    maskEls.forEach(m => m.addEventListener('click', () => next()));
    overlay.addEventListener('click', () => next());
  }

  // ── Show welcome screen ───────────────────────────────────
  function _showWelcome() {
    welcome.classList.remove('tour-hidden');
  }

  // ── Start tour ────────────────────────────────────────────
  function start() {
    welcome.classList.add('tour-hidden');
    active  = true;
    current = 0;
    _showOverlay();
    _renderStep(current);
  }

  // ── Skip / dismiss ────────────────────────────────────────
  function skip() {
    _teardown();
    welcome.classList.add('tour-hidden');
  }

  function skipForever() {
    localStorage.setItem('adaudit_tour_done', '1');
    skip();
  }

  // ── Navigation ────────────────────────────────────────────
  function next() {
    if (!active) return;
    if (current >= STEPS.length - 1) {
      _showFinish();
      return;
    }
    current++;
    _renderStep(current);
  }

  function prev() {
    if (!active || current <= 0) return;
    current--;
    _renderStep(current);
  }

  function goTo(index) {
    if (!active) return;
    current = Math.max(0, Math.min(index, STEPS.length - 1));
    _renderStep(current);
  }

  function closeFinal() {
    localStorage.setItem('adaudit_tour_done', '1');
    finish.classList.add('tour-hidden');
    _teardown();
  }

  // ── Render a step ─────────────────────────────────────────
  function _renderStep(index) {
    const step = STEPS[index];
    const pct  = ((index + 1) / STEPS.length) * 100;
    const isFirst = index === 0;
    const isLast  = index === STEPS.length - 1;

    // Find target element
    const target = document.querySelector(step.target);
    const rect   = target ? target.getBoundingClientRect() : _centreRect();

    // Spotlight
    _positionHighlight(rect);
    _positionMasks(rect);

    // Build card HTML
    const dots = STEPS.map((_, i) => {
      const cls = i === index ? 'active' : i < index ? 'done' : '';
      return `<div class="tour-dot ${cls}" onclick="TOUR.goTo(${i})" title="Step ${i+1}"></div>`;
    }).join('');

    const features = (step.features || []).map(f => `<li>${f}</li>`).join('');

    card.innerHTML = `
      <div class="tour-card-accent"></div>
      <div class="tour-card-inner">
        <div class="tour-step-row">
          <span class="tour-step-badge">${index + 1} / ${STEPS.length}</span>
          <div class="tour-progress-dots">${dots}</div>
        </div>
        <div class="tour-category">${step.category || ''}</div>
        <div class="tour-title">${step.title}</div>
        <div class="tour-desc">${step.desc}</div>
        ${features ? `<ul class="tour-features">${features}</ul>` : ''}
        <div class="tour-progress-bar-wrap">
          <div class="tour-progress-bar" style="width:${pct}%"></div>
        </div>
        <div class="tour-nav">
          <button class="tour-btn tour-btn-skip" onclick="TOUR.skip()">✕ Skip Tour</button>
          <div style="display:flex;gap:.4rem;align-items:center">
            ${!isFirst ? `<button class="tour-btn tour-btn-prev" onclick="TOUR.prev()">← Back</button>` : ''}
            ${!isLast
              ? `<button class="tour-btn tour-btn-next" onclick="TOUR.next()">Next →</button>`
              : `<button class="tour-btn tour-btn-finish" onclick="TOUR._showFinish()">Finish ✓</button>`
            }
          </div>
        </div>
      </div>`;

    card.classList.remove('tour-hidden');
    card.classList.remove('tour-card-enter');
    void card.offsetWidth; // force reflow
    card.classList.add('tour-card-enter');

    // Position card relative to target
    requestAnimationFrame(() => _positionCard(rect, step.position || 'right'));
  }

  // ── Position the spotlight highlight ──────────────────────
  function _positionHighlight(rect) {
    const pad = 6;
    Object.assign(highlight.style, {
      top:    (rect.top    - pad) + 'px',
      left:   (rect.left   - pad) + 'px',
      width:  (rect.width  + pad * 2) + 'px',
      height: (rect.height + pad * 2) + 'px',
    });
    highlight.classList.remove('tour-hidden');
  }

  // ── Position four dark mask panels ────────────────────────
  function _positionMasks(rect) {
    const pad = 6;
    const vw  = window.innerWidth;
    const vh  = window.innerHeight;
    const t   = rect.top    - pad;
    const l   = rect.left   - pad;
    const r   = rect.right  + pad;
    const b   = rect.bottom + pad;

    const positions = [
      { top: '0',  left: '0',  width: vw + 'px', height: Math.max(0, t) + 'px' },           // top
      { top: b + 'px', left: '0', width: vw + 'px', height: Math.max(0, vh - b) + 'px' },   // bottom
      { top: t + 'px', left: '0', width: Math.max(0, l) + 'px', height: (b - t) + 'px' },   // left
      { top: t + 'px', left: r + 'px', width: Math.max(0, vw - r) + 'px', height: (b - t) + 'px' }, // right
    ];

    maskEls.forEach((m, i) => {
      Object.assign(m.style, positions[i]);
      m.classList.remove('tour-hidden');
    });
  }

  // ── Position card ─────────────────────────────────────────
  function _positionCard(rect, preferredPos) {
    const cw  = card.offsetWidth  || 340;
    const ch  = card.offsetHeight || 300;
    const vw  = window.innerWidth;
    const vh  = window.innerHeight;
    const pad = 16;
    const gap = 20;

    let pos = preferredPos;
    let top, left;

    // Determine best position
    const fits = {
      right:  rect.right  + gap + cw + pad < vw,
      left:   rect.left   - gap - cw - pad > 0,
      bottom: rect.bottom + gap + ch + pad < vh,
      top:    rect.top    - gap - ch - pad > 0,
    };

    if (!fits[pos]) {
      pos = ['right','left','bottom','top'].find(p => fits[p]) || 'bottom';
    }

    const midX = rect.left + rect.width  / 2;
    const midY = rect.top  + rect.height / 2;

    if (pos === 'right') {
      left = rect.right + gap;
      top  = Math.max(pad, Math.min(midY - ch / 2, vh - ch - pad));
    } else if (pos === 'left') {
      left = rect.left - gap - cw;
      top  = Math.max(pad, Math.min(midY - ch / 2, vh - ch - pad));
    } else if (pos === 'bottom') {
      top  = rect.bottom + gap;
      left = Math.max(pad, Math.min(midX - cw / 2, vw - cw - pad));
    } else {
      top  = rect.top - gap - ch;
      left = Math.max(pad, Math.min(midX - cw / 2, vw - cw - pad));
    }

    card.style.top  = Math.max(pad, top)  + 'px';
    card.style.left = Math.max(pad, left) + 'px';

    // Arrow
    _positionArrow(rect, pos);
  }

  // ── Position arrow caret ─────────────────────────────────
  function _positionArrow(rect, pos) {
    arrow.className = 'tour-hidden';
    if (!rect || rect.width === 0) return;

    const cRect = card.getBoundingClientRect();
    arrow.className = '';

    const arrowClasses = {
      right:  'tour-arrow-left',
      left:   'tour-arrow-right',
      bottom: 'tour-arrow-top',
      top:    'tour-arrow-bottom',
    };
    arrow.className = arrowClasses[pos] || '';

    const midX = rect.left + rect.width  / 2;
    const midY = rect.top  + rect.height / 2;

    if (pos === 'right') {
      arrow.style.top  = (Math.max(cRect.top, Math.min(midY - 8, cRect.bottom - 16))) + 'px';
      arrow.style.left = (cRect.left - 10) + 'px';
    } else if (pos === 'left') {
      arrow.style.top  = (Math.max(cRect.top, Math.min(midY - 8, cRect.bottom - 16))) + 'px';
      arrow.style.left = (cRect.right) + 'px';
    } else if (pos === 'bottom') {
      arrow.style.top  = (cRect.top - 10) + 'px';
      arrow.style.left = (Math.max(cRect.left, Math.min(midX - 8, cRect.right - 16))) + 'px';
    } else {
      arrow.style.top  = (cRect.bottom) + 'px';
      arrow.style.left = (Math.max(cRect.left, Math.min(midX - 8, cRect.right - 16))) + 'px';
    }
  }

  // ── Show overlay ──────────────────────────────────────────
  function _showOverlay() {
    overlay.classList.remove('tour-hidden');
  }

  // ── Show finish screen ────────────────────────────────────
  function _showFinish() {
    _teardown(true);
    finish.classList.remove('tour-hidden');
  }

  // ── Tear down tour UI ─────────────────────────────────────
  function _teardown(keepFinish = false) {
    active = false;
    overlay.classList.add('tour-hidden');
    highlight.classList.add('tour-hidden');
    card.classList.add('tour-hidden');
    arrow.classList.add('tour-hidden');
    maskEls.forEach(m => m.classList.add('tour-hidden'));
    if (!keepFinish) finish.classList.add('tour-hidden');
  }

  // ── Keyboard navigation ───────────────────────────────────
  function _bindKeys() {
    document.addEventListener('keydown', e => {
      if (!active) return;
      if (e.key === 'ArrowRight' || e.key === 'Enter') { e.preventDefault(); next(); }
      if (e.key === 'ArrowLeft')  { e.preventDefault(); prev(); }
      if (e.key === 'Escape')     { e.preventDefault(); skip(); }
    });
  }

  // ── Helpers ───────────────────────────────────────────────
  function _el(tag, attrs = {}) {
    const el = document.createElement(tag);
    Object.entries(attrs).forEach(([k, v]) => el.setAttribute(k, v));
    return el;
  }

  function _centreRect() {
    return {
      top: window.innerHeight / 2 - 50, left: window.innerWidth / 2 - 100,
      bottom: window.innerHeight / 2 + 50, right: window.innerWidth / 2 + 100,
      width: 200, height: 100,
    };
  }

  // ── Public API ────────────────────────────────────────────
  return { init, start, skip, skipForever, next, prev, goTo, _showFinish, closeFinal };

})();

// Auto-init on DOM ready
document.addEventListener('DOMContentLoaded', () => TOUR.init());

// Clean up tour if user navigates away mid-tour
window.addEventListener('beforeunload', () => {
  if (typeof TOUR !== 'undefined') TOUR.skip();
});
