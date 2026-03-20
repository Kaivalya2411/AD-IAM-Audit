/* ─────────────────────────────────────────────────────────
   theme-switcher.js  —  Theme Engine
   Themes saved to localStorage('adaudit_theme')
   Applied via data-theme attribute on <html>
   ───────────────────────────────────────────────────────── */

const THEMES = [
  {
    id:      'ocean',
    name:    'Ocean',
    desc:    'Default dark blue',
    preview: ['#0d1117','#131920','#38bdf8'],
  },
  {
    id:      'midnight',
    name:    'Midnight',
    desc:    'Deep purple dark',
    preview: ['#100e1a','#161322','#a78bfa'],
  },
  {
    id:      'forest',
    name:    'Forest',
    desc:    'Dark green',
    preview: ['#0d1610','#111e15','#4ade80'],
  },
  {
    id:      'sunset',
    name:    'Sunset',
    desc:    'Warm amber dark',
    preview: ['#18100a','#21160d','#fb923c'],
  },
  {
    id:      'rose',
    name:    'Rose',
    desc:    'Dark pink accent',
    preview: ['#180d11','#201217','#f472b6'],
  },
  {
    id:      'slate',
    name:    'Slate',
    desc:    'Cool blue-grey',
    preview: ['#111520','#171c2a','#60a5fa'],
  },
  {
    id:      'contrast',
    name:    'Contrast',
    desc:    'High contrast',
    preview: ['#0a0a0a','#111111','#00e5ff'],
  },
  {
    id:      'light',
    name:    'Light',
    desc:    'Clean & bright',
    preview: ['#ffffff','#f8f9fa','#6366f1'],
  },
];

// ── Apply theme ───────────────────────────────────────────
function applyTheme(id) {
  const theme = THEMES.find(t => t.id === id) || THEMES[0];

  // Add transition class only for the brief switch duration
  document.documentElement.classList.add('theme-switching');
  document.documentElement.setAttribute('data-theme', theme.id);
  localStorage.setItem('adaudit_theme', theme.id);

  // Remove transition class after animation completes
  clearTimeout(applyTheme._timer);
  applyTheme._timer = setTimeout(() => {
    document.documentElement.classList.remove('theme-switching');
  }, 350);

  // Update all pickers if open
  document.querySelectorAll('.theme-chip').forEach(el => {
    el.classList.toggle('active', el.dataset.themeId === theme.id);
  });
  // Update topbar indicator
  const ind = document.getElementById('themeIndicator');
  if (ind) {
    ind.style.background = theme.preview[2];
    ind.title = theme.name;
  }
}

// ── Load saved theme on boot ──────────────────────────────
(function initTheme() {
  const saved = localStorage.getItem('adaudit_theme') || 'ocean';
  document.documentElement.setAttribute('data-theme', saved);
})();

// ── Build the floating theme picker panel ─────────────────
function buildThemePicker() {
  if (document.getElementById('themePicker')) return;

  const picker = document.createElement('div');
  picker.id = 'themePicker';
  picker.innerHTML = `
    <div class="tp-header">
      <span class="tp-title">🎨 Themes</span>
      <button class="tp-close" onclick="closeThemePicker()">✕</button>
    </div>
    <div class="tp-grid">
      ${THEMES.map(t => `
        <button class="theme-chip ${document.documentElement.getAttribute('data-theme') === t.id ? 'active' : ''}"
                data-theme-id="${t.id}"
                onclick="applyTheme('${t.id}')"
                title="${t.name} — ${t.desc}">
          <div class="tc-preview">
            <div class="tc-bg"  style="background:${t.preview[0]}"></div>
            <div class="tc-mid" style="background:${t.preview[1]}"></div>
            <div class="tc-acc" style="background:${t.preview[2]}"></div>
          </div>
          <div class="tc-label">${t.name}</div>
          <div class="tc-desc">${t.desc}</div>
          <div class="tc-check">✓</div>
        </button>`).join('')}
    </div>
    <div class="tp-footer">
      <span class="tp-note">Preference saved automatically</span>
    </div>`;
  document.body.appendChild(picker);

  // Close when clicking outside
  document.addEventListener('mousedown', outsidePickerClose);
}

function outsidePickerClose(e) {
  const picker  = document.getElementById('themePicker');
  const trigger = document.getElementById('themeToggleBtn');
  if (picker && !picker.contains(e.target) && trigger && !trigger.contains(e.target)) {
    closeThemePicker();
  }
}

function openThemePicker() {
  buildThemePicker();
  const picker = document.getElementById('themePicker');
  picker.classList.add('open');
}

function closeThemePicker() {
  const picker = document.getElementById('themePicker');
  if (picker) picker.classList.remove('open');
  document.removeEventListener('mousedown', outsidePickerClose);
}

function toggleThemePicker() {
  const picker = document.getElementById('themePicker');
  if (picker && picker.classList.contains('open')) closeThemePicker();
  else openThemePicker();
}

// ── Inject topbar button + styles once DOM is ready ───────
document.addEventListener('DOMContentLoaded', () => {
  // Re-apply saved theme (also done above but ensures DOM is ready)
  const saved = localStorage.getItem('adaudit_theme') || 'ocean';
  applyTheme(saved);

  // Inject theme button into topbar-right
  const topbarRight = document.querySelector('.topbar-right');
  if (topbarRight) {
    const btn = document.createElement('button');
    btn.id        = 'themeToggleBtn';
    btn.className = 'topbar-theme-btn';
    btn.title     = 'Switch theme';
    btn.onclick   = toggleThemePicker;
    btn.innerHTML = `
      <div id="themeIndicator" class="theme-indicator" style="background:${THEMES.find(t=>t.id===saved)?.preview[2]||'#38bdf8'}"></div>
      <svg width="14" height="14" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5">
        <circle cx="10" cy="10" r="3"/>
        <path d="M10 2v2M10 16v2M2 10h2M16 10h2M4.22 4.22l1.42 1.42M14.36 14.36l1.42 1.42M4.22 15.78l1.42-1.42M14.36 5.64l1.42-1.42"/>
      </svg>`;
    // Insert before avatar
    const avatar = topbarRight.querySelector('.topbar-avatar');
    if (avatar) topbarRight.insertBefore(btn, avatar);
    else topbarRight.appendChild(btn);
  }

  // Inject styles
  injectPickerStyles();
});

function injectPickerStyles() {
  const style = document.createElement('style');
  style.textContent = `
    /* ── Topbar theme button ────────────────── */
    .topbar-theme-btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: var(--bg3);
      border: 1px solid var(--border2);
      border-radius: 7px;
      padding: 5px 10px;
      color: var(--text2);
      cursor: pointer;
      font-size: .72rem;
      transition: all .18s ease;
    }
    .topbar-theme-btn:hover {
      color: var(--text1);
      border-color: var(--text2);
    }
    .theme-indicator {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      flex-shrink: 0;
      transition: background .25s ease;
    }

    /* ── Picker panel ───────────────────────── */
    #themePicker {
      position: fixed;
      top: 64px;
      right: 1rem;
      z-index: 10000;
      width: 340px;
      background: var(--bg2);
      border: 1px solid var(--border2);
      border-radius: 12px;
      box-shadow: 0 16px 48px rgba(0,0,0,.6), 0 0 0 1px rgba(255,255,255,.04);
      opacity: 0;
      transform: translateY(-8px) scale(.97);
      pointer-events: none;
      transition: opacity .2s ease, transform .2s ease;
      overflow: hidden;
    }
    #themePicker.open {
      opacity: 1;
      transform: translateY(0) scale(1);
      pointer-events: all;
    }
    .tp-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: .75rem 1rem;
      border-bottom: 1px solid var(--border);
    }
    .tp-title {
      font-size: .78rem;
      font-weight: 600;
      color: var(--text0);
      letter-spacing: .01em;
    }
    .tp-close {
      background: none;
      border: none;
      color: var(--text2);
      cursor: pointer;
      font-size: .85rem;
      padding: .1rem .3rem;
      border-radius: 4px;
      transition: color .15s;
    }
    .tp-close:hover { color: var(--text1); }

    /* ── Theme chips grid ───────────────────── */
    .tp-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: .45rem;
      padding: .75rem;
    }
    .theme-chip {
      background: var(--bg3);
      border: 1.5px solid var(--border);
      border-radius: 8px;
      padding: .55rem .65rem;
      cursor: pointer;
      text-align: left;
      transition: all .18s ease;
      position: relative;
      overflow: hidden;
    }
    .theme-chip:hover {
      border-color: var(--border2);
      background: var(--bg4);
      transform: translateY(-1px);
    }
    .theme-chip.active {
      border-color: var(--accent);
      background: var(--accent-dim);
    }
    .tc-preview {
      display: flex;
      gap: 3px;
      margin-bottom: .45rem;
      height: 22px;
      border-radius: 4px;
      overflow: hidden;
    }
    .tc-bg  { flex: 2; }
    .tc-mid { flex: 1; }
    .tc-acc { flex: 0.6; border-radius: 0 3px 3px 0; }
    .tc-label {
      font-size: .72rem;
      font-weight: 600;
      color: var(--text0);
      margin-bottom: .1rem;
    }
    .tc-desc {
      font-size: .63rem;
      color: var(--text2);
    }
    .tc-check {
      position: absolute;
      top: .45rem;
      right: .55rem;
      font-size: .65rem;
      color: var(--accent);
      font-weight: 700;
      opacity: 0;
      transition: opacity .15s;
    }
    .theme-chip.active .tc-check { opacity: 1; }

    .tp-footer {
      padding: .5rem 1rem .65rem;
      border-top: 1px solid var(--border);
    }
    .tp-note {
      font-size: .63rem;
      color: var(--text2);
    }

    /* ── Light theme: picker panel override ── */
    [data-theme="light"] #themePicker {
      box-shadow: 0 8px 32px rgba(0,0,0,.15), 0 0 0 0.5px #e2e8f0;
    }
    [data-theme="light"] .topbar-theme-btn {
      background: #f8f9fa;
      border-color: #e2e8f0;
    }
  `;
  document.head.appendChild(style);
}
