/* ─────────────────────────────────────────────────────────
   forms.js  —  Shared CRUD Form Engine
   Handles: open/close modals, validation, submit, confirm-delete
   ───────────────────────────────────────────────────────── */

// ── Universal CRUD Modal ────────────────────────────────────
const FORM = {

  // Open a form modal (reuses #modal from base.html, expands it)
  open(title, bodyHtml, opts = {}) {
    const overlay = document.getElementById('modal');
    const inner   = overlay.querySelector('.modal');
    inner.className = 'modal' + (opts.size ? ' ' + opts.size : '');
    showModal(title, bodyHtml);
    // Focus first input
    setTimeout(() => {
      const first = modal.querySelector('input:not([type=hidden]),select,textarea');
      if (first) first.focus();
    }, 120);
  },

  close() { closeModal(); },

  // Validate all [required] fields inside #modal, show inline errors
  validate() {
    const modal = document.getElementById('modalBody');
    let valid = true;
    modal.querySelectorAll('[data-required]').forEach(el => {
      const errEl = el.closest('.field')?.querySelector('.field-error');
      const empty = !el.value.trim();
      el.classList.toggle('error', empty);
      if (errEl) errEl.classList.toggle('show', empty);
      if (empty) valid = false;
    });
    return valid;
  },

  // Show inline form message
  msg(type, text) {
    const el = document.getElementById('formMsg');
    if (!el) return;
    el.className = `form-msg ${type} show`;
    el.innerHTML = (type === 'success' ? '✓ ' : '✗ ') + text;
    if (type === 'success') setTimeout(() => el.classList.remove('show'), 3000);
  },

  // Confirm-delete dialog
  confirm(title, targetLabel, onConfirm) {
    FORM.open('Confirm Delete', `
      <div class="confirm-dialog">
        <span class="confirm-icon">🗑</span>
        <div class="confirm-title">${title}</div>
        <div class="confirm-desc">
          This will permanently delete
          <span class="confirm-target">${targetLabel}</span>.
          This action cannot be undone.
        </div>
        <div class="confirm-actions">
          <button class="btn btn-ghost" onclick="FORM.close()">Cancel</button>
          <button class="btn btn-danger" onclick="(${onConfirm.toString()})();FORM.close()">Delete</button>
        </div>
      </div>
    `);
  },
};

// ── Tag input helper ────────────────────────────────────────
function initTagInput(wrapperId, inputId, hiddenId) {
  const wrap   = document.getElementById(wrapperId);
  const input  = document.getElementById(inputId);
  const hidden = document.getElementById(hiddenId);
  if (!wrap || !input) return;

  let tags = [];

  function render() {
    wrap.querySelectorAll('.tag-chip').forEach(c => c.remove());
    tags.forEach((t, i) => {
      const chip = document.createElement('span');
      chip.className = 'tag-chip';
      chip.innerHTML = `${t}<button class="tag-chip-remove" onclick="removeTag(${i},'${wrapperId}','${inputId}','${hiddenId}')">✕</button>`;
      wrap.insertBefore(chip, input);
    });
    if (hidden) hidden.value = tags.join(',');
  }

  input.addEventListener('keydown', e => {
    if ((e.key === 'Enter' || e.key === ',') && input.value.trim()) {
      e.preventDefault();
      const val = input.value.trim().replace(',', '');
      if (val && !tags.includes(val)) { tags.push(val); render(); }
      input.value = '';
    }
    if (e.key === 'Backspace' && !input.value && tags.length) {
      tags.pop(); render();
    }
  });

  wrap.addEventListener('click', () => input.focus());
  wrap._tags = tags;
  wrap._render = render;
}

function removeTag(i, wrapperId, inputId, hiddenId) {
  const wrap = document.getElementById(wrapperId);
  if (!wrap || !wrap._tags) return;
  wrap._tags.splice(i, 1);
  wrap._render();
}

function getTagInputValues(wrapperId) {
  const wrap = document.getElementById(wrapperId);
  return wrap?._tags || [];
}

// ── Autocomplete helper ─────────────────────────────────────
function initAutocomplete(inputId, items, onSelect) {
  const input = document.getElementById(inputId);
  if (!input) return;

  let dd = input.parentElement.querySelector('.ac-dropdown');
  if (!dd) {
    input.parentElement.classList.add('ac-wrap');
    dd = document.createElement('div');
    dd.className = 'ac-dropdown';
    input.parentElement.appendChild(dd);
  }

  input.addEventListener('input', () => {
    const q = input.value.toLowerCase();
    if (!q) { dd.classList.remove('open'); return; }
    const matches = items.filter(it => it.toLowerCase().includes(q)).slice(0, 8);
    if (!matches.length) { dd.classList.remove('open'); return; }
    dd.innerHTML = matches.map(m => {
      const hi = m.replace(new RegExp(q, 'gi'), s => `<mark>${s}</mark>`);
      return `<div class="ac-item" onmousedown="selectAC('${inputId}','${m.replace(/'/g,"\\'")}');">${hi}</div>`;
    }).join('');
    dd.classList.add('open');
  });

  input.addEventListener('blur', () => setTimeout(() => dd.classList.remove('open'), 150));
  window[`_ac_cb_${inputId}`] = onSelect;
}

function selectAC(inputId, val) {
  const input = document.getElementById(inputId);
  if (input) {
    input.value = val;
    const dd = input.parentElement.querySelector('.ac-dropdown');
    if (dd) dd.classList.remove('open');
    const cb = window[`_ac_cb_${inputId}`];
    if (cb) cb(val);
  }
}
