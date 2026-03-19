/* ─────────────────────────────────────────────────────────
   rbac.js  —  Role-Based Access Control (Frontend)
   Reads role from <meta name="user-role"> and:
   1. Hides/disables UI elements that the role can't use
   2. Shows a role indicator badge in the sidebar footer
   3. Intercepts API calls that would be rejected
   4. Shows a permission-denied toast instead of silent fail

   Roles:  viewer < analyst < admin
   ───────────────────────────────────────────────────────── */

const RBAC = (() => {

  // ── Read role from meta tag ─────────────────────────────
  const meta = document.querySelector('meta[name="user-role"]');
  const ROLE = (meta?.content || 'viewer').toLowerCase();

  // ── Permission matrix ───────────────────────────────────
  const CAN = {
    admin:   new Set(['read','create','update','delete','manage','resolve','assign','approve','terminate','reset','configure']),
    analyst: new Set(['read','resolve','assign','approve','terminate','reset','update_status']),
    viewer:  new Set(['read']),
  };

  // ── Check permission ────────────────────────────────────
  function can(action) {
    return CAN[ROLE]?.has(action) ?? false;
  }

  // ── Check minimum role ──────────────────────────────────
  function isAtLeast(minRole) {
    const levels = { viewer: 0, analyst: 1, admin: 2 };
    return (levels[ROLE] ?? 0) >= (levels[minRole] ?? 99);
  }

  // ── Apply restrictions to the page ─────────────────────
  function apply() {
    if (ROLE === 'admin') return; // admin sees everything

    // Elements hidden for viewers only
    const viewerHide = [
      // All Add/Create buttons
      'button[onclick*="openCreate"]',
      'button[onclick*="Create"]',
      '.page-actions .btn-primary',
      // All Edit buttons
      'button[onclick*="openEdit"]',
      '.action-btn:not(.danger)',
      // Delete buttons (analysts also cannot delete)
      'button[onclick*="confirmDelete"]',
      'button[onclick*="Delete"]:not(.btn-ghost)',
      '.action-btn.danger',
      // Specific action buttons
      'button[onclick*="bulkReset"]',
      'button[onclick*="terminateAll"]',
      'button[onclick*="openCreateAnomaly"]',
      'button[onclick*="openCreateGroup"]',
      'button[onclick*="openCreateUser"]',
      'button[onclick*="openCreatePriv"]',
      'button[onclick*="openCreateAlert"]',
      'button[onclick*="openCreateAsset"]',
      'button[onclick*="openCreateControl"]',
      'button[onclick*="openCreateReview"]',
      'button[onclick*="openCreateThreat"]',
      'button[onclick*="openCreatePolicy"]',
    ];

    // Elements analysts CAN see (don't hide these for analyst)
    const analystCanUse = [
      'button[onclick*="resolveThreat"]',
      'button[onclick*="patchAnomaly"]',
      'button[onclick*="terminateSession"]',
      'button[onclick*="resetPassword"]',
      'button[onclick*="decideReview"]',
      'button[onclick*="quickUpdate"]',
      'button[onclick*="toggleStatus"]',
      'button[onclick*="submitCreateEntry"]',  // manual audit
    ];

    if (ROLE === 'viewer') {
      // Hide everything mutating
      disableSelectors(viewerHide);
    } else if (ROLE === 'analyst') {
      // Hide create/delete, keep resolve/assign/approve
      const analystHide = viewerHide.filter(sel =>
        !analystCanUse.some(keep => sel.includes(keep.replace('button[onclick*="','').replace('"]','')))
      );
      disableSelectors(analystHide);
    }

    // Show role banner
    showRoleBanner();
  }

  // ── Disable/hide elements ───────────────────────────────
  function disableSelectors(selectors) {
    selectors.forEach(sel => {
      try {
        document.querySelectorAll(sel).forEach(el => {
          el.style.display = 'none';
        });
      } catch(e) {}
    });
  }

  // ── Re-apply after dynamic content loads ─────────────────
  // Since tables are rendered via JS, we observe DOM changes
  let _applyTimer = null;
  function scheduleApply() {
    clearTimeout(_applyTimer);
    _applyTimer = setTimeout(apply, 150);
  }

  // ── Role banner in sidebar footer ──────────────────────
  function showRoleBanner() {
    const footer = document.querySelector('.sidebar-footer');
    if (!footer || document.getElementById('roleBanner')) return;

    const colors = { admin: 'var(--red)', analyst: 'var(--cyan)', viewer: 'var(--amber)' };
    const icons  = { admin: '⬡', analyst: '◈', viewer: '◎' };
    const color  = colors[ROLE] || 'var(--text2)';

    const banner = document.createElement('div');
    banner.id = 'roleBanner';
    banner.style.cssText = `
      padding: 0.35rem 0.9rem;
      font-size: 0.62rem;
      font-family: var(--mono);
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: ${color};
      background: ${color.replace('var(--', 'rgba(').replace(')', ',0.08)')};
      border-top: 1px solid ${color.replace('var(--', 'rgba(').replace(')', ',0.2)')};
      display: flex;
      align-items: center;
      gap: 0.4rem;
    `;
    banner.innerHTML = `<span>${icons[ROLE]||'○'}</span><span>${ROLE.toUpperCase()}</span>`;
    footer.insertAdjacentElement('afterend', banner);
  }

  // ── Intercept forbidden API calls ──────────────────────
  // Wrap API._req to catch 403 responses
  function patchAPI() {
    if (typeof API === 'undefined') return;
    const orig = API._req.bind(API);
    API._req = async function(method, path, body) {
      const result = await orig(method, path, body);
      if (result && result.error && result.forbidden) {
        showToast('⛔ Permission denied — your role cannot perform this action', 'error');
        return null;
      }
      return result;
    };
  }

  // ── Permission denied toast (for disabled buttons that slip through) ──
  function showPermDenied() {
    showToast(`⛔ ${ROLE.charAt(0).toUpperCase()+ROLE.slice(1)}s cannot perform this action`, 'error');
  }

  // ── Public API ──────────────────────────────────────────
  return { ROLE, can, isAtLeast, apply, scheduleApply, showPermDenied, patchAPI };

})();

// ── Init on DOM ready ────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  RBAC.patchAPI();

  // Apply once immediately
  RBAC.apply();

  // Re-apply whenever DOM changes (catches dynamically rendered table rows/buttons)
  const observer = new MutationObserver((mutations) => {
    const hasNewNodes = mutations.some(m => m.addedNodes.length > 0);
    if (hasNewNodes) RBAC.scheduleApply();
  });

  observer.observe(document.body, { childList: true, subtree: true });
});
