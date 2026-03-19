/* ─────────────────────────────────────────
   api.js  —  Fetch wrapper for /api/*
   All data comes from Flask → SQLite.
   ───────────────────────────────────────── */

// Read CSRF token from session (injected into meta tag)
function _getCsrfToken() {
  return document.querySelector('meta[name="csrf-token"]')?.content || '';
}

const API = {
  async _req(method, path, body) {
    try {
      const headers = { 'Content-Type': 'application/json' };
      // Send CSRF token on all state-changing requests
      if (['POST','PUT','PATCH','DELETE'].includes(method)) {
        headers['X-CSRFToken'] = _getCsrfToken();
      }
      const opts = { method, headers };
      if (body) opts.body = JSON.stringify(body);
      const res = await fetch('/api' + path, opts);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        if (res.status === 403 && data.error?.includes('CSRF')) {
          showToast('Session expired — please refresh the page', 'error');
          return { error: 'csrf' };
        }
        showToast((data.error || `HTTP ${res.status}`), 'error');
        return { error: data.error || `HTTP ${res.status}` };
      }
      return data;
    } catch (err) {
      showToast('Network error: ' + err.message, 'error');
      console.error('[API]', method, path, err);
      return { error: err.message };
    }
  },

  get(path)        { return this._req('GET',    path); },
  post(path, body) { return this._req('POST',   path, body); },
  patch(path, body){ return this._req('PATCH',  path, body); },
  del(path)        { return this._req('DELETE', path); },
};
