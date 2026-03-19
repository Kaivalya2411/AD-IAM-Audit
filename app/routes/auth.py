"""
app/routes/auth.py
Login, logout, session management, account management API.
Uses Flask sessions (server-side cookie, signed with SECRET_KEY).
"""
from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify, current_app
from app.models.database import get_db, rows_to_list, hash_password, verify_password
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
import threading

# ── In-memory brute force tracker ────────────────────────
# Stores: { ip_or_user -> [attempt_timestamps] }
_login_attempts  = defaultdict(list)
_lockout_until   = {}
_attempts_lock   = threading.Lock()

def _check_lockout(key):
    """Returns (is_locked, seconds_remaining). Cleans expired data."""
    now = datetime.utcnow()
    with _attempts_lock:
        # Check hard lockout
        if key in _lockout_until:
            remaining = (_lockout_until[key] - now).total_seconds()
            if remaining > 0:
                return True, int(remaining)
            else:
                del _lockout_until[key]
                _login_attempts.pop(key, None)
        return False, 0

def _record_failure(key, max_attempts=5, lockout_mins=15):
    """Record a failed attempt. Returns True if now locked out."""
    now    = datetime.utcnow()
    window = timedelta(minutes=10)

    with _attempts_lock:
        _login_attempts[key] = [t for t in _login_attempts[key] if now - t < window]
        _login_attempts[key].append(now)

        if len(_login_attempts[key]) >= max_attempts:
            _lockout_until[key] = now + timedelta(minutes=lockout_mins)
            _login_attempts.pop(key, None)
            return True
    return False

def _clear_attempts(key):
    """Clear attempts on successful login."""
    with _attempts_lock:
        _login_attempts.pop(key, None)
        _lockout_until.pop(key, None)

auth_bp = Blueprint('auth', __name__)

def _validate_csrf():
    """Check CSRF token on state-changing requests."""
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        # API calls use X-CSRFToken header (set by api.js)
        token = (request.headers.get('X-CSRFToken')
                 or request.form.get('csrf_token', ''))
        expected = session.get('csrf_token', '')
        if not token or not expected or token != expected:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'CSRF token invalid'}), 403
            # For HTML forms, reject
            return 'CSRF validation failed', 403
    return None


# ── Auth guard decorator ──────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            # API requests get JSON error
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized', 'login': True}), 401
            return redirect(url_for('auth.login', next=request.path))
        return f(*args, **kwargs)
    return decorated


# ── Role permission helpers ──────────────────────────────
ROLE_PERMS = {
    # (method, endpoint_pattern) : minimum role required
    # viewer  < analyst < admin
}

def role_required(*roles):
    """Decorator: requires one of the given roles."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'user_id' not in session:
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Unauthorized'}), 401
                return redirect(url_for('auth.login'))
            user_role = session.get('user_role', 'viewer')
            if user_role not in roles:
                if request.path.startswith('/api/'):
                    return jsonify({'error': f'Permission denied. Required: {" or ".join(roles)}', 'forbidden': True}), 403
                return redirect(url_for('main.dashboard'))
            return f(*args, **kwargs)
        return decorated
    return decorator

def analyst_required(f):
    return role_required('analyst', 'admin')(f)

def admin_required(f):
    return role_required('admin')(f)

def can(role, action):
    """Check if a role can perform an action."""
    perms = {
        'admin':   {'create','read','update','delete','manage','resolve','assign','approve'},
        'analyst': {'read','resolve','assign','approve','update_status','force_reset','terminate'},
        'viewer':  {'read'},
    }
    return action in perms.get(role, set())


def get_current_user():
    """Return current logged-in user dict or None."""
    uid = session.get('user_id')
    if not uid:
        return None
    db = get_db()
    row = db.execute("SELECT * FROM auth_accounts WHERE id=? AND active=1", (uid,)).fetchone()
    db.close()
    return dict(row) if row else None


# ── Login page ────────────────────────────────────────────
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Already logged in
    if 'user_id' in session:
        return redirect(url_for('main.dashboard'))

    error = None

    if request.method == 'POST':
        # CSRF check for login form
        form_token = request.form.get('csrf_token', '')
        sess_token = session.get('csrf_token', '')
        if not form_token or form_token != sess_token:
            error = 'Session expired. Please refresh and try again.'
            return render_template('auth/login.html', error=error)

        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'
        ip       = request.remote_addr or '0.0.0.0'

        if not username or not password:
            error = 'Please enter both username and password.'
        else:
            # ── Rate limit check ──────────────────────────
            ip_key   = f'ip:{ip}'
            user_key = f'user:{username}'
            locked_ip,   secs_ip   = _check_lockout(ip_key)
            locked_user, secs_user = _check_lockout(user_key)

            if locked_ip or locked_user:
                secs  = max(secs_ip, secs_user)
                mins  = max(1, secs // 60)
                error = f'Too many failed attempts. Please try again in {mins} minute{"s" if mins!=1 else ""}.'
            else:
                db  = get_db()
                row = db.execute(
                    "SELECT * FROM auth_accounts WHERE LOWER(username)=? AND active=1",
                    (username,)
                ).fetchone()

                if row and verify_password(password, row['password_hash'], row['salt']):
                    # ── Success ──────────────────────────
                    _clear_attempts(ip_key)
                    _clear_attempts(user_key)
                    session.permanent = remember
                    session['user_id']    = row['id']
                    session['username']   = row['username']
                    session['user_name']  = row['name']
                    session['user_role']  = row['role']
                    session['user_email'] = row['email'] or ''

                    db.execute(
                        "UPDATE auth_accounts SET last_login=? WHERE id=?",
                        (datetime.utcnow().strftime('%Y-%m-%d %H:%M'), row['id'])
                    )
                    count = db.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
                    db.execute(
                        "INSERT INTO audit_logs (event_id,type,username,target,source_ip,result,timestamp)"
                        " VALUES (?,?,?,?,?,?,?)",
                        (f'EVT-{count+1:04d}', 'login', row['username'], 'auth:login',
                         ip, 'success', datetime.utcnow().strftime('%Y-%m-%d %H:%M'))
                    )
                    db.commit()
                    db.close()
                    next_url = request.args.get('next') or url_for('main.dashboard')
                    return redirect(next_url)

                else:
                    # ── Failure — record & check lockout ──
                    count = db.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
                    db.execute(
                        "INSERT INTO audit_logs (event_id,type,username,target,source_ip,result,timestamp)"
                        " VALUES (?,?,?,?,?,?,?)",
                        (f'EVT-{count+1:04d}', 'login', username, 'auth:login',
                         ip, 'failed', datetime.utcnow().strftime('%Y-%m-%d %H:%M'))
                    )
                    db.commit()
                    db.close()

                    max_att   = current_app.config.get('MAX_LOGIN_ATTEMPTS', 5)
                    lock_mins = current_app.config.get('LOCKOUT_MINUTES', 15)
                    ip_locked   = _record_failure(ip_key,   max_att, lock_mins)
                    user_locked = _record_failure(user_key, max_att, lock_mins)

                    if ip_locked or user_locked:
                        error = f'Account locked for {lock_mins} minutes after too many failed attempts.'
                    else:
                        with _attempts_lock:
                            attempts_so_far = len(_login_attempts.get(user_key, []))
                        remaining = max(0, max_att - attempts_so_far)
                        if remaining > 0:
                            error = f'Invalid username or password. {remaining} attempt{"s" if remaining!=1 else ""} remaining before lockout.'
                        else:
                            error = 'Invalid username or password.'

    return render_template('auth/login.html', error=error)


# ── Logout ────────────────────────────────────────────────
@auth_bp.route('/logout')
def logout():
    username = session.get('username', 'unknown')
    session.clear()

    # Log logout
    try:
        db = get_db()
        count = db.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
        db.execute(
            "INSERT INTO audit_logs (event_id,type,username,target,source_ip,result,timestamp)"
            " VALUES (?,?,?,?,?,?,?)",
            (f'EVT-{count+1:04d}', 'login', username, 'auth:logout',
             request.remote_addr, 'success', datetime.utcnow().strftime('%Y-%m-%d %H:%M'))
        )
        db.commit()
        db.close()
    except Exception:
        pass

    return redirect(url_for('auth.login'))


# ── Profile page ──────────────────────────────────────────
@auth_bp.route('/profile')
@login_required
def profile():
    user = get_current_user()
    return render_template('auth/profile.html', active='profile', current_user=user)


# ── API: get current user info ────────────────────────────
@auth_bp.route('/api/me')
@login_required
def api_me():
    return jsonify({
        'id':       session.get('user_id'),
        'username': session.get('username'),
        'name':     session.get('user_name'),
        'role':     session.get('user_role'),
        'email':    session.get('user_email'),
    })


# ── API: change password ──────────────────────────────────
@auth_bp.route('/api/auth/change-password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json() or {}
    current  = data.get('current_password', '')
    new_pw   = data.get('new_password', '')
    confirm  = data.get('confirm_password', '')

    if not current or not new_pw:
        return jsonify({'error': 'All fields required'}), 400
    if new_pw != confirm:
        return jsonify({'error': 'New passwords do not match'}), 400
    if len(new_pw) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    db  = get_db()
    uid = session['user_id']
    row = db.execute("SELECT * FROM auth_accounts WHERE id=?", (uid,)).fetchone()

    if not row or not verify_password(current, row['password_hash'], row['salt']):
        db.close()
        return jsonify({'error': 'Current password is incorrect'}), 400

    new_hash, new_salt = hash_password(new_pw)
    db.execute(
        "UPDATE auth_accounts SET password_hash=?, salt=? WHERE id=?",
        (new_hash, new_salt, uid)
    )
    count = db.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
    db.execute(
        "INSERT INTO audit_logs (event_id,type,username,target,source_ip,result,timestamp)"
        " VALUES (?,?,?,?,?,?,?)",
        (f'EVT-{count+1:04d}', 'modify', session['username'], 'auth:password_change',
         request.remote_addr, 'success', datetime.utcnow().strftime('%Y-%m-%d %H:%M'))
    )
    db.commit()
    db.close()
    return jsonify({'message': 'Password changed successfully'})


# ── API: update profile ───────────────────────────────────
@auth_bp.route('/api/auth/profile', methods=['PATCH'])
@login_required
def update_profile():
    data = request.get_json() or {}
    allowed = {k: v for k, v in data.items() if k in ('name', 'email')}
    if not allowed:
        return jsonify({'error': 'No valid fields'}), 400

    db  = get_db()
    uid = session['user_id']
    for field, value in allowed.items():
        db.execute(f"UPDATE auth_accounts SET {field}=? WHERE id=?", (value, uid))
    db.commit()

    # Update session
    if 'name'  in allowed: session['user_name']  = allowed['name']
    if 'email' in allowed: session['user_email'] = allowed['email']

    db.close()
    return jsonify({'message': 'Profile updated'})


# ── Admin: list all accounts ──────────────────────────────
@auth_bp.route('/api/auth/accounts', methods=['GET'])
@login_required
def list_accounts():
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    db   = get_db()
    rows = rows_to_list(db.execute(
        "SELECT id,username,name,role,email,last_login,created_at,active FROM auth_accounts"
    ).fetchall())
    db.close()
    return jsonify(rows)


# ── Admin: create account ─────────────────────────────────
@auth_bp.route('/api/auth/accounts', methods=['POST'])
@login_required
def create_account():
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    data = request.get_json() or {}
    for f in ('username', 'password', 'name'):
        if not data.get(f):
            return jsonify({'error': f'{f} is required'}), 400

    db = get_db()
    if db.execute("SELECT id FROM auth_accounts WHERE username=?", (data['username'],)).fetchone():
        db.close()
        return jsonify({'error': 'Username already exists'}), 409

    pw_hash, salt = hash_password(data['password'])
    db.execute(
        "INSERT INTO auth_accounts (username,password_hash,salt,name,role,email,created_at,active)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (data['username'], pw_hash, salt, data['name'],
         data.get('role', 'analyst'), data.get('email', ''),
         datetime.utcnow().strftime('%Y-%m-%d %H:%M'), 1)
    )
    db.commit()
    db.close()
    return jsonify({'message': f'Account {data["username"]} created'}), 201


# ── Admin: toggle account active/inactive ─────────────────
@auth_bp.route('/api/auth/accounts/<int:aid>/toggle', methods=['PATCH'])
@login_required
def toggle_account(aid):
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    if aid == session.get('user_id'):
        return jsonify({'error': 'Cannot deactivate your own account'}), 400
    db  = get_db()
    row = db.execute("SELECT * FROM auth_accounts WHERE id=?", (aid,)).fetchone()
    if not row:
        db.close()
        return jsonify({'error': 'Not found'}), 404
    new_active = 0 if row['active'] else 1
    db.execute("UPDATE auth_accounts SET active=? WHERE id=?", (new_active, aid))
    db.commit()
    db.close()
    return jsonify({'message': 'Account ' + ('activated' if new_active else 'deactivated')})


# ── Admin: reset another user's password ─────────────────
@auth_bp.route('/api/auth/accounts/<int:aid>/reset-password', methods=['POST'])
@login_required
def admin_reset_password(aid):
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    data = request.get_json() or {}
    new_pw = data.get('password', '')
    if len(new_pw) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    db = get_db()
    if not db.execute("SELECT id FROM auth_accounts WHERE id=?", (aid,)).fetchone():
        db.close()
        return jsonify({'error': 'Not found'}), 404
    pw_hash, salt = hash_password(new_pw)
    db.execute("UPDATE auth_accounts SET password_hash=?, salt=? WHERE id=?", (pw_hash, salt, aid))
    db.commit()
    db.close()
    return jsonify({'message': 'Password reset'})
