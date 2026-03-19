"""
app/__init__.py — Flask application factory
Uses only Flask + Python's built-in sqlite3 (no extra packages needed)
"""
from flask import Flask
import os, secrets

def _load_env(path='.env'):
    """Simple .env loader — no dependencies needed."""
    env = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, _, v = line.partition('=')
                    env[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    return env

def create_app():
    # Load .env before anything else
    env = _load_env()

    app = Flask(__name__, instance_relative_config=True)

    # SECRET_KEY: env var > .env file > generated (dev only, logs warning)
    secret = (os.environ.get('SECRET_KEY')
              or env.get('SECRET_KEY')
              or '')
    if not secret or secret == 'change-me-to-a-long-random-string-in-production':
        secret = secrets.token_hex(32)
        print("  ⚠  WARNING: SECRET_KEY not set — using a random key (sessions will reset on restart)")
        print("     Set SECRET_KEY in your .env file for persistent sessions.")

    app.config['SECRET_KEY']      = secret
    app.config['DATABASE']        = (os.environ.get('DATABASE_PATH')
                                     or env.get('DATABASE_PATH')
                                     or os.path.join(os.getcwd(), 'instance', 'adaudit.db'))
    app.config['MAX_LOGIN_ATTEMPTS'] = int(os.environ.get('MAX_LOGIN_ATTEMPTS') or env.get('MAX_LOGIN_ATTEMPTS') or 5)
    app.config['LOCKOUT_MINUTES']    = int(os.environ.get('LOCKOUT_MINUTES')    or env.get('LOCKOUT_MINUTES')    or 15)
    app.config['SESSION_COOKIE_HTTPONLY']  = True
    app.config['SESSION_COOKIE_SAMESITE']  = 'Lax'

    os.makedirs('instance', exist_ok=True)

    from app.routes.main import main_bp
    from app.routes.api  import api_bp
    from app.routes.auth import auth_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(auth_bp)

    # Inject current_user + CSRF token into all templates
    from app.routes.auth import get_current_user
    import secrets as _secrets

    @app.before_request
    def set_csrf_token():
        """Generate a CSRF token per session if not already set."""
        from flask import session as _session
        if 'csrf_token' not in _session:
            _session['csrf_token'] = _secrets.token_hex(32)

    @app.context_processor
    def inject_globals():
        from flask import session as _session
        return {
            'current_user': get_current_user(),
            'csrf_token':   _session.get('csrf_token', ''),
        }

    @app.after_request
    def set_security_headers(response):
        """Add security headers to every response."""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options']         = 'SAMEORIGIN'
        response.headers['X-XSS-Protection']        = '1; mode=block'
        response.headers['Referrer-Policy']          = 'strict-origin-when-cross-origin'
        return response

    return app
