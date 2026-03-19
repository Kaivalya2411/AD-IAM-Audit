"""
app/routes/main.py
Serves HTML pages using Flask/Jinja2 templates.
"""
from flask import Blueprint, render_template
from app.routes.auth import login_required

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
@main_bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('pages/dashboard.html', active='dashboard')

@main_bp.route('/users')
@login_required
def users():
    return render_template('pages/users.html', active='users')

@main_bp.route('/groups')
@login_required
def groups():
    return render_template('pages/groups.html', active='groups')

@main_bp.route('/privileges')
@login_required
def privileges():
    return render_template('pages/privileges.html', active='privileges')

@main_bp.route('/threats')
@login_required
def threats():
    return render_template('pages/threats.html', active='threats')

@main_bp.route('/policies')
@login_required
def policies():
    return render_template('pages/policies.html', active='policies')

@main_bp.route('/audit')
@login_required
def audit():
    return render_template('pages/audit.html', active='audit')

@main_bp.route('/reports')
@login_required
def reports():
    return render_template('pages/reports.html', active='reports')

@main_bp.route('/settings')
@login_required
def settings():
    return render_template('pages/settings.html', active='settings')

# ── New audit feature pages ────────────────────────────────
@main_bp.route('/passwords')
@login_required
def passwords():
    return render_template('pages/passwords.html', active='passwords')

@main_bp.route('/sessions')
@login_required
def sessions():
    return render_template('pages/sessions.html', active='sessions')

@main_bp.route('/access-review')
@login_required
def access_review():
    return render_template('pages/access_review.html', active='access_review')

@main_bp.route('/anomalies')
@login_required
def anomalies():
    return render_template('pages/anomalies.html', active='anomalies')

@main_bp.route('/assets')
@login_required
def assets():
    return render_template('pages/assets.html', active='assets')

@main_bp.route('/soc-alerts')
@login_required
def soc_alerts():
    return render_template('pages/soc_alerts.html', active='soc_alerts')

@main_bp.route('/compliance')
@login_required
def compliance():
    return render_template('pages/compliance.html', active='compliance')

@main_bp.route('/timeline')
@login_required
def timeline():
    return render_template('pages/timeline.html', active='timeline')

@main_bp.route('/toolkit')
@login_required
def toolkit():
    return render_template('pages/toolkit.html', active='toolkit')

@main_bp.route('/search')
@login_required
def search_results():
    return render_template('pages/search.html', active='')
