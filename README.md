# AD / IAM Auditor — v2.0

A full-stack Active Directory security auditing dashboard.  
Built with **Flask + SQLAlchemy + SQLite** (backend) and **Jinja2 templates + vanilla JS** (frontend).

---

## Project Structure

```
adaudit/
├── run.py                         ← Entry point: python run.py
├── requirements.txt
├── .env.example                   ← Copy to .env and edit
│
├── app/
│   ├── __init__.py                ← Flask app factory
│   │
│   ├── models/
│   │   └── database.py            ← All SQLAlchemy models + DB seeder
│   │       Models: User, Group, GroupMember,
│   │               Privilege, AuditLog, ThreatIndicator, Policy
│   │
│   ├── routes/
│   │   ├── main.py                ← HTML page routes (Flask renders templates)
│   │   └── api.py                 ← JSON REST API (reads/writes SQLite)
│   │
│   ├── templates/
│   │   ├── base.html              ← Shared layout: sidebar, topbar, modal, toast
│   │   └── pages/
│   │       ├── dashboard.html     ← KPIs, charts, findings, recent events
│   │       ├── users.html         ← User table, search, filter, disable
│   │       ├── groups.html        ← Group list with privilege flags
│   │       ├── privileges.html    ← Escalation risks, revoke button
│   │       ├── threats.html       ← Threat indicators, resolve action
│   │       ├── policies.html      ← Compliance table + radar chart
│   │       ├── audit.html         ← Full audit log, paginated
│   │       ├── reports.html       ← Generate + download CSV / PDF
│   │       └── settings.html      ← DB info, AD connection, rules
│   │
│   └── static/
│       ├── css/
│       │   ├── base.css           ← CSS variables, reset
│       │   ├── layout.css         ← Sidebar, topbar, grids
│       │   └── components.css     ← Buttons, panels, tables, badges…
│       └── js/
│           ├── utils.js           ← Clock, toast, modal, pager, badges
│           ├── api.js             ← fetch() wrapper for /api/*
│           └── charts.js          ← All Chart.js definitions
│
├── instance/
│   └── adaudit.db                 ← SQLite DB (auto-created on first run)
│
└── scripts/
    ├── setup.sh                   ← First-time setup (Mac/Linux)
    ├── start.sh                   ← Start app (Mac/Linux)
    └── start.bat                  ← Start app (Windows)
```

---

## Quick Start

### Option A — Scripts (easiest)

**Mac / Linux:**
```bash
bash scripts/setup.sh   # first time only
bash scripts/start.sh   # opens browser automatically
```

**Windows:**
```
Double-click scripts/start.bat
```

### Option B — Manual

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start the server
python run.py

# 3. Open in browser
http://localhost:5000
```

The SQLite database is **created and seeded automatically** on first run.  
No configuration needed to get started.

---

## API Endpoints

| Method | Endpoint                | Description                     |
|--------|-------------------------|---------------------------------|
| GET    | `/api/summary`          | Dashboard stats + findings      |
| GET    | `/api/users`            | All users (filterable)          |
| GET    | `/api/users/<username>` | Single user detail              |
| PATCH  | `/api/users/<id>`       | Update user (status/risk/mfa)   |
| GET    | `/api/groups`           | All groups (filterable)         |
| GET    | `/api/privileges`       | All privilege assignments       |
| DELETE | `/api/privileges/<id>`  | Revoke a privilege              |
| GET    | `/api/audit`            | Audit log (paginated)           |
| GET    | `/api/threats`          | Threat indicators               |
| PATCH  | `/api/threats/<id>`     | Update threat status            |
| GET    | `/api/policies`         | Security policy compliance      |
| GET    | `/api/report/<type>`    | Generate report data            |
| GET    | `/api/search?q=`        | Cross-entity search             |

**Report types:** `stale` · `privileged` · `threats` · `compliance` · `mfa` · `full`

---

## Connecting to Real Active Directory

1. Install LDAP support (already in requirements.txt):
   ```bash
   pip install ldap3
   ```

2. Edit `.env`:
   ```
   AD_SERVER=ldap://dc.corp.local
   AD_USER=CORP\svc_audit
   AD_PASSWORD=yourpassword
   AD_BASE_DN=DC=corp,DC=local
   ```

3. In `app/routes/api.py`, replace the SQLAlchemy query in `get_users()`  
   with an LDAP query using `ldap3`. The model structure matches AD attributes directly.

---

## Database

- **Engine:** SQLite via SQLAlchemy
- **Location:** `instance/adaudit.db`
- **Tables:** `users`, `groups`, `group_members`, `privileges`, `audit_logs`, `threats`, `policies`
- **Seeded:** 15 users · 9 groups · 7 privileges · 15 audit events · 5 threats · 8 policies

To reset the database, delete `instance/adaudit.db` and restart — it will re-seed automatically.
