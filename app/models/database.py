"""
app/models/database.py
Database layer using Python's built-in sqlite3. No ORM needed.
"""
import sqlite3, os, hashlib, secrets

DB_PATH = os.path.join(os.getcwd(), 'instance', 'adaudit.db')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def rows_to_list(rows):
    return [dict(r) for r in rows]

def init_db():
    os.makedirs('instance', exist_ok=True)
    conn = get_db()
    _create_tables(conn)
    cur = conn.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        _seed(conn)
        print("  ✓ Database seeded with sample AD data")
    _seed_auth(conn)
    conn.close()

def _create_tables(conn):
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL, dept TEXT, email TEXT, last_login TEXT,
        status TEXT DEFAULT 'active', risk TEXT DEFAULT 'low', mfa INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL,
        type TEXT DEFAULT 'Security', privileged INTEGER DEFAULT 0,
        nested INTEGER DEFAULT 0, description TEXT, modified TEXT);
    CREATE TABLE IF NOT EXISTS group_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL,
        group_name TEXT NOT NULL, UNIQUE(username, group_name));
    CREATE TABLE IF NOT EXISTS privileges (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL,
        group_name TEXT, permission TEXT, granted TEXT, risk TEXT DEFAULT 'medium');
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL,
        type TEXT, username TEXT, target TEXT, source_ip TEXT, result TEXT, timestamp TEXT);
    CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT, indicator TEXT, type TEXT,
        severity TEXT, first_seen TEXT, count INTEGER DEFAULT 1, status TEXT DEFAULT 'active');
    CREATE TABLE IF NOT EXISTS policies (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, category TEXT,
        scope TEXT, pass_count INTEGER DEFAULT 0, fail_count INTEGER DEFAULT 0, pct INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS auth_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        name TEXT NOT NULL,
        role TEXT DEFAULT 'analyst',
        email TEXT,
        avatar TEXT,
        last_login TEXT,
        created_at TEXT,
        active INTEGER DEFAULT 1);
    """)

    # Performance indexes on frequently filtered columns
    conn.executescript("""
    CREATE INDEX IF NOT EXISTS idx_users_status      ON users(status);
    CREATE INDEX IF NOT EXISTS idx_users_risk        ON users(risk);
    CREATE INDEX IF NOT EXISTS idx_users_dept        ON users(dept);
    CREATE INDEX IF NOT EXISTS idx_audit_timestamp   ON audit_logs(timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_type        ON audit_logs(type);
    CREATE INDEX IF NOT EXISTS idx_audit_result      ON audit_logs(result);
    CREATE INDEX IF NOT EXISTS idx_audit_username    ON audit_logs(username);
    CREATE INDEX IF NOT EXISTS idx_threats_status    ON threats(status);
    CREATE INDEX IF NOT EXISTS idx_anomalies_status  ON anomalies(status);
    CREATE INDEX IF NOT EXISTS idx_anomalies_sev     ON anomalies(severity);
    CREATE INDEX IF NOT EXISTS idx_soc_status        ON soc_alerts(status);
    CREATE INDEX IF NOT EXISTS idx_soc_severity      ON soc_alerts(severity);
    CREATE INDEX IF NOT EXISTS idx_compliance_fw     ON compliance_checks(framework);
    CREATE INDEX IF NOT EXISTS idx_compliance_status ON compliance_checks(status);
    CREATE INDEX IF NOT EXISTS idx_assets_status     ON assets(status);
    CREATE INDEX IF NOT EXISTS idx_assets_risk       ON assets(risk);
    CREATE INDEX IF NOT EXISTS idx_assets_type       ON assets(type);
    CREATE INDEX IF NOT EXISTS idx_pw_status         ON password_expiry(status);
    CREATE INDEX IF NOT EXISTS idx_sessions_status   ON sessions(status);
    CREATE INDEX IF NOT EXISTS idx_reviews_decision  ON access_reviews(decision);
    CREATE INDEX IF NOT EXISTS idx_timeline_cat      ON timeline(category);
    CREATE INDEX IF NOT EXISTS idx_timeline_sev      ON timeline(severity);
    """)
    conn.commit()

def hash_password(password, salt=None):
    """Hash a password with a random salt using SHA-256."""
    if salt is None:
        salt = secrets.token_hex(16)
    pw_hash = hashlib.sha256((salt + password).encode()).hexdigest()
    return pw_hash, salt

def verify_password(password, stored_hash, salt):
    """Verify a password against stored hash."""
    computed, _ = hash_password(password, salt)
    return computed == stored_hash

def _seed_auth(conn):
    """Create default admin account: admin / admin123"""
    existing = conn.execute("SELECT COUNT(*) FROM auth_accounts").fetchone()[0]
    if existing == 0:
        from datetime import datetime
        pw_hash, salt = hash_password("admin123")
        conn.execute(
            "INSERT INTO auth_accounts (username, password_hash, salt, name, role, email, created_at, active)"
            " VALUES (?,?,?,?,?,?,?,?)",
            ("admin", pw_hash, salt, "Administrator", "admin", "admin@corp.local",
             datetime.utcnow().strftime("%Y-%m-%d %H:%M"), 1)
        )
        # Add a few more demo accounts
        accounts = [
            ("analyst1", "analyst123", "Security Analyst", "analyst", "analyst1@corp.local"),
            ("viewer1",  "viewer123",  "Read-Only Viewer", "viewer",  "viewer1@corp.local"),
        ]
        for uname, pw, name, role, email in accounts:
            ph, s = hash_password(pw)
            conn.execute(
                "INSERT OR IGNORE INTO auth_accounts (username,password_hash,salt,name,role,email,created_at,active)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (uname, ph, s, name, role, email, datetime.utcnow().strftime("%Y-%m-%d %H:%M"), 1)
            )
        conn.commit()
        print("  ✓ Auth accounts seeded  (admin/admin123, analyst1/analyst123, viewer1/viewer123)")

def _seed(conn):
    conn.executemany("INSERT INTO users (username,name,dept,email,last_login,status,risk,mfa) VALUES (?,?,?,?,?,?,?,?)", [
        ('jsmith','John Smith','IT','jsmith@corp.local','2024-08-01','stale','high',0),
        ('alee','Alice Lee','Finance','alee@corp.local','2025-01-10','active','low',1),
        ('rjones','Rob Jones','HR','rjones@corp.local','2023-12-01','stale','high',0),
        ('mwilson','Mary Wilson','Admin','mwilson@corp.local','2025-02-20','active','low',1),
        ('dadmin','Domain Admin','IT','dadmin@corp.local','2025-03-10','active','critical',1),
        ('bjohnson','Bob Johnson','Sales','bjohnson@corp.local','2025-02-28','active','low',1),
        ('stest','svcTest','System','stest@corp.local','2024-01-01','disabled','medium',0),
        ('kbrown','Kate Brown','Legal','kbrown@corp.local','2025-01-25','active','low',1),
        ('gdavis','Gary Davis','IT','gdavis@corp.local','2024-06-15','stale','high',0),
        ('htaylor','Helen Taylor','Exec','htaylor@corp.local','2025-03-01','active','medium',1),
        ('pchang','Peter Chang','IT','pchang@corp.local','2025-03-08','active','low',1),
        ('svc-backup','SVC Backup Acct','System','','2025-02-01','active','high',0),
        ('nwebb','Nina Webb','Sales','nwebb@corp.local','2025-02-15','active','low',1),
        ('cford','Chris Ford','Finance','cford@corp.local','2024-11-20','stale','medium',0),
        ('lmartin','Lisa Martin','HR','lmartin@corp.local','2025-01-05','active','low',1),
    ])
    conn.executemany("INSERT INTO groups (name,type,privileged,nested,description,modified) VALUES (?,?,?,?,?,?)", [
        ('Domain Admins','Security',1,1,'Full domain control','2025-01-15'),
        ('IT Support','Security',0,0,'Helpdesk and IT staff','2025-02-01'),
        ('Finance Users','Security',0,0,'Finance dept access','2024-12-10'),
        ('Schema Admins','Security',1,0,'Schema modification rights','2024-11-05'),
        ('Backup Operators','Security',1,1,'Backup/restore privileges','2024-09-20'),
        ('HR Department','Distribution',0,0,'HR distribution list','2025-02-14'),
        ('Executive Team','Security',1,0,'C-suite and VP access','2025-01-08'),
        ('Sales Team','Distribution',0,0,'Sales distribution','2025-02-20'),
        ('Legal Dept','Security',0,0,'Legal dept file access','2024-10-01'),
    ])
    conn.executemany("INSERT OR IGNORE INTO group_members (username,group_name) VALUES (?,?)", [
        ('jsmith','IT Support'),('jsmith','Backup Operators'),('alee','Finance Users'),
        ('rjones','HR Department'),('mwilson','IT Support'),('dadmin','Domain Admins'),
        ('dadmin','Schema Admins'),('bjohnson','Sales Team'),('stest','IT Support'),
        ('kbrown','Legal Dept'),('gdavis','Backup Operators'),('gdavis','IT Support'),
        ('htaylor','Executive Team'),('pchang','IT Support'),('svc-backup','Backup Operators'),
        ('nwebb','Sales Team'),('cford','Finance Users'),('lmartin','HR Department'),
    ])
    conn.executemany("INSERT INTO privileges (username,group_name,permission,granted,risk) VALUES (?,?,?,?,?)", [
        ('dadmin','Domain Admins','Full Control','2020-01-01','critical'),
        ('jsmith','Schema Admins','Schema Write','2022-06-15','high'),
        ('gdavis','Backup Operators','Backup/Restore','2023-03-10','high'),
        ('htaylor','Executive Team','Remote Access','2024-01-20','medium'),
        ('stest','IT Support','Local Admin','2021-09-05','medium'),
        ('svc-backup','Backup Operators','Backup/Restore','2021-01-01','high'),
        ('dadmin','Schema Admins','Schema Write','2020-01-01','critical'),
    ])
    conn.executemany("INSERT INTO audit_logs (event_id,type,username,target,source_ip,timestamp,result) VALUES (?,?,?,?,?,?,?)", [
        ('EVT-001','login','dadmin','DC01','10.0.0.5','2025-03-14 08:21','success'),
        ('EVT-002','modify','jsmith','GPO-Policy','10.0.1.22','2025-03-14 07:55','success'),
        ('EVT-003','login','unknown','FILESVR01','185.220.101.47','2025-03-13 23:14','failed'),
        ('EVT-004','create','dadmin','svcAcct01','10.0.0.5','2025-03-13 15:30','success'),
        ('EVT-005','delete','mwilson','old_policy','10.0.1.8','2025-03-13 11:05','success'),
        ('EVT-006','login','alee','WS-FIN-05','10.0.2.12','2025-03-13 09:02','success'),
        ('EVT-007','modify','unknown','AdminShare','203.45.67.8','2025-03-12 22:45','failed'),
        ('EVT-008','login','rjones','DC01','10.0.3.5','2025-03-12 10:12','success'),
        ('EVT-009','escalate','jsmith','Domain Admins','10.0.1.22','2025-03-11 16:40','failed'),
        ('EVT-010','login','gdavis','BACKUPSVR','10.0.1.19','2025-03-11 08:55','success'),
        ('EVT-011','delete','dadmin','audit_log_feb','10.0.0.5','2025-03-10 14:22','success'),
        ('EVT-012','create','htaylor','exec-share','10.0.4.2','2025-03-10 11:33','success'),
        ('EVT-013','login','unknown','OWA','91.108.4.15','2025-03-09 03:17','failed'),
        ('EVT-014','modify','pchang','firewall-rule','10.0.1.30','2025-03-09 09:45','success'),
        ('EVT-015','login','stest','DC01','10.0.0.22','2025-03-08 22:01','failed'),
    ])
    conn.executemany("INSERT INTO threats (indicator,type,severity,first_seen,count,status) VALUES (?,?,?,?,?,?)", [
        ('185.220.101.47','Brute Force IP','critical','2025-03-13 23:14',47,'active'),
        ('unknown user','Phantom Login','high','2025-03-12 22:45',12,'active'),
        ('91.108.4.15','TOR Exit Node','high','2025-03-09 03:17',3,'active'),
        ('203.45.67.8','Suspicious IP','medium','2025-03-12 22:45',2,'reviewing'),
        ('stest@corp','Disabled Acct Login','medium','2025-03-08 22:01',1,'resolved'),
    ])
    conn.executemany("INSERT INTO policies (name,category,scope,pass_count,fail_count,pct) VALUES (?,?,?,?,?,?)", [
        ('Password Complexity','Password','All Users',12,3,80),
        ('Password Max Age (90 days)','Password','All Users',11,4,73),
        ('MFA Enforcement','Auth','All Users',9,6,60),
        ('Privileged Acct Review','Access','Admins',3,4,43),
        ('Stale Acct Cleanup','Lifecycle','All Users',11,4,73),
        ('Service Acct Review','Lifecycle','Svc Accts',1,2,33),
        ('Admin Group Membership','Access','Admins',5,2,71),
        ('Audit Log Retention','Audit','All DCs',4,0,100),
    ])
    conn.commit()


# ─────────────────────────────────────────────────────────────
#  NEW TABLES — added for extended auditing features
# ─────────────────────────────────────────────────────────────

def migrate_db():
    """Add new tables to existing DB without destroying data."""
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS password_expiry (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT NOT NULL,
        last_set    TEXT,
        expires_on  TEXT,
        days_left   INTEGER,
        policy_days INTEGER DEFAULT 90,
        status      TEXT DEFAULT 'ok'
    );

    CREATE TABLE IF NOT EXISTS sessions (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT NOT NULL,
        host        TEXT,
        ip          TEXT,
        login_time  TEXT,
        last_seen   TEXT,
        duration    TEXT,
        status      TEXT DEFAULT 'active'
    );

    CREATE TABLE IF NOT EXISTS access_reviews (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT NOT NULL,
        resource    TEXT,
        access_type TEXT,
        granted_by  TEXT,
        review_due  TEXT,
        reviewed_by TEXT,
        decision    TEXT DEFAULT 'pending',
        notes       TEXT,
        created_at  TEXT
    );

    CREATE TABLE IF NOT EXISTS anomalies (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT,
        type        TEXT,
        description TEXT,
        severity    TEXT DEFAULT 'medium',
        source_ip   TEXT,
        detected_at TEXT,
        status      TEXT DEFAULT 'open'
    );

    CREATE TABLE IF NOT EXISTS assets (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname    TEXT NOT NULL,
        ip          TEXT,
        type        TEXT,
        os          TEXT,
        owner       TEXT,
        dept        TEXT,
        last_seen   TEXT,
        status      TEXT DEFAULT 'active',
        risk        TEXT DEFAULT 'low'
    );

    CREATE TABLE IF NOT EXISTS soc_alerts (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        title       TEXT NOT NULL,
        description TEXT,
        severity    TEXT DEFAULT 'medium',
        source      TEXT,
        username    TEXT,
        assigned_to TEXT,
        status      TEXT DEFAULT 'open',
        created_at  TEXT,
        closed_at   TEXT
    );

    CREATE TABLE IF NOT EXISTS compliance_checks (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        framework   TEXT,
        control_id  TEXT,
        control     TEXT NOT NULL,
        category    TEXT,
        status      TEXT DEFAULT 'fail',
        evidence    TEXT,
        last_check  TEXT
    );

    CREATE TABLE IF NOT EXISTS timeline (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT,
        action      TEXT NOT NULL,
        detail      TEXT,
        category    TEXT,
        severity    TEXT DEFAULT 'info',
        ip          TEXT,
        timestamp   TEXT
    );
    """)
    conn.commit()

    # Seed only if tables are empty
    if conn.execute("SELECT COUNT(*) FROM password_expiry").fetchone()[0] == 0:
        _seed_new(conn)
        print("  ✓ New audit tables seeded")
    conn.close()


def _seed_new(conn):
    from datetime import datetime, timedelta

    today = datetime.utcnow()

    # Password expiry
    pw_data = [
        ('jsmith',    '2024-06-01', (today+timedelta(days=-5)).strftime('%Y-%m-%d'),  -5,  90, 'expired'),
        ('alee',      '2025-01-10', (today+timedelta(days=12)).strftime('%Y-%m-%d'),   12, 90, 'warning'),
        ('rjones',    '2024-05-01', (today+timedelta(days=-45)).strftime('%Y-%m-%d'), -45, 90, 'expired'),
        ('mwilson',   '2025-02-01', (today+timedelta(days=30)).strftime('%Y-%m-%d'),   30, 90, 'ok'),
        ('dadmin',    '2025-01-01', (today+timedelta(days=6)).strftime('%Y-%m-%d'),     6, 90, 'warning'),
        ('bjohnson',  '2025-01-15', (today+timedelta(days=25)).strftime('%Y-%m-%d'),   25, 90, 'ok'),
        ('stest',     '2023-06-01', (today+timedelta(days=-90)).strftime('%Y-%m-%d'), -90, 90, 'expired'),
        ('kbrown',    '2025-02-10', (today+timedelta(days=45)).strftime('%Y-%m-%d'),   45, 90, 'ok'),
        ('gdavis',    '2024-07-01', (today+timedelta(days=-20)).strftime('%Y-%m-%d'), -20, 90, 'expired'),
        ('htaylor',   '2025-02-20', (today+timedelta(days=8)).strftime('%Y-%m-%d'),     8, 90, 'warning'),
        ('pchang',    '2025-03-01', (today+timedelta(days=55)).strftime('%Y-%m-%d'),   55, 90, 'ok'),
        ('svc-backup','2021-01-01', (today+timedelta(days=-200)).strftime('%Y-%m-%d'),-200,90, 'expired'),
        ('nwebb',     '2025-01-20', (today+timedelta(days=35)).strftime('%Y-%m-%d'),   35, 90, 'ok'),
        ('cford',     '2024-11-01', (today+timedelta(days=-10)).strftime('%Y-%m-%d'), -10, 90, 'expired'),
        ('lmartin',   '2025-02-01', (today+timedelta(days=28)).strftime('%Y-%m-%d'),   28, 90, 'ok'),
    ]
    conn.executemany(
        "INSERT INTO password_expiry (username,last_set,expires_on,days_left,policy_days,status) VALUES (?,?,?,?,?,?)",
        pw_data
    )

    # Active sessions
    sessions = [
        ('dadmin',    'DC01',       '10.0.0.5',       '2025-03-14 06:00', '2025-03-14 08:30', '2h 30m', 'active'),
        ('alee',      'WS-FIN-05',  '10.0.2.12',      '2025-03-14 08:00', '2025-03-14 08:20', '20m',    'active'),
        ('mwilson',   'WS-ADMIN-01','10.0.1.8',       '2025-03-14 07:45', '2025-03-14 08:15', '30m',    'active'),
        ('pchang',    'WS-IT-03',   '10.0.1.30',      '2025-03-14 07:30', '2025-03-14 08:10', '40m',    'active'),
        ('htaylor',   'WS-EXEC-02', '10.0.4.2',       '2025-03-14 08:05', '2025-03-14 08:22', '17m',    'active'),
        ('jsmith',    'WS-IT-01',   '10.0.1.22',      '2025-03-13 22:00', '2025-03-13 23:30', '1h 30m', 'expired'),
        ('unknown',   'FILESVR01',  '185.220.101.47',  '2025-03-13 23:14', '2025-03-13 23:14', '0m',     'blocked'),
        ('gdavis',    'BACKUPSVR',  '10.0.1.19',       '2025-03-13 08:00', '2025-03-13 09:00', '1h',     'expired'),
    ]
    conn.executemany(
        "INSERT INTO sessions (username,host,ip,login_time,last_seen,duration,status) VALUES (?,?,?,?,?,?,?)",
        sessions
    )

    # Access reviews
    reviews = [
        ('dadmin',    'Domain Controllers',  'Admin',      'IT Director', '2025-03-20', None,    'pending', 'Quarterly review required'),
        ('jsmith',    'Backup Share',        'Read/Write', 'IT Director', '2025-03-15', None,    'pending', 'Access since 2022, still needed?'),
        ('gdavis',    'Backup Operators Grp','Member',     'IT Director', '2025-03-15', None,    'pending', 'User is stale - review urgently'),
        ('htaylor',   'Exec File Share',     'Full Control','CEO',        '2025-03-30', None,    'pending', 'Exec access - routine review'),
        ('stest',     'IT Support Group',    'Member',     'IT Director', '2025-03-10', 'admin', 'approved','Service acct — kept for legacy'),
        ('alee',      'Finance Reports',     'Read',       'CFO',         '2025-04-01', None,    'pending', 'Standard finance access'),
        ('svc-backup','Backup Operators',    'Member',     'IT Director', '2025-03-10', 'admin', 'revoked', 'Old SVC account - removed'),
        ('rjones',    'HR Database',         'Read/Write', 'HR Director', '2025-03-25', None,    'pending', 'Stale user with DB write access'),
    ]
    conn.executemany(
        "INSERT INTO access_reviews (username,resource,access_type,granted_by,review_due,reviewed_by,decision,notes,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        [(r[0],r[1],r[2],r[3],r[4],r[5],r[6],r[7], today.strftime('%Y-%m-%d')) for r in reviews]
    )

    # Anomalies
    anomalies = [
        ('unknown',    'Brute Force',       '47 failed logins from 185.220.101.47 in 10 minutes',      'critical','185.220.101.47', '2025-03-13 23:14','open'),
        ('dadmin',     'Off-Hours Login',   'Domain Admin logged in at 02:33 AM — no change window',    'high',    '10.0.0.5',        '2025-03-11 02:33','open'),
        ('jsmith',     'Priv Escalation',   'Attempted to add self to Domain Admins group',             'high',    '10.0.1.22',       '2025-03-11 16:40','open'),
        ('unknown',    'TOR Node',          'Login attempt from known TOR exit node 91.108.4.15',       'high',    '91.108.4.15',     '2025-03-09 03:17','open'),
        ('stest',      'Disabled Acct',     'Disabled account attempted login to DC01',                 'medium',  '10.0.0.22',       '2025-03-08 22:01','investigating'),
        ('dadmin',     'Audit Log Deleted', 'Audit log for February deleted — possible cover-up',       'critical','10.0.0.5',        '2025-03-10 14:22','open'),
        ('svc-backup', 'Stale SVC Login',   'Service account unused 14 months logged in',               'medium',  '10.0.1.19',       '2025-03-11 08:55','investigating'),
        ('gdavis',     'After Hours Access','Stale user gdavis accessed BACKUPSVR outside business hrs','medium',  '10.0.1.19',       '2025-03-11 08:55','resolved'),
    ]
    conn.executemany(
        "INSERT INTO anomalies (username,type,description,severity,source_ip,detected_at,status) VALUES (?,?,?,?,?,?,?)",
        anomalies
    )

    # Assets
    assets = [
        ('DC01',        '10.0.0.1',  'Domain Controller','Windows Server 2022','IT Ops',   'IT',    '2025-03-14','active','low'),
        ('DC02',        '10.0.0.2',  'Domain Controller','Windows Server 2019','IT Ops',   'IT',    '2025-03-14','active','low'),
        ('FILESVR01',   '10.0.0.10', 'File Server',      'Windows Server 2019','IT Ops',   'IT',    '2025-03-13','active','medium'),
        ('BACKUPSVR',   '10.0.0.11', 'Backup Server',    'Windows Server 2016','IT Ops',   'IT',    '2025-03-13','active','high'),
        ('WS-IT-01',    '10.0.1.22', 'Workstation',      'Windows 11',         'jsmith',   'IT',    '2025-03-14','active','high'),
        ('WS-FIN-05',   '10.0.2.12', 'Workstation',      'Windows 11',         'alee',     'Finance','2025-03-14','active','low'),
        ('WS-EXEC-02',  '10.0.4.2',  'Workstation',      'Windows 11',         'htaylor',  'Exec',  '2025-03-14','active','medium'),
        ('WS-ADMIN-01', '10.0.1.8',  'Workstation',      'Windows 11',         'mwilson',  'Admin', '2025-03-14','active','low'),
        ('PRINTSVR',    '10.0.0.20', 'Print Server',     'Windows Server 2016','IT Ops',   'IT',    '2025-03-10','active','medium'),
        ('OWA',         '10.0.0.30', 'Web Server',       'Windows Server 2022','IT Ops',   'IT',    '2025-03-14','active','high'),
        ('LEGACYAPP01', '10.0.5.5',  'App Server',       'Windows Server 2012','Unknown',  'Unknown','2025-01-01','stale','critical'),
        ('TESTVM-01',   '10.0.9.1',  'Virtual Machine',  'Windows 10',         'gdavis',   'IT',    '2024-09-01','stale','high'),
    ]
    conn.executemany(
        "INSERT INTO assets (hostname,ip,type,os,owner,dept,last_seen,status,risk) VALUES (?,?,?,?,?,?,?,?,?)",
        assets
    )

    # SOC Alerts
    alerts = [
        ('Brute Force Attack Detected',       'Multiple failed logins from external IP 185.220.101.47',     'critical','IDS',        'unknown',  None,    'open',         today.strftime('%Y-%m-%d %H:%M'), None),
        ('Audit Log Deletion',                'dadmin deleted February audit logs — investigate immediately','critical','Sysmon',     'dadmin',   None,    'open',         today.strftime('%Y-%m-%d %H:%M'), None),
        ('Privilege Escalation Attempt',      'jsmith attempted to join Domain Admins group',               'high',    'AD',         'jsmith',   'admin', 'investigating', today.strftime('%Y-%m-%d %H:%M'), None),
        ('TOR Exit Node Login Attempt',       'Connection from known TOR node 91.108.4.15',                 'high',    'Firewall',   'unknown',  None,    'open',         today.strftime('%Y-%m-%d %H:%M'), None),
        ('Admin Off-Hours Login',             'Domain Admin account active at 2:33 AM',                     'high',    'AD',         'dadmin',   'admin', 'investigating', today.strftime('%Y-%m-%d %H:%M'), None),
        ('Stale Account Activity',            '3 accounts inactive 90+ days still have AD access',         'medium',  'AD Audit',   None,       'admin', 'open',         today.strftime('%Y-%m-%d %H:%M'), None),
        ('Expired Passwords Still Active',    '5 users with expired passwords can still authenticate',     'medium',  'AD Audit',   None,       None,    'open',         today.strftime('%Y-%m-%d %H:%M'), None),
        ('MFA Gap Identified',                '6 users without MFA including IT staff',                    'medium',  'Policy Chk', None,       None,    'open',         today.strftime('%Y-%m-%d %H:%M'), None),
        ('Legacy Server Detected',            'LEGACYAPP01 running Windows Server 2012 — EOL OS',          'low',     'Asset Scan', None,       None,    'resolved',     today.strftime('%Y-%m-%d %H:%M'), today.strftime('%Y-%m-%d %H:%M')),
        ('Service Account Password Expired',  'svc-backup password expired 200+ days ago',                 'low',     'AD Audit',   'svc-backup',None,   'resolved',     today.strftime('%Y-%m-%d %H:%M'), today.strftime('%Y-%m-%d %H:%M')),
    ]
    conn.executemany(
        "INSERT INTO soc_alerts (title,description,severity,source,username,assigned_to,status,created_at,closed_at) VALUES (?,?,?,?,?,?,?,?,?)",
        alerts
    )

    # Compliance checks (SOC2 / ISO27001 style)
    checks = [
        ('SOC2','AC-1', 'Access Control Policy',              'Access Control','pass', 'Policy documented and reviewed 2025-01', '2025-03-01'),
        ('SOC2','AC-2', 'Account Management',                 'Access Control','fail', '3 stale accounts not disabled',           '2025-03-14'),
        ('SOC2','AC-3', 'Access Enforcement',                 'Access Control','fail', 'Privilege review overdue for 4 accounts', '2025-03-14'),
        ('SOC2','AC-7', 'Unsuccessful Login Attempts',        'Access Control','pass', 'Lockout policy enforced after 5 attempts','2025-03-01'),
        ('SOC2','AU-2', 'Audit Events',                       'Audit',        'pass', 'All DCs logging to SIEM',                 '2025-03-14'),
        ('SOC2','AU-9', 'Protection of Audit Information',    'Audit',        'fail', 'Audit log deleted by dadmin on 2025-03-10','2025-03-14'),
        ('SOC2','IA-5', 'Authenticator Management',           'Identity',     'fail', '5 users with expired passwords',          '2025-03-14'),
        ('SOC2','IA-2', 'Multi-Factor Authentication',        'Identity',     'fail', '6 users lack MFA',                        '2025-03-14'),
        ('SOC2','SC-8', 'Transmission Confidentiality',       'System',       'pass', 'TLS enforced on all services',            '2025-03-01'),
        ('SOC2','SI-2', 'Flaw Remediation',                   'System',       'fail', 'LEGACYAPP01 running EOL OS (Win 2012)',   '2025-03-14'),
        ('ISO27001','A.9.1','Access Control Policy',          'Access Control','pass','Documented and approved',                  '2025-02-01'),
        ('ISO27001','A.9.2','User Access Management',         'Access Control','fail','Stale & orphaned accounts present',        '2025-03-14'),
        ('ISO27001','A.9.4','System Access Control',          'Access Control','pass','Screensaver lock enforced',                '2025-03-01'),
        ('ISO27001','A.12.4','Logging and Monitoring',        'Operations',   'fail','Audit log integrity compromised',           '2025-03-14'),
        ('ISO27001','A.16.1','Incident Management',           'Incident',     'pass','IRP documented and tested Q4 2024',        '2025-01-15'),
    ]
    conn.executemany(
        "INSERT INTO compliance_checks (framework,control_id,control,category,status,evidence,last_check) VALUES (?,?,?,?,?,?,?)",
        checks
    )

    # Timeline entries
    timeline = [
        ('dadmin',   'Login',              'Logged into DC01',                           'auth',    'info',    '10.0.0.5',       '2025-03-14 08:21'),
        ('jsmith',   'GPO Modified',       'Modified Group Policy Object: GPO-Policy',   'change',  'warn',    '10.0.1.22',      '2025-03-14 07:55'),
        ('unknown',  'Failed Login',       'Failed login to FILESVR01 x47',              'security','critical','185.220.101.47', '2025-03-13 23:14'),
        ('dadmin',   'Account Created',    'Created new account: svcAcct01',             'change',  'warn',    '10.0.0.5',       '2025-03-13 15:30'),
        ('mwilson',  'Object Deleted',     'Deleted old_policy from AD',                 'change',  'warn',    '10.0.1.8',       '2025-03-13 11:05'),
        ('alee',     'Login',              'Logged into WS-FIN-05',                      'auth',    'info',    '10.0.2.12',      '2025-03-13 09:02'),
        ('unknown',  'Share Access',       'Attempted access to AdminShare — denied',    'security','high',    '203.45.67.8',    '2025-03-12 22:45'),
        ('rjones',   'Login',              'Logged into DC01',                           'auth',    'info',    '10.0.3.5',       '2025-03-12 10:12'),
        ('jsmith',   'Escalation Attempt', 'Tried to add self to Domain Admins',        'security','critical','10.0.1.22',      '2025-03-11 16:40'),
        ('dadmin',   'Off-Hours Login',    'Login at 02:33 outside business hours',      'security','high',    '10.0.0.5',       '2025-03-11 02:33'),
        ('dadmin',   'Audit Log Deleted',  'Deleted audit_log_feb — no change ticket',   'security','critical','10.0.0.5',       '2025-03-10 14:22'),
        ('htaylor',  'Share Created',      'Created exec-share with broad permissions',  'change',  'warn',    '10.0.4.2',       '2025-03-10 11:33'),
        ('unknown',  'Failed Login',       'Login attempt to OWA from TOR node',         'security','high',    '91.108.4.15',    '2025-03-09 03:17'),
        ('pchang',   'Firewall Modified',  'Updated firewall-rule on perimeter FW',      'change',  'warn',    '10.0.1.30',      '2025-03-09 09:45'),
        ('stest',    'Disabled Acct Login','Disabled account attempted login to DC01',   'security','high',    '10.0.0.22',      '2025-03-08 22:01'),
    ]
    conn.executemany(
        "INSERT INTO timeline (username,action,detail,category,severity,ip,timestamp) VALUES (?,?,?,?,?,?,?)",
        timeline
    )

    conn.commit()
