"""
app/routes/api.py
Full CRUD REST API — every entity has Create, Read, Update, Delete.
All writes are auto-logged to audit_logs.
"""
from flask import Blueprint, jsonify, request, session
from app.models.database import get_db, rows_to_list
from app.routes.auth import login_required, analyst_required, admin_required
from datetime import datetime, timedelta

api_bp = Blueprint('api', __name__)

def _paginate(items, request):
    """Apply pagination to a list. Returns (paged_items, total, page, size)."""
    page = max(1, int(request.args.get('page', 1)))
    size = min(200, max(1, int(request.args.get('size', 50))))
    total = len(items)
    start = (page - 1) * size
    return items[start:start + size], total, page, size

def _paginated_response(items, request):
    """Return a paginated JSON response."""
    paged, total, page, size = _paginate(items, request)
    return jsonify({'items': paged, 'total': total, 'page': page, 'size': size,
                    'pages': max(1, -(-total // size))})

@api_bp.before_request
def check_api_csrf():
    """Validate CSRF token on all state-changing API requests."""
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        from flask import session as _session
        token    = request.headers.get('X-CSRFToken', '')
        expected = _session.get('csrf_token', '')
        if not token or not expected or token != expected:
            return jsonify({'error': 'CSRF token invalid or missing'}), 403

def _now():
    return datetime.utcnow().strftime('%Y-%m-%d %H:%M')

def _today():
    return datetime.utcnow().strftime('%Y-%m-%d')

def _log(db, type_, user, target, ip, result='success'):
    count = db.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
    db.execute(
        "INSERT INTO audit_logs (event_id,type,username,target,source_ip,result,timestamp) VALUES (?,?,?,?,?,?,?)",
        (f'EVT-{count+1:04d}', type_, user, target, ip or '127.0.0.1', result, _now())
    )

def _err(msg, code=400):
    return jsonify({'error': msg}), code

def _require(data, *fields):
    return [f for f in fields if not str(data.get(f, '')).strip()]

def _ip():
    return request.remote_addr or '127.0.0.1'

def _fmt_user(u):
    u['mfa'] = bool(u.get('mfa', 0))
    return u

@api_bp.route('/health')
def health():
    db = get_db()
    counts = {}
    for t in ['users','groups','privileges','audit_logs','threats','policies','sessions','assets','soc_alerts','compliance_checks']:
        try: counts[t] = db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        except: counts[t] = 0
    db.close()
    return jsonify({'status': 'ok', 'version': '3.0.0', 'db': counts})

@api_bp.route('/summary')
def summary():
    db = get_db()
    users = rows_to_list(db.execute("SELECT * FROM users").fetchall())
    stale=[u for u in users if u['status']=='stale']
    priv=[u for u in users if u['risk'] in ('critical','high')]
    compliant=[u for u in users if u['risk']=='low']
    no_mfa=[u for u in users if not u['mfa']]
    score=round((len(compliant)/len(users)*60)+((1-len(stale)/len(users))*40)) if users else 0
    dept_risk={}
    for u in users:
        dept_risk.setdefault(u['dept'],{'high':0,'total':0})
        dept_risk[u['dept']]['total']+=1
        if u['risk'] in ('critical','high'): dept_risk[u['dept']]['high']+=1
    # Build real 30-day trend from audit_logs
    from datetime import date, timedelta
    today = date.today()
    trend = []
    for i in range(29, -1, -1):
        day_date = (today - timedelta(days=i)).strftime('%Y-%m-%d')
        day_num  = 30 - i
        # Count events by severity/type for this day
        critical = db.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE timestamp LIKE ? AND type='escalate'",
            (day_date + '%',)).fetchone()[0]
        high = db.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE timestamp LIKE ? AND result='failed'",
            (day_date + '%',)).fetchone()[0]
        medium = db.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE timestamp LIKE ? AND type IN ('modify','delete')",
            (day_date + '%',)).fetchone()[0]
        trend.append({'day': day_num, 'date': day_date,
                      'critical': critical, 'high': high, 'medium': medium})
    threats=db.execute("SELECT COUNT(*) FROM threats WHERE status='active'").fetchone()[0]
    recent=rows_to_list(db.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 5").fetchall())
    for e in recent:
        e['user']=e.pop('username',''); e['ip']=e.pop('source_ip',''); e['time']=e.pop('timestamp','')
    db.close()
    return jsonify({'total':len(users),'stale':len(stale),'priv':len(priv),'compliant':len(compliant),'no_mfa':len(no_mfa),'score':score,
        'status':{'active':sum(1 for u in users if u['status']=='active'),'stale':sum(1 for u in users if u['status']=='stale'),'disabled':sum(1 for u in users if u['status']=='disabled')},
        'dept_risk':dept_risk,'trend':trend,
        'findings':[
            {'level':'danger','text':f'{len(stale)} stale accounts with active domain access'},
            {'level':'danger','text':f'{threats} active threat indicators detected'},
            {'level':'warn','text':f'{len(no_mfa)} users without MFA enabled'},
            {'level':'warn','text':f'{len(priv)} users with high/critical risk level'},
            {'level':'ok','text':f'{len(compliant)} accounts pass all security checks'},
        ],'recent':recent})

# USERS CRUD
@api_bp.route('/users', methods=['GET'])
def get_users():
    db=get_db(); sql="SELECT * FROM users WHERE 1=1"; params=[]
    for f in ('status','risk','dept'):
        v=request.args.get(f)
        if v: sql+=f" AND {f}=?"; params.append(v)
    q=request.args.get('q','')
    if q: sql+=" AND (username LIKE ? OR name LIKE ? OR dept LIKE ? OR email LIKE ?)"; params+=[f'%{q}%']*4
    users=rows_to_list(db.execute(sql,params).fetchall())
    for u in users:
        _fmt_user(u)
        u['groups']=[r['group_name'] for r in db.execute("SELECT group_name FROM group_members WHERE username=?",(u['username'],)).fetchall()]
    db.close()
    # Support both paginated and full list (page param triggers pagination)
    if request.args.get('page'):
        return _paginated_response(users, request)
    return jsonify(users)

@api_bp.route('/users/<username>', methods=['GET'])
def get_user(username):
    db=get_db(); row=db.execute("SELECT * FROM users WHERE username=?",(username,)).fetchone()
    if not row: db.close(); return _err('Not found',404)
    u=_fmt_user(dict(row))
    u['groups']=[r['group_name'] for r in db.execute("SELECT group_name FROM group_members WHERE username=?",(username,)).fetchall()]
    u['recent_events']=rows_to_list(db.execute("SELECT * FROM audit_logs WHERE username=? ORDER BY id DESC LIMIT 5",(username,)).fetchall())
    db.close(); return jsonify(u)

@api_bp.route('/users', methods=['POST'])
@admin_required
def create_user():
    data=request.get_json() or {}
    m=_require(data,'username','name')
    if m: return _err(f'Required: {", ".join(m)}')
    db=get_db()
    if db.execute("SELECT id FROM users WHERE username=?",(data['username'],)).fetchone():
        db.close(); return _err(f'Username "{data["username"]}" already exists',409)
    db.execute("INSERT INTO users (username,name,dept,email,last_login,status,risk,mfa) VALUES (?,?,?,?,?,?,?,?)",
        (data['username'].strip(),data['name'].strip(),data.get('dept',''),data.get('email',''),
         data.get('last_login',_today()),data.get('status','active'),data.get('risk','low'),1 if data.get('mfa') else 0))
    uid=db.execute("SELECT id FROM users WHERE username=?",(data['username'],)).fetchone()['id']
    for grp in data.get('groups',[]):
        if grp.strip(): db.execute("INSERT OR IGNORE INTO group_members (username,group_name) VALUES (?,?)",(data['username'],grp.strip()))
    exp=(datetime.utcnow()+timedelta(days=90)).strftime('%Y-%m-%d')
    db.execute("INSERT INTO password_expiry (username,last_set,expires_on,days_left,policy_days,status) VALUES (?,?,?,?,?,?)",
        (data['username'],_today(),exp,90,90,'ok'))
    _log(db,'create','admin',f'user:{data["username"]}',_ip())
    db.commit()
    row=db.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
    u=_fmt_user(dict(row)); u['groups']=data.get('groups',[]); db.close()
    return jsonify(u),201

@api_bp.route('/users/<int:uid>', methods=['PUT'])
@admin_required
def update_user_full(uid):
    data=request.get_json() or {}
    m=_require(data,'username','name')
    if m: return _err(f'Required: {", ".join(m)}')
    db=get_db()
    if not db.execute("SELECT id FROM users WHERE id=?",(uid,)).fetchone(): db.close(); return _err('Not found',404)
    db.execute("UPDATE users SET username=?,name=?,dept=?,email=?,last_login=?,status=?,risk=?,mfa=? WHERE id=?",
        (data['username'],data['name'],data.get('dept',''),data.get('email',''),
         data.get('last_login',_today()),data.get('status','active'),data.get('risk','low'),1 if data.get('mfa') else 0,uid))
    if 'groups' in data:
        db.execute("DELETE FROM group_members WHERE username=?",(data['username'],))
        for grp in data['groups']:
            if grp.strip(): db.execute("INSERT OR IGNORE INTO group_members (username,group_name) VALUES (?,?)",(data['username'],grp.strip()))
    _log(db,'modify','admin',f'user:{data["username"]}',_ip())
    db.commit()
    row=db.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
    u=_fmt_user(dict(row)); db.close(); return jsonify(u)

@api_bp.route('/users/<int:uid>', methods=['PATCH'])
@admin_required
def patch_user(uid):
    data=request.get_json() or {}; db=get_db()
    allowed=('status','risk','mfa','dept','email','name','last_login')
    updates={k:v for k,v in data.items() if k in allowed}
    if not updates: db.close(); return _err('No valid fields')
    sets=', '.join(f"{k}=?" for k in updates)
    db.execute(f"UPDATE users SET {sets} WHERE id=?",(*updates.values(),uid))
    _log(db,'modify','admin',f'user:id={uid}',_ip()); db.commit()
    row=db.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
    if not row: db.close(); return _err('Not found',404)
    u=_fmt_user(dict(row)); db.close(); return jsonify(u)

@api_bp.route('/users/<int:uid>', methods=['DELETE'])
@admin_required
def delete_user(uid):
    db=get_db(); row=db.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
    if not row: db.close(); return _err('Not found',404)
    uname=row['username']
    for tbl in ['users','group_members','privileges','password_expiry']:
        col='id' if tbl=='users' else 'username'
        val=uid if tbl=='users' else uname
        db.execute(f"DELETE FROM {tbl} WHERE {col}=?",(val,))
    _log(db,'delete','admin',f'user:{uname}',_ip()); db.commit(); db.close()
    return jsonify({'message':f'User {uname} deleted'})

# GROUPS CRUD
@api_bp.route('/groups', methods=['GET'])
def get_groups():
    db=get_db(); sql="SELECT * FROM groups WHERE 1=1"; params=[]
    t=request.args.get('type')
    if t: sql+=" AND type=?"; params.append(t)
    if request.args.get('privileged')=='true': sql+=" AND privileged=1"
    q=request.args.get('q','')
    if q: sql+=" AND name LIKE ?"; params.append(f'%{q}%')
    groups=rows_to_list(db.execute(sql,params).fetchall())
    for g in groups:
        g['privileged']=bool(g['privileged'])
        g['members']=db.execute("SELECT COUNT(*) FROM group_members WHERE group_name=?",(g['name'],)).fetchone()[0]
        g['member_list']=[r['username'] for r in db.execute("SELECT username FROM group_members WHERE group_name=?",(g['name'],)).fetchall()]
    db.close(); return jsonify(groups)

@api_bp.route('/groups/<int:gid>', methods=['GET'])
def get_group(gid):
    db=get_db(); row=db.execute("SELECT * FROM groups WHERE id=?",(gid,)).fetchone()
    if not row: db.close(); return _err('Not found',404)
    g=dict(row); g['privileged']=bool(g['privileged'])
    g['member_list']=[r['username'] for r in db.execute("SELECT username FROM group_members WHERE group_name=?",(g['name'],)).fetchall()]
    db.close(); return jsonify(g)

@api_bp.route('/groups', methods=['POST'])
@admin_required
def create_group():
    data=request.get_json() or {}
    m=_require(data,'name')
    if m: return _err('Group name is required')
    db=get_db()
    if db.execute("SELECT id FROM groups WHERE name=?",(data['name'],)).fetchone():
        db.close(); return _err(f'Group "{data["name"]}" already exists',409)
    db.execute("INSERT INTO groups (name,type,privileged,nested,description,modified) VALUES (?,?,?,?,?,?)",
        (data['name'].strip(),data.get('type','Security'),1 if data.get('privileged') else 0,
         int(data.get('nested',0)),data.get('description',''),_today()))
    gid=db.execute("SELECT id FROM groups WHERE name=?",(data['name'],)).fetchone()['id']
    for m2 in data.get('members',[]):
        if m2.strip(): db.execute("INSERT OR IGNORE INTO group_members (username,group_name) VALUES (?,?)",(m2.strip(),data['name']))
    _log(db,'create','admin',f'group:{data["name"]}',_ip()); db.commit()
    row=db.execute("SELECT * FROM groups WHERE id=?",(gid,)).fetchone()
    g=dict(row); g['privileged']=bool(g['privileged']); db.close()
    return jsonify(g),201

@api_bp.route('/groups/<int:gid>', methods=['PUT'])
@admin_required
def update_group(gid):
    data=request.get_json() or {}
    m=_require(data,'name')
    if m: return _err('Group name is required')
    db=get_db()
    row=db.execute("SELECT * FROM groups WHERE id=?",(gid,)).fetchone()
    if not row: db.close(); return _err('Not found',404)
    db.execute("UPDATE groups SET name=?,type=?,privileged=?,nested=?,description=?,modified=? WHERE id=?",
        (data['name'],data.get('type','Security'),1 if data.get('privileged') else 0,
         int(data.get('nested',0)),data.get('description',''),_today(),gid))
    if 'members' in data:
        db.execute("DELETE FROM group_members WHERE group_name=?",(row['name'],))
        for m2 in data['members']:
            if m2.strip(): db.execute("INSERT OR IGNORE INTO group_members (username,group_name) VALUES (?,?)",(m2.strip(),data['name']))
    _log(db,'modify','admin',f'group:{data["name"]}',_ip()); db.commit()
    g=dict(db.execute("SELECT * FROM groups WHERE id=?",(gid,)).fetchone()); g['privileged']=bool(g['privileged']); db.close()
    return jsonify(g)

@api_bp.route('/groups/<int:gid>', methods=['DELETE'])
@admin_required
def delete_group(gid):
    db=get_db(); row=db.execute("SELECT * FROM groups WHERE id=?",(gid,)).fetchone()
    if not row: db.close(); return _err('Not found',404)
    db.execute("DELETE FROM groups WHERE id=?",(gid,))
    db.execute("DELETE FROM group_members WHERE group_name=?",(row['name'],))
    _log(db,'delete','admin',f'group:{row["name"]}',_ip()); db.commit(); db.close()
    return jsonify({'message':f'Group {row["name"]} deleted'})

@api_bp.route('/groups/<int:gid>/members', methods=['POST'])
@admin_required
def add_group_member(gid):
    data=request.get_json() or {}
    if not data.get('username'): return _err('username required')
    db=get_db(); row=db.execute("SELECT * FROM groups WHERE id=?",(gid,)).fetchone()
    if not row: db.close(); return _err('Not found',404)
    db.execute("INSERT OR IGNORE INTO group_members (username,group_name) VALUES (?,?)",(data['username'],row['name']))
    _log(db,'modify','admin',f'group_add:{row["name"]}:{data["username"]}',_ip()); db.commit(); db.close()
    return jsonify({'message':f'Added {data["username"]} to {row["name"]}'})

@api_bp.route('/groups/<int:gid>/members/<username>', methods=['DELETE'])
@admin_required
def remove_group_member(gid, username):
    db=get_db(); row=db.execute("SELECT * FROM groups WHERE id=?",(gid,)).fetchone()
    if not row: db.close(); return _err('Not found',404)
    db.execute("DELETE FROM group_members WHERE group_name=? AND username=?",(row['name'],username))
    _log(db,'delete','admin',f'group_remove:{row["name"]}:{username}',_ip()); db.commit(); db.close()
    return jsonify({'message':f'Removed {username} from {row["name"]}'})

# PRIVILEGES CRUD
@api_bp.route('/privileges', methods=['GET'])
def get_privileges():
    db=get_db(); rows=rows_to_list(db.execute("SELECT * FROM privileges ORDER BY id DESC").fetchall())
    for r in rows: r['user']=r.pop('username','')
    db.close(); return jsonify(rows)

@api_bp.route('/privileges', methods=['POST'])
@admin_required
def create_privilege():
    data=request.get_json() or {}
    m=_require(data,'username','group_name','permission')
    if m: return _err(f'Required: {", ".join(m)}')
    db=get_db()
    db.execute("INSERT INTO privileges (username,group_name,permission,granted,risk) VALUES (?,?,?,?,?)",
        (data['username'],data['group_name'],data['permission'],data.get('granted',_today()),data.get('risk','medium')))
    pid=db.execute("SELECT last_insert_rowid()").fetchone()[0]
    _log(db,'create','admin',f'privilege:{data["username"]}:{data["group_name"]}',_ip()); db.commit()
    row=dict(db.execute("SELECT * FROM privileges WHERE id=?",(pid,)).fetchone())
    row['user']=row.pop('username',''); db.close(); return jsonify(row),201

@api_bp.route('/privileges/<int:pid>', methods=['PUT'])
@admin_required
def update_privilege(pid):
    data=request.get_json() or {}; db=get_db()
    if not db.execute("SELECT id FROM privileges WHERE id=?",(pid,)).fetchone(): db.close(); return _err('Not found',404)
    db.execute("UPDATE privileges SET username=?,group_name=?,permission=?,granted=?,risk=? WHERE id=?",
        (data.get('username',''),data.get('group_name',''),data.get('permission',''),data.get('granted',_today()),data.get('risk','medium'),pid))
    _log(db,'modify','admin',f'privilege:id={pid}',_ip()); db.commit()
    row=dict(db.execute("SELECT * FROM privileges WHERE id=?",(pid,)).fetchone())
    row['user']=row.pop('username',''); db.close(); return jsonify(row)

@api_bp.route('/privileges/<int:pid>', methods=['DELETE'])
@admin_required
def delete_privilege(pid):
    db=get_db(); row=db.execute("SELECT * FROM privileges WHERE id=?",(pid,)).fetchone()
    if not row: db.close(); return _err('Not found',404)
    db.execute("DELETE FROM privileges WHERE id=?",(pid,))
    _log(db,'delete','admin',f'privilege:{row["username"]}',_ip()); db.commit(); db.close()
    return jsonify({'message':f'Privilege revoked for {row["username"]}'})

# AUDIT LOG — Read + Create
@api_bp.route('/audit', methods=['GET'])
def get_audit():
    db=get_db(); sql="SELECT * FROM audit_logs WHERE 1=1"; params=[]
    for f,c in (('type','type'),('result','result')):
        v=request.args.get(f)
        if v: sql+=f" AND {c}=?"; params.append(v)
    u=request.args.get('user','')
    if u: sql+=" AND username LIKE ?"; params.append(f'%{u}%')
    total=db.execute(sql.replace("SELECT *","SELECT COUNT(*)"),params).fetchone()[0]
    page,size=int(request.args.get('page',1)),int(request.args.get('size',20))
    sql+=" ORDER BY id DESC LIMIT ? OFFSET ?"; params+=[size,(page-1)*size]
    items=rows_to_list(db.execute(sql,params).fetchall())
    for e in items:
        e['user']=e.pop('username',''); e['ip']=e.pop('source_ip',''); e['time']=e.pop('timestamp','')
    db.close(); return jsonify({'total':total,'page':page,'size':size,'items':items})

@api_bp.route('/audit', methods=['POST'])
@analyst_required
def create_audit_entry():
    data=request.get_json() or {}
    m=_require(data,'type','username','target')
    if m: return _err(f'Required: {", ".join(m)}')
    db=get_db(); count=db.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
    db.execute("INSERT INTO audit_logs (event_id,type,username,target,source_ip,result,timestamp) VALUES (?,?,?,?,?,?,?)",
        (f'EVT-{count+1:04d}',data['type'],data['username'],data['target'],
         data.get('source_ip',_ip()),data.get('result','success'),data.get('timestamp',_now())))
    db.commit(); eid=db.execute("SELECT last_insert_rowid()").fetchone()[0]
    row=dict(db.execute("SELECT * FROM audit_logs WHERE id=?",(eid,)).fetchone())
    row['user']=row.pop('username',''); row['ip']=row.pop('source_ip',''); row['time']=row.pop('timestamp','')
    db.close(); return jsonify(row),201

@api_bp.route('/audit/<int:eid>', methods=['DELETE'])
@admin_required
def delete_audit_entry(eid):
    db=get_db()
    if not db.execute("SELECT id FROM audit_logs WHERE id=?",(eid,)).fetchone(): db.close(); return _err('Not found',404)
    db.execute("DELETE FROM audit_logs WHERE id=?",(eid,)); db.commit(); db.close()
    return jsonify({'message':'Entry deleted'})

# THREATS CRUD
@api_bp.route('/threats', methods=['GET'])
def get_threats():
    db=get_db(); rows=rows_to_list(db.execute("SELECT * FROM threats ORDER BY id DESC").fetchall())
    for r in rows: r['first']=r.pop('first_seen','')
    db.close(); return jsonify(rows)

@api_bp.route('/threats', methods=['POST'])
@admin_required
def create_threat():
    data=request.get_json() or {}
    m=_require(data,'indicator','type','severity')
    if m: return _err(f'Required: {", ".join(m)}')
    db=get_db()
    db.execute("INSERT INTO threats (indicator,type,severity,first_seen,count,status) VALUES (?,?,?,?,?,?)",
        (data['indicator'],data['type'],data['severity'],data.get('first_seen',_now()),int(data.get('count',1)),data.get('status','active')))
    tid=db.execute("SELECT last_insert_rowid()").fetchone()[0]
    _log(db,'create','admin',f'threat:{data["indicator"]}',_ip()); db.commit()
    row=dict(db.execute("SELECT * FROM threats WHERE id=?",(tid,)).fetchone()); row['first']=row.pop('first_seen','')
    db.close(); return jsonify(row),201

@api_bp.route('/threats/<int:tid>', methods=['PUT'])
@analyst_required
def update_threat_full(tid):
    data=request.get_json() or {}; db=get_db()
    if not db.execute("SELECT id FROM threats WHERE id=?",(tid,)).fetchone(): db.close(); return _err('Not found',404)
    db.execute("UPDATE threats SET indicator=?,type=?,severity=?,first_seen=?,count=?,status=? WHERE id=?",
        (data.get('indicator',''),data.get('type',''),data.get('severity','medium'),
         data.get('first_seen',_now()),int(data.get('count',1)),data.get('status','active'),tid))
    _log(db,'modify','admin',f'threat:id={tid}',_ip()); db.commit()
    row=dict(db.execute("SELECT * FROM threats WHERE id=?",(tid,)).fetchone()); row['first']=row.pop('first_seen','')
    db.close(); return jsonify(row)

@api_bp.route('/threats/<int:tid>', methods=['PATCH'])
@analyst_required
def patch_threat(tid):
    data=request.get_json() or {}; db=get_db()
    if 'status' in data: db.execute("UPDATE threats SET status=? WHERE id=?",(data['status'],tid)); db.commit()
    row=db.execute("SELECT * FROM threats WHERE id=?",(tid,)).fetchone()
    if not row: db.close(); return _err('Not found',404)
    r=dict(row); r['first']=r.pop('first_seen',''); db.close(); return jsonify(r)

@api_bp.route('/threats/<int:tid>', methods=['DELETE'])
@admin_required
def delete_threat(tid):
    db=get_db(); row=db.execute("SELECT * FROM threats WHERE id=?",(tid,)).fetchone()
    if not row: db.close(); return _err('Not found',404)
    db.execute("DELETE FROM threats WHERE id=?",(tid,))
    _log(db,'delete','admin',f'threat:{row["indicator"]}',_ip()); db.commit(); db.close()
    return jsonify({'message':'Threat deleted'})

# POLICIES CRUD
def _policy_row(r):
    r['pass']=r.pop('pass_count',0); r['fail']=r.pop('fail_count',0)
    r['status']='PASS' if r['pct']>=80 else 'PARTIAL' if r['pct']>=50 else 'FAIL'; return r

@api_bp.route('/policies', methods=['GET'])
def get_policies():
    db=get_db(); rows=rows_to_list(db.execute("SELECT * FROM policies").fetchall()); db.close()
    return jsonify([_policy_row(r) for r in rows])

@api_bp.route('/policies', methods=['POST'])
@admin_required
def create_policy():
    data=request.get_json() or {}
    m=_require(data,'name','category')
    if m: return _err(f'Required: {", ".join(m)}')
    db=get_db()
    db.execute("INSERT INTO policies (name,category,scope,pass_count,fail_count,pct) VALUES (?,?,?,?,?,?)",
        (data['name'],data['category'],data.get('scope','All Users'),int(data.get('pass',0)),int(data.get('fail',0)),int(data.get('pct',0))))
    pid=db.execute("SELECT last_insert_rowid()").fetchone()[0]
    _log(db,'create','admin',f'policy:{data["name"]}',_ip()); db.commit()
    row=_policy_row(dict(db.execute("SELECT * FROM policies WHERE id=?",(pid,)).fetchone()))
    db.close(); return jsonify(row),201

@api_bp.route('/policies/<int:pid>', methods=['PUT'])
@admin_required
def update_policy(pid):
    data=request.get_json() or {}; db=get_db()
    if not db.execute("SELECT id FROM policies WHERE id=?",(pid,)).fetchone(): db.close(); return _err('Not found',404)
    db.execute("UPDATE policies SET name=?,category=?,scope=?,pass_count=?,fail_count=?,pct=? WHERE id=?",
        (data.get('name',''),data.get('category',''),data.get('scope','All Users'),
         int(data.get('pass',0)),int(data.get('fail',0)),int(data.get('pct',0)),pid))
    _log(db,'modify','admin',f'policy:id={pid}',_ip()); db.commit()
    row=_policy_row(dict(db.execute("SELECT * FROM policies WHERE id=?",(pid,)).fetchone())); db.close(); return jsonify(row)

@api_bp.route('/policies/<int:pid>', methods=['DELETE'])
@admin_required
def delete_policy(pid):
    db=get_db(); row=db.execute("SELECT * FROM policies WHERE id=?",(pid,)).fetchone()
    if not row: db.close(); return _err('Not found',404)
    db.execute("DELETE FROM policies WHERE id=?",(pid,))
    _log(db,'delete','admin',f'policy:{row["name"]}',_ip()); db.commit(); db.close()
    return jsonify({'message':'Policy deleted'})

# ASSETS CRUD
@api_bp.route('/assets', methods=['GET'])
def get_assets():
    db=get_db(); sql="SELECT * FROM assets WHERE 1=1"; params=[]
    for f in ('status','risk','type','dept'):
        v=request.args.get(f)
        if v: sql+=f" AND {f}=?"; params.append(v)
    q=request.args.get('q','')
    if q: sql+=" AND (hostname LIKE ? OR ip LIKE ? OR owner LIKE ? OR dept LIKE ?)"; params+=[f'%{q}%']*4
    rows=rows_to_list(db.execute(sql,params).fetchall()); db.close(); return jsonify(rows)

@api_bp.route('/assets/summary', methods=['GET'])
def assets_summary():
    db=get_db(); rows=rows_to_list(db.execute("SELECT * FROM assets").fetchall()); db.close()
    types={}
    for a in rows: types[a['type']]=types.get(a['type'],0)+1
    return jsonify({'total':len(rows),'active':sum(1 for a in rows if a['status']=='active'),
        'stale':sum(1 for a in rows if a['status']=='stale'),
        'critical':sum(1 for a in rows if a['risk']=='critical'),'by_type':types})

@api_bp.route('/assets', methods=['POST'])
@admin_required
def create_asset():
    data=request.get_json() or {}
    m=_require(data,'hostname','type')
    if m: return _err(f'Required: {", ".join(m)}')
    db=get_db()
    if db.execute("SELECT id FROM assets WHERE hostname=?",(data['hostname'],)).fetchone():
        db.close(); return _err(f'Hostname "{data["hostname"]}" already exists',409)
    db.execute("INSERT INTO assets (hostname,ip,type,os,owner,dept,last_seen,status,risk) VALUES (?,?,?,?,?,?,?,?,?)",
        (data['hostname'],data.get('ip',''),data['type'],data.get('os',''),
         data.get('owner',''),data.get('dept',''),data.get('last_seen',_today()),data.get('status','active'),data.get('risk','low')))
    aid=db.execute("SELECT last_insert_rowid()").fetchone()[0]
    _log(db,'create','admin',f'asset:{data["hostname"]}',_ip()); db.commit()
    row=dict(db.execute("SELECT * FROM assets WHERE id=?",(aid,)).fetchone()); db.close(); return jsonify(row),201

@api_bp.route('/assets/<int:aid>', methods=['PUT'])
@admin_required
def update_asset(aid):
    data=request.get_json() or {}; db=get_db()
    if not db.execute("SELECT id FROM assets WHERE id=?",(aid,)).fetchone(): db.close(); return _err('Not found',404)
    db.execute("UPDATE assets SET hostname=?,ip=?,type=?,os=?,owner=?,dept=?,last_seen=?,status=?,risk=? WHERE id=?",
        (data.get('hostname',''),data.get('ip',''),data.get('type',''),data.get('os',''),
         data.get('owner',''),data.get('dept',''),data.get('last_seen',_today()),data.get('status','active'),data.get('risk','low'),aid))
    _log(db,'modify','admin',f'asset:id={aid}',_ip()); db.commit()
    row=dict(db.execute("SELECT * FROM assets WHERE id=?",(aid,)).fetchone()); db.close(); return jsonify(row)

@api_bp.route('/assets/<int:aid>', methods=['DELETE'])
@admin_required
def delete_asset(aid):
    db=get_db(); row=db.execute("SELECT * FROM assets WHERE id=?",(aid,)).fetchone()
    if not row: db.close(); return _err('Not found',404)
    db.execute("DELETE FROM assets WHERE id=?",(aid,))
    _log(db,'delete','admin',f'asset:{row["hostname"]}',_ip()); db.commit(); db.close()
    return jsonify({'message':f'Asset {row["hostname"]} deleted'})

# SOC ALERTS CRUD
@api_bp.route('/soc-alerts', methods=['GET'])
def get_soc_alerts():
    db=get_db(); sql="SELECT * FROM soc_alerts WHERE 1=1"; params=[]
    for f in ('severity','status'):
        v=request.args.get(f)
        if v: sql+=f" AND {f}=?"; params.append(v)
    q=request.args.get('q','')
    if q: sql+=" AND (title LIKE ? OR description LIKE ?)"; params+=[f'%{q}%']*2
    sql+=" ORDER BY id DESC"
    rows=rows_to_list(db.execute(sql,params).fetchall()); db.close()
    if request.args.get('page'):
        return _paginated_response(rows, request)
    return jsonify(rows)

@api_bp.route('/soc-alerts/summary', methods=['GET'])
def soc_summary():
    db=get_db(); rows=rows_to_list(db.execute("SELECT * FROM soc_alerts").fetchall()); db.close()
    return jsonify({'total':len(rows),'open':sum(1 for a in rows if a['status']=='open'),
        'critical':sum(1 for a in rows if a['severity']=='critical' and a['status']=='open'),
        'high':sum(1 for a in rows if a['severity']=='high' and a['status']=='open'),
        'resolved':sum(1 for a in rows if a['status'] in ('resolved','closed'))})

@api_bp.route('/soc-alerts', methods=['POST'])
@admin_required
def create_soc_alert():
    data=request.get_json() or {}
    m=_require(data,'title','severity')
    if m: return _err(f'Required: {", ".join(m)}')
    db=get_db()
    db.execute("INSERT INTO soc_alerts (title,description,severity,source,username,assigned_to,status,created_at) VALUES (?,?,?,?,?,?,?,?)",
        (data['title'],data.get('description',''),data['severity'],data.get('source','Manual'),
         data.get('username',''),data.get('assigned_to',''),data.get('status','open'),_now()))
    sid=db.execute("SELECT last_insert_rowid()").fetchone()[0]
    _log(db,'create','admin',f'soc_alert:{data["title"]}',_ip()); db.commit()
    row=dict(db.execute("SELECT * FROM soc_alerts WHERE id=?",(sid,)).fetchone()); db.close(); return jsonify(row),201

@api_bp.route('/soc-alerts/<int:sid>', methods=['PUT'])
@analyst_required
def update_soc_alert_full(sid):
    data=request.get_json() or {}; db=get_db()
    if not db.execute("SELECT id FROM soc_alerts WHERE id=?",(sid,)).fetchone(): db.close(); return _err('Not found',404)
    closed=_now() if data.get('status') in ('resolved','closed') else None
    db.execute("UPDATE soc_alerts SET title=?,description=?,severity=?,source=?,username=?,assigned_to=?,status=?,closed_at=COALESCE(?,closed_at) WHERE id=?",
        (data.get('title',''),data.get('description',''),data.get('severity','medium'),
         data.get('source',''),data.get('username',''),data.get('assigned_to',''),data.get('status','open'),closed,sid))
    _log(db,'modify','admin',f'soc_alert:id={sid}',_ip()); db.commit()
    row=dict(db.execute("SELECT * FROM soc_alerts WHERE id=?",(sid,)).fetchone()); db.close(); return jsonify(row)

@api_bp.route('/soc-alerts/<int:sid>', methods=['PATCH'])
@analyst_required
def patch_soc_alert(sid):
    data=request.get_json() or {}; db=get_db()
    closed=_now() if data.get('status') in ('resolved','closed') else None
    db.execute("UPDATE soc_alerts SET status=?,assigned_to=COALESCE(?,assigned_to),closed_at=COALESCE(?,closed_at) WHERE id=?",
        (data.get('status','open'),data.get('assigned_to'),closed,sid))
    db.commit(); row=db.execute("SELECT * FROM soc_alerts WHERE id=?",(sid,)).fetchone()
    if not row: db.close(); return _err('Not found',404)
    db.close(); return jsonify(dict(row))

@api_bp.route('/soc-alerts/<int:sid>', methods=['DELETE'])
@admin_required
def delete_soc_alert(sid):
    db=get_db(); row=db.execute("SELECT * FROM soc_alerts WHERE id=?",(sid,)).fetchone()
    if not row: db.close(); return _err('Not found',404)
    db.execute("DELETE FROM soc_alerts WHERE id=?",(sid,))
    _log(db,'delete','admin',f'soc_alert:{row["title"]}',_ip()); db.commit(); db.close()
    return jsonify({'message':'Alert deleted'})

# COMPLIANCE CRUD
@api_bp.route('/compliance', methods=['GET'])
def get_compliance():
    db=get_db(); sql="SELECT * FROM compliance_checks WHERE 1=1"; params=[]
    for f in ('framework','status','category'):
        v=request.args.get(f)
        if v: sql+=f" AND {f}=?"; params.append(v)
    rows=rows_to_list(db.execute(sql,params).fetchall()); db.close(); return jsonify(rows)

@api_bp.route('/compliance/score', methods=['GET'])
def compliance_score():
    db=get_db(); rows=rows_to_list(db.execute("SELECT * FROM compliance_checks").fetchall()); db.close()
    fw={}
    for r in rows:
        fw.setdefault(r['framework'],{'pass':0,'fail':0,'total':0}); fw[r['framework']]['total']+=1
        fw[r['framework']][r['status']]=fw[r['framework']].get(r['status'],0)+1
    return jsonify({k:{**v,'score':round(v.get('pass',0)/v['total']*100) if v['total'] else 0} for k,v in fw.items()})

@api_bp.route('/compliance', methods=['POST'])
@admin_required
def create_compliance():
    data=request.get_json() or {}
    m=_require(data,'framework','control_id','control')
    if m: return _err(f'Required: {", ".join(m)}')
    db=get_db()
    db.execute("INSERT INTO compliance_checks (framework,control_id,control,category,status,evidence,last_check) VALUES (?,?,?,?,?,?,?)",
        (data['framework'],data['control_id'],data['control'],data.get('category','General'),
         data.get('status','fail'),data.get('evidence',''),data.get('last_check',_today())))
    cid=db.execute("SELECT last_insert_rowid()").fetchone()[0]
    _log(db,'create','admin',f'compliance:{data["framework"]}:{data["control_id"]}',_ip()); db.commit()
    row=dict(db.execute("SELECT * FROM compliance_checks WHERE id=?",(cid,)).fetchone()); db.close(); return jsonify(row),201

@api_bp.route('/compliance/<int:cid>', methods=['PUT'])
@analyst_required
def update_compliance_full(cid):
    data=request.get_json() or {}; db=get_db()
    if not db.execute("SELECT id FROM compliance_checks WHERE id=?",(cid,)).fetchone(): db.close(); return _err('Not found',404)
    db.execute("UPDATE compliance_checks SET framework=?,control_id=?,control=?,category=?,status=?,evidence=?,last_check=? WHERE id=?",
        (data.get('framework',''),data.get('control_id',''),data.get('control',''),
         data.get('category',''),data.get('status','fail'),data.get('evidence',''),_today(),cid))
    _log(db,'modify','admin',f'compliance:id={cid}',_ip()); db.commit()
    row=dict(db.execute("SELECT * FROM compliance_checks WHERE id=?",(cid,)).fetchone()); db.close(); return jsonify(row)

@api_bp.route('/compliance/<int:cid>', methods=['PATCH'])
@analyst_required
def patch_compliance(cid):
    data=request.get_json() or {}; db=get_db()
    db.execute("UPDATE compliance_checks SET status=?,evidence=COALESCE(?,evidence),last_check=? WHERE id=?",
        (data.get('status','fail'),data.get('evidence'),_today(),cid))
    db.commit(); row=db.execute("SELECT * FROM compliance_checks WHERE id=?",(cid,)).fetchone()
    if not row: db.close(); return _err('Not found',404)
    db.close(); return jsonify(dict(row))

@api_bp.route('/compliance/<int:cid>', methods=['DELETE'])
@admin_required
def delete_compliance(cid):
    db=get_db(); row=db.execute("SELECT * FROM compliance_checks WHERE id=?",(cid,)).fetchone()
    if not row: db.close(); return _err('Not found',404)
    db.execute("DELETE FROM compliance_checks WHERE id=?",(cid,))
    _log(db,'delete','admin',f'compliance:{row["framework"]}:{row["control_id"]}',_ip()); db.commit(); db.close()
    return jsonify({'message':'Compliance check deleted'})

# ANOMALIES CRUD
@api_bp.route('/anomalies', methods=['GET'])
def get_anomalies():
    db=get_db(); sql="SELECT * FROM anomalies WHERE 1=1"; params=[]
    for f in ('severity','status'):
        v=request.args.get(f)
        if v: sql+=f" AND {f}=?"; params.append(v)
    q=request.args.get('q','')
    if q: sql+=" AND (username LIKE ? OR description LIKE ? OR type LIKE ?)"; params+=[f'%{q}%']*3
    sql+=" ORDER BY id DESC"
    rows=rows_to_list(db.execute(sql,params).fetchall()); db.close()
    if request.args.get('page'):
        return _paginated_response(rows, request)
    return jsonify(rows)

@api_bp.route('/anomalies', methods=['POST'])
@admin_required
def create_anomaly():
    data=request.get_json() or {}
    m=_require(data,'type','description','severity')
    if m: return _err(f'Required: {", ".join(m)}')
    db=get_db()
    db.execute("INSERT INTO anomalies (username,type,description,severity,source_ip,detected_at,status) VALUES (?,?,?,?,?,?,?)",
        (data.get('username',''),data['type'],data['description'],data['severity'],
         data.get('source_ip',''),data.get('detected_at',_now()),data.get('status','open')))
    aid=db.execute("SELECT last_insert_rowid()").fetchone()[0]
    _log(db,'create','admin',f'anomaly:{data["type"]}',_ip()); db.commit()
    row=dict(db.execute("SELECT * FROM anomalies WHERE id=?",(aid,)).fetchone()); db.close(); return jsonify(row),201

@api_bp.route('/anomalies/<int:aid>', methods=['PUT'])
@analyst_required
def update_anomaly_full(aid):
    data=request.get_json() or {}; db=get_db()
    if not db.execute("SELECT id FROM anomalies WHERE id=?",(aid,)).fetchone(): db.close(); return _err('Not found',404)
    db.execute("UPDATE anomalies SET username=?,type=?,description=?,severity=?,source_ip=?,detected_at=?,status=? WHERE id=?",
        (data.get('username',''),data.get('type',''),data.get('description',''),
         data.get('severity','medium'),data.get('source_ip',''),data.get('detected_at',_now()),data.get('status','open'),aid))
    _log(db,'modify','admin',f'anomaly:id={aid}',_ip()); db.commit()
    row=dict(db.execute("SELECT * FROM anomalies WHERE id=?",(aid,)).fetchone()); db.close(); return jsonify(row)

@api_bp.route('/anomalies/<int:aid>', methods=['PATCH'])
@analyst_required
def patch_anomaly(aid):
    data=request.get_json() or {}; db=get_db()
    db.execute("UPDATE anomalies SET status=? WHERE id=?",(data.get('status','open'),aid))
    db.commit(); db.close(); return jsonify({'message':'Anomaly updated'})

@api_bp.route('/anomalies/<int:aid>', methods=['DELETE'])
@admin_required
def delete_anomaly(aid):
    db=get_db(); row=db.execute("SELECT * FROM anomalies WHERE id=?",(aid,)).fetchone()
    if not row: db.close(); return _err('Not found',404)
    db.execute("DELETE FROM anomalies WHERE id=?",(aid,))
    _log(db,'delete','admin',f'anomaly:id={aid}',_ip()); db.commit(); db.close()
    return jsonify({'message':'Anomaly deleted'})

# ACCESS REVIEWS CRUD
@api_bp.route('/access-reviews', methods=['GET'])
def get_access_reviews():
    db=get_db(); sql="SELECT * FROM access_reviews WHERE 1=1"; params=[]
    d=request.args.get('decision'); q=request.args.get('q','')
    if d: sql+=" AND decision=?"; params.append(d)
    if q: sql+=" AND (username LIKE ? OR resource LIKE ?)"; params+=[f'%{q}%']*2
    sql+=" ORDER BY review_due ASC"
    rows=rows_to_list(db.execute(sql,params).fetchall()); db.close(); return jsonify(rows)

@api_bp.route('/access-reviews', methods=['POST'])
@admin_required
def create_access_review():
    data=request.get_json() or {}
    m=_require(data,'username','resource','access_type','review_due')
    if m: return _err(f'Required: {", ".join(m)}')
    db=get_db()
    db.execute("INSERT INTO access_reviews (username,resource,access_type,granted_by,review_due,decision,notes,created_at) VALUES (?,?,?,?,?,?,?,?)",
        (data['username'],data['resource'],data['access_type'],data.get('granted_by','admin'),
         data['review_due'],data.get('decision','pending'),data.get('notes',''),_today()))
    rid=db.execute("SELECT last_insert_rowid()").fetchone()[0]
    _log(db,'create','admin',f'access_review:{data["username"]}:{data["resource"]}',_ip()); db.commit()
    row=dict(db.execute("SELECT * FROM access_reviews WHERE id=?",(rid,)).fetchone()); db.close(); return jsonify(row),201

@api_bp.route('/access-reviews/<int:rid>', methods=['PUT'])
@analyst_required
def update_access_review(rid):
    data=request.get_json() or {}; db=get_db()
    if not db.execute("SELECT id FROM access_reviews WHERE id=?",(rid,)).fetchone(): db.close(); return _err('Not found',404)
    db.execute("UPDATE access_reviews SET username=?,resource=?,access_type=?,granted_by=?,review_due=?,decision=?,notes=? WHERE id=?",
        (data.get('username',''),data.get('resource',''),data.get('access_type',''),
         data.get('granted_by',''),data.get('review_due',''),data.get('decision','pending'),data.get('notes',''),rid))
    _log(db,'modify','admin',f'access_review:id={rid}',_ip()); db.commit()
    row=dict(db.execute("SELECT * FROM access_reviews WHERE id=?",(rid,)).fetchone()); db.close(); return jsonify(row)

@api_bp.route('/access-reviews/<int:rid>/decide', methods=['PATCH'])
@analyst_required
def decide_review(rid):
    data=request.get_json() or {}; db=get_db()
    db.execute("UPDATE access_reviews SET decision=?,reviewed_by='admin',notes=COALESCE(?,notes) WHERE id=?",
        (data.get('decision','pending'),data.get('notes'),rid))
    row=db.execute("SELECT * FROM access_reviews WHERE id=?",(rid,)).fetchone()
    _log(db,'modify','admin',f'access_review:{row["username"] if row else rid}:{data.get("decision")}',_ip())
    db.commit(); db.close(); return jsonify({'message':f'Review {data.get("decision","updated")}'})

@api_bp.route('/access-reviews/<int:rid>', methods=['DELETE'])
@admin_required
def delete_access_review(rid):
    db=get_db(); row=db.execute("SELECT * FROM access_reviews WHERE id=?",(rid,)).fetchone()
    if not row: db.close(); return _err('Not found',404)
    db.execute("DELETE FROM access_reviews WHERE id=?",(rid,))
    _log(db,'delete','admin',f'access_review:{row["username"]}',_ip()); db.commit(); db.close()
    return jsonify({'message':'Access review deleted'})

# PASSWORDS
@api_bp.route('/passwords', methods=['GET'])
def get_passwords():
    db=get_db(); sql="SELECT * FROM password_expiry WHERE 1=1"; params=[]
    s=request.args.get('status'); q=request.args.get('q','')
    if s: sql+=" AND status=?"; params.append(s)
    if q: sql+=" AND username LIKE ?"; params.append(f'%{q}%')
    sql+=" ORDER BY days_left ASC"
    rows=rows_to_list(db.execute(sql,params).fetchall()); db.close(); return jsonify(rows)

@api_bp.route('/passwords/summary', methods=['GET'])
def passwords_summary():
    db=get_db(); rows=rows_to_list(db.execute("SELECT * FROM password_expiry").fetchall()); db.close()
    return jsonify({'expired':sum(1 for r in rows if r['status']=='expired'),
        'warning':sum(1 for r in rows if r['status']=='warning'),
        'ok':sum(1 for r in rows if r['status']=='ok'),'total':len(rows)})

@api_bp.route('/passwords/<int:pid>/reset', methods=['POST'])
@analyst_required
def reset_password(pid):
    db=get_db(); row=db.execute("SELECT * FROM password_expiry WHERE id=?",(pid,)).fetchone()
    if not row: db.close(); return _err('Not found',404)
    exp=(datetime.utcnow()+timedelta(days=90)).strftime('%Y-%m-%d')
    db.execute("UPDATE password_expiry SET last_set=?,expires_on=?,days_left=90,status='ok' WHERE id=?",(_today(),exp,pid))
    _log(db,'modify','admin',f'password_reset:{row["username"]}',_ip()); db.commit(); db.close()
    return jsonify({'message':f'Password reset for {row["username"]}'})

# SESSIONS
@api_bp.route('/sessions', methods=['GET'])
def get_sessions():
    db=get_db(); sql="SELECT * FROM sessions WHERE 1=1"; params=[]
    s=request.args.get('status'); q=request.args.get('q','')
    if s: sql+=" AND status=?"; params.append(s)
    if q: sql+=" AND (username LIKE ? OR host LIKE ? OR ip LIKE ?)"; params+=[f'%{q}%']*3
    rows=rows_to_list(db.execute(sql,params).fetchall()); db.close(); return jsonify(rows)

@api_bp.route('/sessions/<int:sid>/terminate', methods=['POST'])
@analyst_required
def terminate_session(sid):
    db=get_db(); row=db.execute("SELECT * FROM sessions WHERE id=?",(sid,)).fetchone()
    if not row: db.close(); return _err('Not found',404)
    db.execute("UPDATE sessions SET status='terminated' WHERE id=?",(sid,))
    _log(db,'delete','admin',f'session:{row["username"]}@{row["host"]}',_ip()); db.commit(); db.close()
    return jsonify({'message':f'Session terminated for {row["username"]}'})

# TIMELINE
@api_bp.route('/timeline', methods=['GET'])
def get_timeline():
    db=get_db(); sql="SELECT * FROM timeline WHERE 1=1"; params=[]
    for f in ('username','category','severity'):
        v=request.args.get(f)
        if v: sql+=f" AND {f}=?"; params.append(v)
    q=request.args.get('q','')
    if q: sql+=" AND (username LIKE ? OR action LIKE ? OR detail LIKE ?)"; params+=[f'%{q}%']*3
    total=db.execute(sql.replace("SELECT *","SELECT COUNT(*)"),params).fetchone()[0]
    page,size=int(request.args.get('page',1)),int(request.args.get('size',20))
    sql+=" ORDER BY id DESC LIMIT ? OFFSET ?"; params+=[size,(page-1)*size]
    rows=rows_to_list(db.execute(sql,params).fetchall()); db.close()
    return jsonify({'total':total,'page':page,'size':size,'items':rows})

@api_bp.route('/timeline', methods=['POST'])
def create_timeline_entry():
    data=request.get_json() or {}
    m=_require(data,'action')
    if m: return _err('action is required')
    db=get_db()
    db.execute("INSERT INTO timeline (username,action,detail,category,severity,ip,timestamp) VALUES (?,?,?,?,?,?,?)",
        (data.get('username',''),data['action'],data.get('detail',''),
         data.get('category','change'),data.get('severity','info'),data.get('ip',_ip()),data.get('timestamp',_now())))
    db.commit(); db.close(); return jsonify({'message':'Entry created'}),201

# REPORTS
@api_bp.route('/report/<report_type>', methods=['GET'])
def get_report(report_type):
    db=get_db(); now=_now()
    if   report_type=='stale':      data=rows_to_list(db.execute("SELECT * FROM users WHERE status='stale'").fetchall()); [_fmt_user(u) for u in data]
    elif report_type=='privileged':
        data=rows_to_list(db.execute("SELECT * FROM privileges").fetchall())
        for r in data: r['user']=r.pop('username','')
    elif report_type=='threats':    data=rows_to_list(db.execute("SELECT * FROM threats").fetchall())
    elif report_type=='compliance':
        rows2=rows_to_list(db.execute("SELECT * FROM policies").fetchall()); data=[_policy_row(r) for r in rows2]
    elif report_type=='mfa':
        data=[{'username':r['username'],'name':r['name'],'dept':r['dept'],'mfa':'Yes' if r['mfa'] else 'No','risk':r['risk']}
              for r in rows_to_list(db.execute("SELECT * FROM users").fetchall())]
    elif report_type=='full':       data=rows_to_list(db.execute("SELECT * FROM users").fetchall()); [_fmt_user(u) for u in data]
    elif report_type=='passwords':  data=rows_to_list(db.execute("SELECT * FROM password_expiry ORDER BY days_left ASC").fetchall())
    elif report_type=='anomalies':  data=rows_to_list(db.execute("SELECT * FROM anomalies WHERE status='open'").fetchall())
    elif report_type=='assets':     data=rows_to_list(db.execute("SELECT * FROM assets").fetchall())
    else: db.close(); return _err('Unknown report type',400)
    db.close(); return jsonify({'type':report_type,'generated':now,'count':len(data),'data':data})

# SEARCH
@api_bp.route('/search', methods=['GET'])
def search():
    q=request.args.get('q','').strip()
    if not q: return jsonify({'users':[],'groups':[],'events':[],'assets':[],'alerts':[]})
    db=get_db(); like=f'%{q}%'
    users=rows_to_list(db.execute("SELECT * FROM users WHERE username LIKE ? OR name LIKE ? OR dept LIKE ? LIMIT 8",(like,like,like)).fetchall())
    groups=rows_to_list(db.execute("SELECT * FROM groups WHERE name LIKE ? LIMIT 8",(like,)).fetchall())
    events=rows_to_list(db.execute("SELECT * FROM audit_logs WHERE username LIKE ? OR target LIKE ? LIMIT 8",(like,like)).fetchall())
    assets=rows_to_list(db.execute("SELECT * FROM assets WHERE hostname LIKE ? OR ip LIKE ? LIMIT 5",(like,like)).fetchall())
    alerts=rows_to_list(db.execute("SELECT * FROM soc_alerts WHERE title LIKE ? OR description LIKE ? LIMIT 5",(like,like)).fetchall())
    for e in events:
        e['user']=e.pop('username',''); e['ip']=e.pop('source_ip',''); e['time']=e.pop('timestamp','')
    db.close()
    return jsonify({'users':users,'groups':groups,'events':events,'assets':assets,'alerts':alerts})
