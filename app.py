#!/usr/bin/env python3
"""CertVault - Certificate Management System"""

import os, json, sqlite3, hashlib, zipfile, subprocess, string
import threading, time, shutil, base64, secrets, struct
from datetime import datetime, timezone
from pathlib import Path
from functools import wraps
from flask import Flask, render_template, request, jsonify, send_file, g, session, redirect, url_for
import hmac as _hmac

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 86400 * 7

BASE_DIR    = Path(__file__).parent
CERTS_DIR   = BASE_DIR / 'certs_store'
EXPORTS_DIR = BASE_DIR / 'exports'
DB_PATH     = BASE_DIR / 'certvault.db'
CERTS_DIR.mkdir(exist_ok=True)
EXPORTS_DIR.mkdir(exist_ok=True)

# ─── TOTP ────────────────────────────────────────────────────────────────────
def totp_secret(): return base64.b32encode(secrets.token_bytes(20)).decode()
def totp_code(secret, t=None):
    if t is None: t = int(time.time())//30
    key = base64.b32decode(secret.upper())
    h   = _hmac.new(key, struct.pack('>Q', t), 'sha1').digest()
    off = h[-1] & 0x0f
    return str((struct.unpack('>I', h[off:off+4])[0] & 0x7fffffff) % 1000000).zfill(6)
def totp_verify(secret, token, window=1):
    t = int(time.time())//30
    tok = str(token).strip().zfill(6)
    for i in range(-window, window+1):
        if _hmac.compare_digest(totp_code(secret, t+i), tok): return True
    return False
def totp_uri(secret, username):
    from urllib.parse import quote
    return f"otpauth://totp/CertVault:{quote(username)}?secret={secret}&issuer=CertVault&algorithm=SHA1&digits=6&period=30"

# ─── Password ─────────────────────────────────────────────────────────────────
def hash_pw(pw):
    salt = secrets.token_hex(16)
    h    = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 260000)
    return f"pbkdf2:{salt}:{h.hex()}"
def check_pw(pw, stored):
    try:
        _, salt, h = stored.split(':')
        h2 = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 260000)
        return _hmac.compare_digest(h2.hex(), h)
    except: return False

# ─── DB ───────────────────────────────────────────────────────────────────────
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH); g.db.row_factory = sqlite3.Row
    return g.db
@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db: db.close()

SCHEMA = '''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL, totp_secret TEXT, totp_enabled INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')),
    last_login TEXT, is_admin INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, domain TEXT NOT NULL,
    notes TEXT DEFAULT '', tags TEXT DEFAULT '[]', locations TEXT DEFAULT '[]',
    created_at TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')),
    updated_at TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')),
    folder TEXT NOT NULL UNIQUE, notify_days TEXT DEFAULT '[30,14,7]',
    notify_slack TEXT DEFAULT '', color TEXT DEFAULT '#4f8ef7');
CREATE TABLE IF NOT EXISTS cert_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT, cert_id INTEGER NOT NULL,
    filename TEXT NOT NULL, file_type TEXT NOT NULL, file_path TEXT NOT NULL,
    uploaded_at TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')),
    version INTEGER DEFAULT 1, is_active INTEGER DEFAULT 1, file_hash TEXT,
    FOREIGN KEY (cert_id) REFERENCES certificates(id));
CREATE TABLE IF NOT EXISTS cert_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT, cert_id INTEGER NOT NULL UNIQUE,
    subject TEXT, issuer TEXT, serial TEXT, not_before TEXT, not_after TEXT,
    san TEXT DEFAULT '[]', key_size INTEGER, signature_algorithm TEXT,
    is_ca INTEGER DEFAULT 0, raw_info TEXT DEFAULT '{}',
    FOREIGN KEY (cert_id) REFERENCES certificates(id));
CREATE TABLE IF NOT EXISTS locations (
    id INTEGER PRIMARY KEY AUTOINCREMENT, cert_id INTEGER NOT NULL,
    location_name TEXT NOT NULL, replacement_notes TEXT DEFAULT '',
    responsible_person TEXT DEFAULT '', contact_info TEXT DEFAULT '',
    last_updated TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')),
    FOREIGN KEY (cert_id) REFERENCES certificates(id));
CREATE TABLE IF NOT EXISTS notification_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, cert_id INTEGER NOT NULL,
    sent_at TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')),
    days_remaining INTEGER, status TEXT,
    FOREIGN KEY (cert_id) REFERENCES certificates(id));
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS certbot_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL,
    status TEXT DEFAULT 'pending', output TEXT DEFAULT '', cert_id INTEGER,
    created_at TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')), completed_at TEXT);
'''

def init_db():
    with app.app_context():
        db = sqlite3.connect(DB_PATH)
        db.executescript(SCHEMA); db.commit(); db.close()

def migrate_db():
    with app.app_context():
        db = sqlite3.connect(DB_PATH); db.row_factory = sqlite3.Row
        for stmt in ["ALTER TABLE certificates ADD COLUMN color TEXT DEFAULT '#4f8ef7'"]:
            try: db.execute(stmt)
            except: pass
        try:
            for row in db.execute("SELECT id,not_before,not_after FROM cert_info").fetchall():
                nb,na = norm_ts(row['not_before']), norm_ts(row['not_after'])
                if nb!=row['not_before'] or na!=row['not_after']:
                    db.execute("UPDATE cert_info SET not_before=?,not_after=? WHERE id=?",(nb,na,row['id']))
        except: pass
        db.commit(); db.close()

def no_users():
    with app.app_context():
        db = sqlite3.connect(DB_PATH)
        n  = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]; db.close(); return n==0

# ─── Auth ─────────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def dec(*a,**kw):
        if not session.get('user_id'):
            if request.path.startswith('/api/'): return jsonify({'error':'Unauthorized'}),401
            return redirect(url_for('login_page'))
        return f(*a,**kw)
    return dec

def cur_user(): return get_db().execute("SELECT * FROM users WHERE id=?",(session.get('user_id'),)).fetchone()

# ─── Timestamp helpers ────────────────────────────────────────────────────────
def norm_ts(s):
    if not s: return s
    s = str(s).replace('T',' ')
    for sep in ('+','Z'):
        idx = s.find(sep,10)
        if idx!=-1: s=s[:idx]
    return s[:19]
def parse_ts(s):
    if not s: return None
    try: return datetime.strptime(norm_ts(str(s)),'%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
    except: return None

# ─── Cert parsing ─────────────────────────────────────────────────────────────
def parse_cert_pem(pem):
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        if isinstance(pem,str): pem=pem.encode()
        c = x509.load_pem_x509_certificate(pem,default_backend())
        def n2d(n): return {a.oid._name:a.value for a in n}
        san=[]
        try:
            for n in c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value: san.append(str(n.value))
        except: pass
        ks=None
        try: ks=c.public_key().key_size
        except: pass
        is_ca=False
        try: is_ca=c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        except: pass
        gdt=lambda a: getattr(c,a+'_utc') if hasattr(c,a+'_utc') else getattr(c,a)
        return {'subject':json.dumps(n2d(c.subject)),'issuer':json.dumps(n2d(c.issuer)),
                'serial':str(c.serial_number),
                'not_before':norm_ts(gdt('not_valid_before').isoformat()),
                'not_after':norm_ts(gdt('not_valid_after').isoformat()),
                'san':json.dumps(san),'key_size':ks,
                'signature_algorithm':c.signature_hash_algorithm.name if c.signature_hash_algorithm else 'unknown',
                'is_ca':1 if is_ca else 0}
    except: return None

# ─── Auth Routes ──────────────────────────────────────────────────────────────
@app.route('/login')
def login_page():
    if session.get('user_id'): return redirect('/')
    return render_template('login.html', needs_setup=no_users())

@app.route('/api/auth/setup', methods=['POST'])
def setup_first_user():
    if not no_users(): return jsonify({'error':'Setup done'}),400
    d=request.get_json(); u=d.get('username','').strip(); p=d.get('password','')
    if not u or len(p)<8: return jsonify({'error':'Username required; password 8+ chars'}),400
    db=get_db(); db.execute("INSERT INTO users(username,password_hash,is_admin)VALUES(?,?,1)",(u,hash_pw(p))); db.commit()
    uid=db.execute("SELECT id FROM users WHERE username=?",(u,)).fetchone()['id']
    session['user_id']=uid; session['username']=u; session.permanent=True
    return jsonify({'ok':True})

@app.route('/api/auth/login', methods=['POST'])
def do_login():
    d=request.get_json(); u=d.get('username','').strip(); p=d.get('password',''); tok=d.get('totp_token','').strip()
    db=get_db(); user=db.execute("SELECT * FROM users WHERE username=?",(u,)).fetchone()
    if not user or not check_pw(p,user['password_hash']): time.sleep(0.5); return jsonify({'error':'Invalid username or password'}),401
    if user['totp_enabled']:
        if not tok: return jsonify({'need_totp':True}),200
        if not totp_verify(user['totp_secret'],tok): return jsonify({'error':'Invalid authenticator code'}),401
    db.execute("UPDATE users SET last_login=? WHERE id=?",(norm_ts(datetime.now(timezone.utc).isoformat()),user['id'])); db.commit()
    session['user_id']=user['id']; session['username']=user['username']; session.permanent=True
    return jsonify({'ok':True})

@app.route('/api/auth/logout', methods=['POST'])
def do_logout(): session.clear(); return jsonify({'ok':True})

@app.route('/api/auth/me')
@login_required
def auth_me():
    u=cur_user(); return jsonify({'id':u['id'],'username':u['username'],'totp_enabled':bool(u['totp_enabled']),'is_admin':bool(u['is_admin'])})

@app.route('/api/auth/totp/setup', methods=['POST'])
@login_required
def totp_setup_route():
    u=cur_user(); s=totp_secret(); uri=totp_uri(s,u['username'])
    db=get_db(); db.execute("UPDATE users SET totp_secret=? WHERE id=?",(s,u['id'])); db.commit()
    from urllib.parse import quote
    return jsonify({'secret':s,'uri':uri,'qr_url':f"https://api.qrserver.com/v1/create-qr-code/?size=220x220&data={quote(uri)}"})

@app.route('/api/auth/totp/verify', methods=['POST'])
@login_required
def totp_verify_route():
    d=request.get_json(); tok=d.get('token','').strip(); u=cur_user()
    if not u['totp_secret']: return jsonify({'error':'No secret — restart setup'}),400
    if not totp_verify(u['totp_secret'],tok): return jsonify({'error':'Invalid code'}),400
    db=get_db(); db.execute("UPDATE users SET totp_enabled=1 WHERE id=?",(u['id'],)); db.commit()
    return jsonify({'ok':True})

@app.route('/api/auth/totp/disable', methods=['POST'])
@login_required
def totp_disable_route():
    d=request.get_json(); tok=d.get('token','').strip(); u=cur_user()
    if u['totp_enabled'] and not totp_verify(u['totp_secret'],tok): return jsonify({'error':'Invalid code'}),400
    db=get_db(); db.execute("UPDATE users SET totp_enabled=0,totp_secret=NULL WHERE id=?",(u['id'],)); db.commit()
    return jsonify({'ok':True})

@app.route('/api/auth/change-password', methods=['POST'])
@login_required
def change_password():
    d=request.get_json(); cur=d.get('current_password',''); new=d.get('new_password',''); u=cur_user()
    if not check_pw(cur,u['password_hash']): return jsonify({'error':'Current password incorrect'}),400
    if len(new)<8: return jsonify({'error':'Password must be 8+ chars'}),400
    db=get_db(); db.execute("UPDATE users SET password_hash=? WHERE id=?",(hash_pw(new),u['id'])); db.commit()
    return jsonify({'ok':True})

@app.route('/api/users', methods=['GET'])
@login_required
def list_users():
    u=cur_user()
    if not u['is_admin']: return jsonify({'error':'Forbidden'}),403
    rows=get_db().execute("SELECT id,username,totp_enabled,is_admin,created_at,last_login FROM users").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/users', methods=['POST'])
@login_required
def create_user():
    u=cur_user()
    if not u['is_admin']: return jsonify({'error':'Forbidden'}),403
    d=request.get_json(); un=d.get('username','').strip(); pw=d.get('password','')
    if not un or len(pw)<8: return jsonify({'error':'Invalid'}),400
    db=get_db()
    try: db.execute("INSERT INTO users(username,password_hash,is_admin)VALUES(?,?,?)",(un,hash_pw(pw),1 if d.get('is_admin') else 0)); db.commit(); return jsonify({'ok':True}),201
    except sqlite3.IntegrityError: return jsonify({'error':'Username exists'}),409

@app.route('/api/users/<int:uid>', methods=['DELETE'])
@login_required
def delete_user(uid):
    u=cur_user()
    if not u['is_admin']: return jsonify({'error':'Forbidden'}),403
    if uid==u['id']: return jsonify({'error':'Cannot delete yourself'}),400
    db=get_db(); db.execute("DELETE FROM users WHERE id=?",(uid,)); db.commit(); return jsonify({'ok':True})

# ─── Main index ───────────────────────────────────────────────────────────────
@app.route('/')
@login_required
def index(): return render_template('index.html')

# ─── Certs ────────────────────────────────────────────────────────────────────
def expiry_info(not_after_str, now):
    exp=parse_ts(not_after_str)
    if not exp: return None,'unknown'
    d=(exp-now).days
    return d, ('expired' if d<0 else 'critical' if d<=7 else 'warning' if d<=30 else 'ok')

@app.route('/api/certs', methods=['GET'])
@login_required
def list_certs():
    db=get_db(); tag=request.args.get('tag',''); search=request.args.get('search',''); sort=request.args.get('sort','name')
    q='SELECT c.*,ci.not_after,ci.subject,ci.issuer,ci.is_ca FROM certificates c LEFT JOIN cert_info ci ON c.id=ci.cert_id'
    params=[]; conds=[]
    if search: conds.append("(c.name LIKE ? OR c.domain LIKE ? OR c.notes LIKE ?)"); params+=[f'%{search}%']*3
    if tag: conds.append("c.tags LIKE ?"); params.append(f'%{tag}%')
    if conds: q+=' WHERE '+' AND '.join(conds)
    om={'name':'c.name ASC','expiry':'ci.not_after ASC','created':'c.created_at DESC','domain':'c.domain ASC'}
    q+=f' ORDER BY {om.get(sort,"c.name ASC")}'
    now=datetime.now(timezone.utc); results=[]
    for row in db.execute(q,params).fetchall():
        r=dict(row)
        r['tags']=json.loads(r.get('tags') or '[]'); r['locations']=json.loads(r.get('locations') or '[]')
        r['notify_days']=json.loads(r.get('notify_days') or '[30,14,7]')
        d,s=expiry_info(r.get('not_after'),now); r['days_until_expiry']=d; r['expiry_status']=s
        fc=db.execute("SELECT COUNT(*) as c FROM cert_files WHERE cert_id=? AND is_active=1",(r['id'],)).fetchone()
        r['file_count']=fc['c'] if fc else 0; results.append(r)
    return jsonify(results)

@app.route('/api/certs', methods=['POST'])
@login_required
def create_cert():
    db=get_db(); d=request.get_json(); name=d.get('name','').strip(); domain=d.get('domain','').strip()
    if not name or not domain: return jsonify({'error':'Name and domain required'}),400
    folder=hashlib.md5(f"{name}{domain}{time.time()}".encode()).hexdigest()[:12]
    (CERTS_DIR/folder).mkdir(exist_ok=True)
    try:
        db.execute('INSERT INTO certificates(name,domain,notes,tags,locations,folder,notify_days,notify_slack,color)VALUES(?,?,?,?,?,?,?,?,?)',
            (name,domain,d.get('notes',''),json.dumps(d.get('tags',[])),json.dumps(d.get('locations',[])),
             folder,json.dumps(d.get('notify_days',[30,14,7])),d.get('notify_slack',''),d.get('color','#4f8ef7')))
        db.commit(); cid=db.execute('SELECT last_insert_rowid()').fetchone()[0]
        return jsonify({'id':cid,'folder':folder}),201
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/certs/<int:cid>', methods=['GET'])
@login_required
def get_cert(cid):
    db=get_db()
    row=db.execute('SELECT c.*,ci.not_after,ci.not_before,ci.subject,ci.issuer,ci.serial,ci.san,ci.key_size,ci.signature_algorithm,ci.is_ca FROM certificates c LEFT JOIN cert_info ci ON c.id=ci.cert_id WHERE c.id=?',(cid,)).fetchone()
    if not row: return jsonify({'error':'Not found'}),404
    r=dict(row)
    r['tags']=json.loads(r.get('tags') or '[]'); r['locations_json']=json.loads(r.get('locations') or '[]')
    r['notify_days']=json.loads(r.get('notify_days') or '[30,14,7]'); r['san']=json.loads(r.get('san') or '[]')
    d,s=expiry_info(r.get('not_after'),datetime.now(timezone.utc)); r['days_until_expiry']=d; r['expiry_status']=s
    r['files']=[dict(f) for f in db.execute("SELECT * FROM cert_files WHERE cert_id=? ORDER BY file_type,version DESC",(cid,)).fetchall()]
    r['location_details']=[dict(l) for l in db.execute("SELECT * FROM locations WHERE cert_id=?",(cid,)).fetchall()]
    return jsonify(r)

@app.route('/api/certs/<int:cid>', methods=['PUT'])
@login_required
def update_cert(cid):
    db=get_db(); d=request.get_json()
    db.execute("UPDATE certificates SET name=?,domain=?,notes=?,tags=?,notify_days=?,notify_slack=?,color=?,updated_at=strftime('%Y-%m-%d %H:%M:%S','now') WHERE id=?",
        (d.get('name'),d.get('domain'),d.get('notes',''),json.dumps(d.get('tags',[])),json.dumps(d.get('notify_days',[30,14,7])),d.get('notify_slack',''),d.get('color','#4f8ef7'),cid))
    db.commit(); return jsonify({'ok':True})

@app.route('/api/certs/<int:cid>', methods=['DELETE'])
@login_required
def delete_cert(cid):
    db=get_db(); row=db.execute("SELECT folder FROM certificates WHERE id=?",(cid,)).fetchone()
    if row:
        p=CERTS_DIR/row['folder']
        if p.exists(): shutil.rmtree(p)
    for t in ['cert_files','cert_info','locations']: db.execute(f"DELETE FROM {t} WHERE cert_id=?",(cid,))
    db.execute("DELETE FROM certificates WHERE id=?",(cid,)); db.commit(); return jsonify({'ok':True})

@app.route('/api/certs/<int:cid>/upload', methods=['POST'])
@login_required
def upload_file(cid):
    db=get_db(); crow=db.execute("SELECT * FROM certificates WHERE id=?",(cid,)).fetchone()
    if not crow: return jsonify({'error':'Not found'}),404
    if 'file' not in request.files: return jsonify({'error':'No file'}),400
    cd=CERTS_DIR/crow['folder']; cd.mkdir(exist_ok=True)
    f=request.files['file']; ft=request.form.get('file_type','other'); is_ren=request.form.get('renewal','false')=='true'
    content=f.read(); fhash=hashlib.sha256(content).hexdigest()
    ex=db.execute("SELECT MAX(version) as mv FROM cert_files WHERE cert_id=? AND file_type=?",(cid,ft)).fetchone()
    ver=(ex['mv'] or 0)+1
    if is_ren: db.execute("UPDATE cert_files SET is_active=0 WHERE cert_id=? AND file_type=?",(cid,ft))
    stem=Path(f.filename).stem; ext=Path(f.filename).suffix
    sp=cd/f"{stem}_v{ver}{ext}"; sp.write_bytes(content)
    db.execute('INSERT INTO cert_files(cert_id,filename,file_type,file_path,version,is_active,file_hash)VALUES(?,?,?,?,?,1,?)',
               (cid,f.filename,ft,str(sp),ver,fhash)); db.commit()
    if ft=='certificate':
        try:
            info=parse_cert_pem(content.decode('utf-8','ignore'))
            if info:
                db.execute("DELETE FROM cert_info WHERE cert_id=?",(cid,))
                db.execute('INSERT INTO cert_info(cert_id,subject,issuer,serial,not_before,not_after,san,key_size,signature_algorithm,is_ca)VALUES(?,?,?,?,?,?,?,?,?,?)',
                    (cid,info['subject'],info['issuer'],info['serial'],info['not_before'],info['not_after'],info['san'],info['key_size'],info['signature_algorithm'],info['is_ca']))
                db.commit()
        except: pass
    return jsonify({'ok':True,'version':ver})

@app.route('/api/certs/<int:cid>/files/<int:fid>', methods=['DELETE'])
@login_required
def delete_file(cid,fid):
    db=get_db(); row=db.execute("SELECT * FROM cert_files WHERE id=? AND cert_id=?",(fid,cid)).fetchone()
    if not row: return jsonify({'error':'Not found'}),404
    Path(row['file_path']).unlink(missing_ok=True); db.execute("DELETE FROM cert_files WHERE id=?",(fid,)); db.commit()
    return jsonify({'ok':True})

@app.route('/api/certs/<int:cid>/files/<int:fid>', methods=['PATCH'])
@login_required
def set_file_active(cid,fid):
    db=get_db(); d=request.get_json(); is_active=1 if d.get('is_active') else 0
    row=db.execute("SELECT * FROM cert_files WHERE id=? AND cert_id=?",(fid,cid)).fetchone()
    if not row: return jsonify({'error':'Not found'}),404
    # When activating, deactivate other files of the same type so only one is active
    if is_active:
        db.execute("UPDATE cert_files SET is_active=0 WHERE cert_id=? AND file_type=? AND id!=?",(cid,row['file_type'],fid))
    db.execute("UPDATE cert_files SET is_active=? WHERE id=?",(is_active,fid)); db.commit()
    return jsonify({'ok':True})

@app.route('/api/certs/<int:cid>/files/<int:fid>/download')
@login_required
def download_file(cid,fid):
    db=get_db(); row=db.execute("SELECT * FROM cert_files WHERE id=? AND cert_id=?",(fid,cid)).fetchone()
    if not row or not Path(row['file_path']).exists(): return jsonify({'error':'Not found'}),404
    return send_file(row['file_path'],as_attachment=True,download_name=row['filename'])

@app.route('/api/certs/<int:cid>/export', methods=['POST'])
@login_required
def export_cert(cid):
    db=get_db(); d=request.get_json(); fmt=d.get('format','zip'); pw=d.get('password','')
    crow=db.execute("SELECT * FROM certificates WHERE id=?",(cid,)).fetchone()
    if not crow: return jsonify({'error':'Not found'}),404
    files=db.execute("SELECT * FROM cert_files WHERE cert_id=? AND is_active=1",(cid,)).fetchall()
    fm={f['file_type']:f for f in files}
    stem=f"{crow['name'].replace(' ','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"; out=EXPORTS_DIR/stem
    try:
        if fmt=='zip':
            p=str(out)+'.zip'
            with zipfile.ZipFile(p,'w',zipfile.ZIP_DEFLATED) as zf:
                for f in files:
                    fp=Path(f['file_path'])
                    if fp.exists(): zf.write(fp,f"{f['file_type']}_{f['filename']}")
            return send_file(p,as_attachment=True,download_name=Path(p).name)
        elif fmt=='pem_bundle':
            parts=[]
            for ft in ['certificate','chain','key']:
                if ft in fm:
                    fp=Path(fm[ft]['file_path'])
                    if fp.exists(): parts.append(f"# {ft.upper()}\n{fp.read_text()}")
            p=str(out)+'_bundle.pem'; Path(p).write_text('\n'.join(parts))
            return send_file(p,as_attachment=True,download_name=Path(p).name)
        elif fmt in ('cert_only','chain_only','key_only'):
            key=fmt.replace('_only','').replace('cert','certificate')
            if key not in fm: return jsonify({'error':f'No {key}'}),400
            return send_file(str(Path(fm[key]['file_path'])),as_attachment=True,download_name=f"{stem}_{key}.pem")
        elif fmt=='pfx':
            if 'certificate' not in fm or 'key' not in fm: return jsonify({'error':'Need cert+key'}),400
            p=str(out)+'.pfx'
            cmd=['openssl','pkcs12','-export','-in',fm['certificate']['file_path'],'-inkey',fm['key']['file_path'],'-out',p,'-passout',f'pass:{pw}']
            if 'chain' in fm: cmd+=['-certfile',fm['chain']['file_path']]
            r=subprocess.run(cmd,capture_output=True,text=True,timeout=30)
            if r.returncode!=0: return jsonify({'error':r.stderr}),500
            return send_file(p,as_attachment=True,download_name=Path(p).name)
        elif fmt=='der':
            if 'certificate' not in fm: return jsonify({'error':'No cert'}),400
            p=str(out)+'.der'
            r=subprocess.run(['openssl','x509','-in',fm['certificate']['file_path'],'-out',p,'-outform','DER'],capture_output=True,text=True,timeout=30)
            if r.returncode!=0: return jsonify({'error':r.stderr}),500
            return send_file(p,as_attachment=True,download_name=Path(p).name)
        else: return jsonify({'error':'Unknown format'}),400
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/certs/<int:cid>/locations', methods=['POST'])
@login_required
def add_location(cid):
    db=get_db(); d=request.get_json()
    db.execute('INSERT INTO locations(cert_id,location_name,replacement_notes,responsible_person,contact_info)VALUES(?,?,?,?,?)',
               (cid,d.get('location_name',''),d.get('replacement_notes',''),d.get('responsible_person',''),d.get('contact_info',''))); db.commit()
    return jsonify({'id':db.execute('SELECT last_insert_rowid()').fetchone()[0]}),201

@app.route('/api/locations/<int:lid>', methods=['PUT'])
@login_required
def update_location(lid):
    db=get_db(); d=request.get_json()
    db.execute("UPDATE locations SET location_name=?,replacement_notes=?,responsible_person=?,contact_info=?,last_updated=strftime('%Y-%m-%d %H:%M:%S','now') WHERE id=?",
               (d.get('location_name'),d.get('replacement_notes',''),d.get('responsible_person',''),d.get('contact_info',''),lid)); db.commit()
    return jsonify({'ok':True})

@app.route('/api/locations/<int:lid>', methods=['DELETE'])
@login_required
def delete_location(lid):
    db=get_db(); db.execute("DELETE FROM locations WHERE id=?",(lid,)); db.commit(); return jsonify({'ok':True})

# ─── Certbot / Cloudflare ─────────────────────────────────────────────────────
@app.route('/api/certbot/check')
@login_required
def certbot_check():
    has_cb=bool(shutil.which('certbot')); has_pl=False
    if has_cb:
        r=subprocess.run(['certbot','plugins','--non-interactive'],capture_output=True,text=True,timeout=10)
        has_pl='dns-cloudflare' in r.stdout
    cf=get_db().execute("SELECT value FROM settings WHERE key='cf_api_token'").fetchone()
    return jsonify({'certbot':has_cb,'dns_cloudflare':has_pl,'cf_token_set':bool(cf and cf['value'])})

@app.route('/api/certbot/save-token', methods=['POST'])
@login_required
def certbot_save_token():
    d=request.get_json(); tok=d.get('cf_api_token','').strip()
    if not tok: return jsonify({'error':'Token required'}),400
    db=get_db(); db.execute("INSERT OR REPLACE INTO settings(key,value)VALUES('cf_api_token',?)",(tok,)); db.commit()
    return jsonify({'ok':True})

@app.route('/api/certbot/install-plugin', methods=['POST'])
@login_required
def certbot_install():
    try:
        r=subprocess.run(['pip3','install','certbot','certbot-dns-cloudflare','--break-system-packages'],capture_output=True,text=True,timeout=180)
        if r.returncode==0: return jsonify({'ok':True,'output':r.stdout[-2000:]})
        return jsonify({'error':(r.stderr or r.stdout)[-2000:]}),500
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/certbot/issue', methods=['POST'])
@login_required
def certbot_issue():
    db=get_db(); d=request.get_json()
    domain=d.get('domain','').strip(); email=d.get('email','').strip()
    staging=d.get('staging',False); wildcard=d.get('wildcard',False)
    if not domain or not email: return jsonify({'error':'Domain and email required'}),400
    cf=db.execute("SELECT value FROM settings WHERE key='cf_api_token'").fetchone()
    if not cf or not cf['value']: return jsonify({'error':'Cloudflare token not set'}),400
    cf_token=cf['value']
    db.execute("INSERT INTO certbot_jobs(domain)VALUES(?)",(domain,)); db.commit()
    job_id=db.execute("SELECT last_insert_rowid()").fetchone()[0]
    def run():
        with app.app_context():
            jdb=sqlite3.connect(DB_PATH); jdb.row_factory=sqlite3.Row
            cf_ini=BASE_DIR/f'.cf_{job_id}.ini'
            try:
                cf_ini.write_text(f"dns_cloudflare_api_token = {cf_token}\n"); cf_ini.chmod(0o600)
                doms=[domain]; 
                if wildcard: doms=[f'*.{domain}',domain]
                cmd=['certbot','certonly','--dns-cloudflare',
                     f'--dns-cloudflare-credentials={cf_ini}',
                     '--dns-cloudflare-propagation-seconds=60',
                     '--email',email,'--agree-tos','--non-interactive','--cert-name',domain]
                for dom in doms: cmd+=['-d',dom]
                if staging: cmd.append('--staging')
                res=subprocess.run(cmd,capture_output=True,text=True,timeout=300)
                out=(res.stdout+'\n'+res.stderr).strip()
                if res.returncode==0:
                    cp=Path(f'/etc/letsencrypt/live/{domain}')
                    cid=_import_le(domain,cp,jdb) if cp.exists() else None
                    jdb.execute("UPDATE certbot_jobs SET status='success',output=?,cert_id=?,completed_at=strftime('%Y-%m-%d %H:%M:%S','now') WHERE id=?",(out,cid,job_id))
                else:
                    jdb.execute("UPDATE certbot_jobs SET status='failed',output=?,completed_at=strftime('%Y-%m-%d %H:%M:%S','now') WHERE id=?",(out,job_id))
                jdb.commit()
            except Exception as e:
                jdb.execute("UPDATE certbot_jobs SET status='error',output=?,completed_at=strftime('%Y-%m-%d %H:%M:%S','now') WHERE id=?",(str(e),job_id)); jdb.commit()
            finally:
                try: cf_ini.unlink()
                except: pass
                jdb.close()
    threading.Thread(target=run,daemon=True).start()
    return jsonify({'ok':True,'job_id':job_id})

@app.route('/api/certbot/jobs')
@login_required
def certbot_jobs():
    rows=get_db().execute("SELECT * FROM certbot_jobs ORDER BY created_at DESC LIMIT 50").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/certbot/jobs/<int:jid>')
@login_required
def certbot_job_status(jid):
    row=get_db().execute("SELECT * FROM certbot_jobs WHERE id=?",(jid,)).fetchone()
    if not row: return jsonify({'error':'Not found'}),404
    return jsonify(dict(row))

def _import_le(domain,cert_path,db):
    folder=hashlib.md5(f"le-{domain}{time.time()}".encode()).hexdigest()[:12]
    dest=CERTS_DIR/folder
    try:
        row=db.execute("SELECT id,folder FROM certificates WHERE domain=?",(domain,)).fetchone()
        if row:
            cid=row['id']; dest=CERTS_DIR/row['folder']; dest.mkdir(exist_ok=True); is_ren=True
        else:
            dest.mkdir(exist_ok=True)
            db.execute("INSERT INTO certificates(name,domain,folder,tags,notify_days,color)VALUES(?,?,?,?,?,?)",
                       (f"Let's Encrypt — {domain}",domain,folder,json.dumps(['letsencrypt']),json.dumps([30,14,7]),'#00c8ff'))
            db.commit(); cid=db.execute("SELECT last_insert_rowid()").fetchone()[0]; is_ren=False
        for fname,ftype in [('cert.pem','certificate'),('privkey.pem','key'),('chain.pem','chain'),('fullchain.pem','other')]:
            src=cert_path/fname
            if not src.exists(): continue
            content=src.read_bytes(); fhash=hashlib.sha256(content).hexdigest()
            ex=db.execute("SELECT MAX(version) as mv FROM cert_files WHERE cert_id=? AND file_type=?",(cid,ftype)).fetchone()
            ver=(ex['mv'] or 0)+1
            if is_ren: db.execute("UPDATE cert_files SET is_active=0 WHERE cert_id=? AND file_type=?",(cid,ftype))
            sp=dest/f"{Path(fname).stem}_v{ver}.pem"; sp.write_bytes(content)
            db.execute('INSERT INTO cert_files(cert_id,filename,file_type,file_path,version,is_active,file_hash)VALUES(?,?,?,?,?,1,?)',(cid,fname,ftype,str(sp),ver,fhash))
        cp=cert_path/'cert.pem'
        if cp.exists():
            info=parse_cert_pem(cp.read_text())
            if info:
                db.execute("DELETE FROM cert_info WHERE cert_id=?",(cid,))
                db.execute('INSERT INTO cert_info(cert_id,subject,issuer,serial,not_before,not_after,san,key_size,signature_algorithm,is_ca)VALUES(?,?,?,?,?,?,?,?,?,?)',
                    (cid,info['subject'],info['issuer'],info['serial'],info['not_before'],info['not_after'],info['san'],info['key_size'],info['signature_algorithm'],info['is_ca']))
        db.commit()
    except Exception as e: print(f"LE import error: {e}")
    return cid

# ─── Notifications ────────────────────────────────────────────────────────────
@app.route('/api/notify/test', methods=['POST'])
@login_required
def test_notification():
    d=request.get_json(); wh=d.get('webhook_url','')
    if not wh: return jsonify({'error':'No URL'}),400
    try:
        import urllib.request
        req=urllib.request.Request(wh,data=json.dumps({'text':'🔔 *CertVault* — webhook OK!'}).encode(),headers={'Content-Type':'application/json'})
        urllib.request.urlopen(req,timeout=5); return jsonify({'ok':True})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/notify/run', methods=['POST'])
@login_required
def run_notifications(): return jsonify({'sent':check_and_notify()})

def check_and_notify():
    sent=[]
    with app.app_context():
        db=sqlite3.connect(DB_PATH); db.row_factory=sqlite3.Row; now=datetime.now(timezone.utc)
        for cert in db.execute("SELECT c.*,ci.not_after FROM certificates c LEFT JOIN cert_info ci ON c.id=ci.cert_id WHERE c.notify_slack!='' AND ci.not_after IS NOT NULL").fetchall():
            exp=parse_ts(cert['not_after'])
            if not exp: continue
            dl=(exp-now).days; ndays=json.loads(cert['notify_days'] or '[30,14,7]')
            if dl not in ndays: continue
            already=db.execute("SELECT id FROM notification_log WHERE cert_id=? AND days_remaining=? AND DATE(sent_at)=DATE('now')",(cert['id'],dl)).fetchone()
            if already: continue
            emoji='🔴' if dl<=7 else '🟡' if dl<=14 else '🟠'; status='sent'
            try:
                import urllib.request
                msg={'text':f'{emoji} *CertVault: Cert Expiring*','attachments':[{'color':'#ff4444' if dl<=7 else '#ff8c00',
                    'fields':[{'title':'Cert','value':cert['name'],'short':True},{'title':'Domain','value':cert['domain'],'short':True},
                               {'title':'Days','value':str(dl),'short':True},{'title':'Expires','value':exp.strftime('%Y-%m-%d'),'short':True}]}]}
                req=urllib.request.Request(cert['notify_slack'],data=json.dumps(msg).encode(),headers={'Content-Type':'application/json'})
                urllib.request.urlopen(req,timeout=5)
            except Exception as e: status=f'error:{e}'
            db.execute("INSERT INTO notification_log(cert_id,days_remaining,status)VALUES(?,?,?)",(cert['id'],dl,status)); db.commit()
            sent.append({'cert':cert['name'],'days':dl,'status':status})
        db.close()
    return sent


# ─── Password Generator ───────────────────────────────────────────────────────
@app.route('/api/generate_password', methods=['POST'])
@login_required
def generate_password():
    d = request.get_json() or {}
    length   = max(8, min(128, int(d.get('length', 24))))
    use_up   = d.get('uppercase', True)
    use_lo   = d.get('lowercase', True)
    use_di   = d.get('digits', True)
    use_sp   = d.get('special', True)
    charset  = ''; required = []
    if use_up:  charset += string.ascii_uppercase; required.append(secrets.choice(string.ascii_uppercase))
    if use_lo:  charset += string.ascii_lowercase; required.append(secrets.choice(string.ascii_lowercase))
    if use_di:  charset += string.digits;          required.append(secrets.choice(string.digits))
    if use_sp:
        sp = '!@#$%^&*()_+-=[]{}|;:,.<>?'
        charset += sp; required.append(secrets.choice(sp))
    if not charset: return jsonify({'error': 'Select at least one character type'}), 400
    rest = [secrets.choice(charset) for _ in range(length - len(required))]
    pw = required + rest; secrets.SystemRandom().shuffle(pw)
    return jsonify({'password': ''.join(pw)})

# ─── Settings ─────────────────────────────────────────────────────────────────
@app.route('/api/settings', methods=['GET'])
@login_required
def get_settings():
    db=get_db(); rows=db.execute("SELECT key,value FROM settings WHERE key!='cf_api_token'").fetchall()
    d={r['key']:r['value'] for r in rows}
    cf=db.execute("SELECT value FROM settings WHERE key='cf_api_token'").fetchone()
    d['cf_token_set']=bool(cf and cf['value']); return jsonify(d)

@app.route('/api/settings', methods=['POST'])
@login_required
def save_settings():
    db=get_db(); d=request.get_json()
    for k,v in d.items():
        if k=='cf_api_token' and not v: continue
        db.execute("INSERT OR REPLACE INTO settings(key,value)VALUES(?,?)",(k,v))
    db.commit(); return jsonify({'ok':True})

# ─── Stats ────────────────────────────────────────────────────────────────────
@app.route('/api/stats')
@login_required
def get_stats():
    db=get_db(); now=datetime.now(timezone.utc)
    tot=db.execute("SELECT COUNT(*) as c FROM certificates").fetchone()['c']
    cnt={'expired':0,'critical':0,'warning':0,'ok':0,'unknown':0}
    for r in db.execute("SELECT not_after FROM cert_info").fetchall():
        exp=parse_ts(r['not_after'])
        if not exp: cnt['unknown']+=1; continue
        d=(exp-now).days; cnt['expired' if d<0 else 'critical' if d<=7 else 'warning' if d<=30 else 'ok']+=1
    tags={}
    for r in db.execute("SELECT tags FROM certificates").fetchall():
        for t in json.loads(r['tags'] or '[]'): tags[t]=tags.get(t,0)+1
    return jsonify({'total':tot,'expiry':cnt,'tags':tags})

def notification_scheduler():
    while True:
        try: check_and_notify()
        except: pass
        time.sleep(3600)

if __name__=='__main__':
    init_db(); migrate_db()
    threading.Thread(target=notification_scheduler,daemon=True).start()
    port=int(os.environ.get('PORT',5000))
    print(f"\n🔐 CertVault running at http://0.0.0.0:{port}\n")
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    app.run(host=host, port=port, debug=False)
