"""
Sentinel Zero Trust Backend — Production (Render)
==================================================
Changes for Render deployment:
  - DB_PATH read from env var (points to persistent disk at /data/sentinel.db)
  - SESSION_COOKIE_SAMESITE='None' + SECURE=True — required for cross-origin
    cookies when frontend (sentinel-zero-trust-vault.vercel.app) and backend
    (sentinel-zero-trust-vault.onrender.com) are on different domains.
    SameSite=Lax silently drops cookies on cross-origin POST requests.
  - Gunicorn-compatible: no app.run() block needed, but kept for local dev
  - init_db() called at module level so Gunicorn workers initialize the DB
"""

import sqlite3
import time
import os
import hmac
import secrets
from functools import wraps
from flask import Flask, request, jsonify, g, render_template, session, redirect, url_for, flash
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# ------------------------------------------------------------------ #
#  SECRET KEY — env preferred, demo fallback for one-click deploys    #
# ------------------------------------------------------------------ #
app.secret_key = os.environ.get('SECRET_KEY', 'sentinel-demo-secret-change-me')

# ------------------------------------------------------------------ #
#  Environment flags                                                  #
# ------------------------------------------------------------------ #
_is_prod = os.environ.get('FLASK_ENV', 'development') == 'production'

# ------------------------------------------------------------------ #
#  Cookie config                                                      #
#  RENDER-SPECIFIC: SameSite=None is required because the frontend    #
#  and backend are on different subdomains of onrender.com.           #
#  SameSite=None requires Secure=True (HTTPS only).                   #
#  Render always uses HTTPS, so this is safe.                         #
# ------------------------------------------------------------------ #
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='None' if _is_prod else 'Lax',
    SESSION_COOKIE_SECURE=_is_prod,   # True in prod (HTTPS), False locally
)

# ------------------------------------------------------------------ #
#  CORS — single call, origins from env var                           #
# ------------------------------------------------------------------ #
_allowed_origins = [
    o.strip()
    for o in os.environ.get(
        'CORS_ORIGINS',
        'http://localhost:5173,http://127.0.0.1:5173,https://sentinel-zero-trust-vault.vercel.app'
    ).split(',')
    if o.strip()
]

CORS(app, supports_credentials=True, origins=_allowed_origins)

# ------------------------------------------------------------------ #
#  Database path — env var allows Render's persistent disk            #
# ------------------------------------------------------------------ #
DB_PATH = os.environ.get('DB_PATH', os.path.join(os.path.dirname(__file__), 'sentinel.db'))
SESSION_TIMEOUT = 15 * 60

# ------------------------------------------------------------------ #
#  Rate Limiter (sliding window, in-memory per worker)                #
# ------------------------------------------------------------------ #
_RATE_LIMIT_STORE: dict = {}

def check_rate_limit(ip: str, limit: int = 5, window: int = 60) -> bool:
    now = time.time()
    _RATE_LIMIT_STORE.setdefault(ip, [])
    _RATE_LIMIT_STORE[ip] = [t for t in _RATE_LIMIT_STORE[ip] if now - t < window]
    if len(_RATE_LIMIT_STORE[ip]) >= limit:
        return False
    _RATE_LIMIT_STORE[ip].append(now)
    return True

# ------------------------------------------------------------------ #
#  Auth DB — hardcoded demo credentials                               #
# ------------------------------------------------------------------ #
def _build_auth_db() -> dict:
    raw = {
        "admin1": {"pass": "Admin@123", "role": "Admin",     "id": "u1", "name": "Alice Admin"},
        "hr1":    {"pass": "HR@123",    "role": "HR",        "id": "u3", "name": "Charlie HR"},
        "dev1":   {"pass": "Dev@123",   "role": "Developer", "id": "u2", "name": "Bob Dev"},
        "fin1":   {"pass": "Fin@123",   "role": "Finance",   "id": "u4", "name": "Dana Finance"},
    }

    return {
        username: {
            "hash": generate_password_hash(data["pass"], method="pbkdf2:sha256"),
            "role": data["role"], "id": data["id"],
            "name": data["name"], "username": username,
        }
        for username, data in raw.items()
    }

AUTH_DB = _build_auth_db()
_DUMMY_HASH = generate_password_hash("__sentinel_canary__", method="pbkdf2:sha256")

# ------------------------------------------------------------------ #
#  Document Registry                                                  #
# ------------------------------------------------------------------ #
DOCUMENTS = {
    'd1':  {'title': 'Company Handbook',             'classification': 'Public',       'department': 'General'},
    'd2':  {'title': 'Q3 Financial Report',          'classification': 'Confidential', 'department': 'Finance'},
    'd3':  {'title': 'Employee Salaries',            'classification': 'Restricted',   'department': 'HR'},
    'd4':  {'title': 'Project Sentinel Source Code', 'classification': 'Internal',     'department': 'Developer'},
    'd5':  {'title': 'Admin Credentials Backup',     'classification': 'Restricted',   'department': 'Admin'},
    'd6':  {'title': 'Office Floor Plan',            'classification': 'Internal',     'department': 'General'},
    'd7':  {'title': 'Merger Strategy 2025',         'classification': 'Restricted',   'department': 'Finance'},
    'd8':  {'title': 'API Documentation',            'classification': 'Public',       'department': 'Developer'},
    'd9':  {'title': 'Termination Policy',           'classification': 'Confidential', 'department': 'HR'},
    'd10': {'title': 'Audit Logs 2024',              'classification': 'Confidential', 'department': 'Admin'},
}
_VALID_DOC_IDS = frozenset(DOCUMENTS.keys())

# ------------------------------------------------------------------ #
#  Access Policy Engine                                               #
# ------------------------------------------------------------------ #
def check_policy_engine(role: str, doc: dict) -> tuple[bool, str]:
    c = doc['classification']
    d = doc['department']
    if c == 'Public':       return True,  "Public Classification"
    if role == 'Admin':     return True,  "Admin Override [AUDITED]"
    same = (d == 'General') or (d == role)
    if c == 'Internal':     return True,  "Internal Access Policy"
    if c == 'Confidential': return (True, "Role-Based Access") if same else (False, "Department Mismatch")
    if c == 'Restricted':   return False, "Restricted: Escalation Required"
    return False, "Implicit Deny"

# ------------------------------------------------------------------ #
#  Database                                                           #
# ------------------------------------------------------------------ #
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    # Ensure the directory exists (needed for /data on Render)
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS access_logs (
            id              TEXT PRIMARY KEY,
            timestamp       REAL NOT NULL,
            user_id         TEXT NOT NULL,
            user_name       TEXT NOT NULL,
            user_role       TEXT NOT NULL,
            doc_id          TEXT NOT NULL,
            doc_title       TEXT NOT NULL,
            access_result   TEXT NOT NULL,
            reason          TEXT NOT NULL,
            is_admin_access INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()
    print(f"[Sentinel] DB initialized at {DB_PATH}")

def log_access_event(user_id, user_name, user_role, doc_id, doc_title, result, reason):
    try:
        conn = get_db()
        conn.execute(
            'INSERT INTO access_logs VALUES (?,?,?,?,?,?,?,?,?,?)',
            (secrets.token_hex(8), time.time(), user_id, user_name, user_role,
             doc_id, doc_title, result, reason, 1 if user_role == 'Admin' else 0)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Sentinel] Log error: {e}")

def detect_insider_threat(user_id: str) -> bool:
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute(
            "SELECT COUNT(*) FROM access_logs WHERE user_id=? AND access_result='DENIED' AND timestamp>?",
            (user_id, time.time() - 60)
        )
        count = c.fetchone()[0]
        conn.close()
        return count >= 3
    except Exception:
        return False

def get_flagged_users():
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute(
            """SELECT user_id, user_name, COUNT(*) as deny_count
               FROM access_logs WHERE access_result='DENIED' AND timestamp>?
               GROUP BY user_id HAVING deny_count >= 3""",
            (time.time() - 60,)
        )
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []

# ------------------------------------------------------------------ #
#  CSRF                                                               #
# ------------------------------------------------------------------ #
_CSRF_EXEMPT = frozenset({'/login', '/logout', '/api/me'})

def _validate_csrf():
    if request.path in _CSRF_EXEMPT or request.method in ('GET', 'OPTIONS', 'HEAD'):
        return
    client  = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token', '')
    stored  = session.get('csrf_token', '')
    if not client or not stored:
        return jsonify({'error': 'CSRF token missing'}), 403
    if not hmac.compare_digest(client, stored):
        return jsonify({'error': 'CSRF token invalid'}), 403

app.before_request(_validate_csrf)

# ------------------------------------------------------------------ #
#  Session middleware                                                  #
# ------------------------------------------------------------------ #
@app.before_request
def extract_identity():
    if request.method == 'OPTIONS':
        return
    if 'user_id' in session:
        now = time.time()
        if now - session.get('last_active', now) > SESSION_TIMEOUT:
            session.clear()
            g.user_id = None
            return
        session['last_active'] = now
        g.user_id   = session['user_id']
        g.user_name = session['user_name']
        g.user_role = session['user_role']
    else:
        g.user_id = None

# ------------------------------------------------------------------ #
#  Routes                                                             #
# ------------------------------------------------------------------ #

@app.route('/api/me', methods=['GET'])
def get_current_user():
    if not g.user_id:
        return jsonify({'authenticated': False}), 401
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return jsonify({
        'authenticated': True,
        'csrf_token': session['csrf_token'],
        'user': {'id': g.user_id, 'name': g.user_name, 'role': g.user_role}
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    if not check_rate_limit(ip):
        msg = 'Too many login attempts. Try again later.'
        return (jsonify({'error': msg}), 429) if request.is_json else (render_template('login.html'), 429)

    if request.method == 'POST':
        if request.is_json:
            d = request.get_json(silent=True) or {}
            username_input, password_input = d.get('username', ''), d.get('password', '')
        else:
            username_input = request.form.get('username', '')
            password_input = request.form.get('password', '')

        user_key = next((k for k in AUTH_DB if k.lower() == username_input.lower()), None)
        user     = AUTH_DB.get(user_key)
        ok       = check_password_hash(user['hash'] if user else _DUMMY_HASH, password_input)

        if user and ok:
            session.clear()
            session.update({
                'user_id': user['id'], 'user_name': user['name'],
                'user_role': user['role'], 'last_active': time.time(),
                'csrf_token': secrets.token_hex(32),
            })
            if request.is_json:
                return jsonify({
                    'success': True,
                    'csrf_token': session['csrf_token'],
                    'user': {k: user[k] for k in ('id', 'name', 'role')}
                })
            return redirect(url_for('dashboard_view'))

        if request.is_json:
            return jsonify({'error': 'Invalid credentials'}), 401
        flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    return jsonify({'success': True}) if request.is_json else redirect(url_for('login'))

@app.route('/dashboard')
def dashboard_view():
    if 'user_id' not in session or session.get('user_role') != 'Admin':
        return redirect(url_for('login'))
    return render_template('dashboard.html',
                           user_name=session.get('user_name'),
                           user_role=session.get('user_role'))

@app.route('/api/access', methods=['POST'])
def request_access():
    if not g.user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    data   = request.get_json(silent=True) or {}
    doc_id = data.get('documentId', '')

    if not isinstance(doc_id, str) or doc_id not in _VALID_DOC_IDS:
        return jsonify({'error': 'Document not found'}), 404

    doc            = DOCUMENTS[doc_id]
    allowed, reason = check_policy_engine(g.user_role, doc)
    result         = 'ALLOWED' if allowed else 'DENIED'

    log_access_event(g.user_id, g.user_name, g.user_role, doc_id, doc['title'], result, reason)
    is_threat = detect_insider_threat(g.user_id)

    return jsonify({
        'access': result, 'reason': reason,
        'threat_detected': is_threat,
        'document': doc if allowed else None
    })

@app.route('/api/admin/stats', methods=['GET'])
def get_admin_stats():
    if not g.user_id or g.user_role != 'Admin':
        return jsonify({'error': 'Forbidden'}), 403

    conn = get_db()
    c    = conn.cursor()
    c.execute('SELECT COUNT(*) FROM access_logs')
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM access_logs WHERE access_result='DENIED'")
    denied = c.fetchone()[0]
    c.execute("SELECT * FROM access_logs WHERE access_result='DENIED' ORDER BY timestamp DESC LIMIT 10")
    violations = [dict(r) for r in c.fetchall()]
    conn.close()

    return jsonify({
        'total_requests': total, 'denied_requests': denied,
        'violations': violations, 'threats': get_flagged_users()
    })

# ------------------------------------------------------------------ #
#  Initialize DB at module load (works for both Gunicorn and dev)     #
# ------------------------------------------------------------------ #
init_db()

if __name__ == '__main__':
    _debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5001)), debug=_debug)
