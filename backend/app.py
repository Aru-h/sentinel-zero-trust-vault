import base64
import hmac
import os
import secrets
import sqlite3
import time
from functools import wraps

from cryptography.fernet import Fernet
from flask import Flask, g, jsonify, redirect, render_template, request, session, url_for
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'sentinel-demo-secret-change-me')

_is_prod = os.environ.get('FLASK_ENV', 'development') == 'production'
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='None' if _is_prod else 'Lax',
    SESSION_COOKIE_SECURE=_is_prod,
)

_allowed_origins = [
    o.strip() for o in os.environ.get(
        'CORS_ORIGINS',
        'http://localhost:5173,http://127.0.0.1:5173,https://sentinel-zero-trust-vault.vercel.app'
    ).split(',') if o.strip()
]
CORS(app, supports_credentials=True, origins=_allowed_origins)

DB_PATH = os.environ.get('DB_PATH', os.path.join(os.path.dirname(__file__), 'sentinel.db'))
SESSION_TIMEOUT = 15 * 60
BLOCKED_USERS: set[str] = set()
ACTIVE_SESSIONS: dict[str, str] = {}
ACCESS_EVENTS: list[dict] = []
ACCESS_REQUESTS: list[dict] = []
TEMP_APPROVALS: dict[str, dict] = {}
REQUEST_RATE_TRACKER: dict[str, list[float]] = {}
_RATE_LIMIT_STORE: dict[str, list[float]] = {}

CLASSIFICATION_CLEARANCE = {
    'Public': 1,
    'Internal': 2,
    'Confidential': 3,
    'Restricted': 4,
}


def _load_fernet() -> Fernet:
    raw_key = os.environ.get('ENCRYPTION_KEY', '').strip()
    if raw_key:
        return Fernet(raw_key.encode())
    runtime_key = Fernet.generate_key()
    print('[Sentinel] WARNING: ENCRYPTION_KEY missing, using runtime-only key')
    return Fernet(runtime_key)


FERNET = _load_fernet()


SEED_USERS = [
    {'username': 'admin1', 'password': 'Admin@123', 'name': 'Alice Admin', 'department': 'admin', 'role': 'Admin', 'role_title': 'admin', 'clearance_level': 5, 'id': 'u1'},
    {'username': 'hr_head', 'password': 'HRHead@123', 'name': 'Hannah HR Head', 'department': 'hr', 'role': 'HR', 'role_title': 'head', 'clearance_level': 4, 'id': 'u2'},
    {'username': 'hr_emp', 'password': 'HREmp@123', 'name': 'Henry HR Employee', 'department': 'hr', 'role': 'HR', 'role_title': 'employee', 'clearance_level': 3, 'id': 'u3'},
    {'username': 'hr_int', 'password': 'HRInt@123', 'name': 'Hazel HR Intern', 'department': 'hr', 'role': 'HR', 'role_title': 'intern', 'clearance_level': 2, 'id': 'u4'},
    {'username': 'fin_head', 'password': 'FinHead@123', 'name': 'Fiona Finance Head', 'department': 'finance', 'role': 'Finance', 'role_title': 'head', 'clearance_level': 4, 'id': 'u5'},
    {'username': 'fin_emp', 'password': 'FinEmp@123', 'name': 'Frank Finance Employee', 'department': 'finance', 'role': 'Finance', 'role_title': 'employee', 'clearance_level': 3, 'id': 'u6'},
    {'username': 'fin_int', 'password': 'FinInt@123', 'name': 'Faith Finance Intern', 'department': 'finance', 'role': 'Finance', 'role_title': 'intern', 'clearance_level': 2, 'id': 'u7'},
    {'username': 'dev_head', 'password': 'DevHead@123', 'name': 'Derek Dev Head', 'department': 'dev', 'role': 'Developer', 'role_title': 'head', 'clearance_level': 4, 'id': 'u8'},
    {'username': 'dev_emp', 'password': 'DevEmp@123', 'name': 'Diana Dev Employee', 'department': 'dev', 'role': 'Developer', 'role_title': 'employee', 'clearance_level': 3, 'id': 'u9'},
    {'username': 'dev_int', 'password': 'DevInt@123', 'name': 'Daniel Dev Intern', 'department': 'dev', 'role': 'Developer', 'role_title': 'intern', 'clearance_level': 2, 'id': 'u10'},
]

SEED_DOCS = [
    ('d1', 'Company Handbook', 'Public', 'hr', 'Corporate handbook and leave policy.'),
    ('d2', 'Q3 Financial Report', 'Confidential', 'finance', 'Quarterly revenue, cost and forecast data.'),
    ('d3', 'Employee Salaries', 'Restricted', 'hr', 'Compensation ledger and salary adjustment notes.'),
    ('d4', 'Project Sentinel Source Code', 'Internal', 'dev', 'Repository map and secure module architecture.'),
    ('d5', 'Admin Credentials Backup', 'Restricted', 'admin', 'Administrative credential recovery vault procedures.'),
    ('d6', 'Office Floor Plan', 'Internal', 'hr', 'Office floor and emergency path plan.'),
    ('d7', 'Merger Strategy 2025', 'Restricted', 'finance', 'M&A strategy, due diligence and capital plan.'),
    ('d8', 'API Documentation', 'Public', 'dev', 'Public API integration guide and usage examples.'),
    ('d9', 'Termination Policy', 'Confidential', 'hr', 'Employee termination policy and legal checklist.'),
    ('d10', 'Audit Logs 2024', 'Confidential', 'admin', 'Security and compliance audit event review for 2024.'),
]


def encrypt_document(plaintext: str) -> bytes:
    return FERNET.encrypt(plaintext.encode('utf-8'))


def decrypt_document(ciphertext: bytes) -> str:
    return FERNET.decrypt(ciphertext).decode('utf-8')


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def check_rate_limit(ip: str, limit: int = 5, window: int = 60) -> bool:
    now = time.time()
    _RATE_LIMIT_STORE.setdefault(ip, [])
    _RATE_LIMIT_STORE[ip] = [t for t in _RATE_LIMIT_STORE[ip] if now - t < window]
    if len(_RATE_LIMIT_STORE[ip]) >= limit:
        return False
    _RATE_LIMIT_STORE[ip].append(now)
    return True


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            department TEXT NOT NULL,
            role_title TEXT NOT NULL,
            clearance_level INTEGER NOT NULL
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS documents (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            classification TEXT NOT NULL,
            department TEXT NOT NULL,
            required_clearance INTEGER NOT NULL,
            encrypted_content BLOB NOT NULL
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS access_logs (
            id TEXT PRIMARY KEY,
            timestamp REAL NOT NULL,
            user_id TEXT NOT NULL,
            user_name TEXT NOT NULL,
            user_role TEXT NOT NULL,
            doc_id TEXT NOT NULL,
            doc_title TEXT NOT NULL,
            access_result TEXT NOT NULL,
            reason TEXT NOT NULL,
            is_admin_access INTEGER DEFAULT 0
        )
    ''')

    if conn.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0:
        for u in SEED_USERS:
            conn.execute(
                'INSERT INTO users VALUES (?,?,?,?,?,?,?,?)',
                (
                    u['id'], u['username'], u['name'],
                    generate_password_hash(u['password'], method='pbkdf2:sha256'),
                    u['role'], u['department'], u['role_title'], u['clearance_level'],
                )
            )
    if conn.execute('SELECT COUNT(*) FROM documents').fetchone()[0] == 0:
        for doc_id, title, classification, department, plaintext in SEED_DOCS:
            conn.execute(
                'INSERT INTO documents VALUES (?,?,?,?,?,?)',
                (doc_id, title, classification, department, CLASSIFICATION_CLEARANCE[classification], encrypt_document(plaintext)),
            )
    conn.commit()
    conn.close()


def load_auth_db() -> dict:
    conn = get_db()
    rows = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    return {r['username']: dict(r) for r in rows}


def get_document(doc_id: str):
    conn = get_db()
    row = conn.execute('SELECT * FROM documents WHERE id=?', (doc_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def cleanup_expired_tokens() -> None:
    now = time.time()
    expired = [token for token, payload in TEMP_APPROVALS.items() if payload['expires_at'] <= now]
    for token in expired:
        payload = TEMP_APPROVALS.pop(token)
        log_access_event(
            payload['user'],
            payload['user'],
            'TokenSystem',
            payload['document_id'],
            'temporary_grant',
            'TOKEN_EXPIRED',
            'token_expired',
        )


def log_access_event(user_id, user_name, user_role, doc_id, doc_title, result, reason):
    ACCESS_EVENTS.append({'timestamp': time.time(), 'user_id': user_id, 'doc_id': doc_id, 'result': result, 'reason': reason})
    try:
        conn = get_db()
        conn.execute(
            'INSERT INTO access_logs VALUES (?,?,?,?,?,?,?,?,?,?)',
            (secrets.token_hex(8), time.time(), user_id, user_name, user_role, doc_id, doc_title, result, reason, 1 if user_role == 'Admin' else 0),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f'[Sentinel] Log error: {e}')


def detect_insider_threat(user_id: str) -> bool:
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM access_logs WHERE user_id=? AND access_result='DENIED' AND timestamp>?", (user_id, time.time() - 60))
    count = c.fetchone()[0]
    conn.close()
    return count >= 3


def get_flagged_users():
    conn = get_db()
    c = conn.cursor()
    c.execute(
        """SELECT user_id, user_name, COUNT(*) as deny_count
           FROM access_logs WHERE access_result='DENIED' AND timestamp>?
           GROUP BY user_id HAVING deny_count >= 3""",
        (time.time() - 60,),
    )
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def evaluate_access_policy(user: dict, doc: dict, approval_token: str | None) -> tuple[bool, str, bool]:
    cleanup_expired_tokens()

    if user['role_title'] == 'admin':
        return True, 'Admin Override [AUDITED]', False
    if user['id'] in BLOCKED_USERS:
        return False, 'User blocked by admin', False
    if user['department'] != doc['department']:
        return False, 'Department isolation policy denied access', False
    if int(user['clearance_level']) < int(doc['required_clearance']):
        return False, 'Clearance level insufficient for document', False
    if doc['classification'] == 'Restricted':
        if not approval_token:
            return False, 'Restricted: escalation token required', True
        grant = TEMP_APPROVALS.get(approval_token)
        if not grant:
            return False, 'Invalid temporary approval token', True
        if grant['expires_at'] <= time.time():
            TEMP_APPROVALS.pop(approval_token, None)
            log_access_event(user['id'], user['name'], user['role'], doc['id'], doc['title'], 'TOKEN_EXPIRED', 'token_expired')
            return False, 'Temporary approval token expired', True
        if grant['user'] != user['id'] or grant['document_id'] != doc['id']:
            return False, 'Temporary token does not match user/document', True
        log_access_event(user['id'], user['name'], user['role'], doc['id'], doc['title'], 'TOKEN_USED', 'token_used')
    return True, 'Policy checks passed', False


_CSRF_EXEMPT = frozenset({'/login', '/logout', '/api/me'})


def _validate_csrf():
    if request.path in _CSRF_EXEMPT or request.method in ('GET', 'OPTIONS', 'HEAD'):
        return
    client = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token', '')
    stored = session.get('csrf_token', '')
    if not client or not stored:
        return jsonify({'error': 'CSRF token missing'}), 403
    if not hmac.compare_digest(client, stored):
        return jsonify({'error': 'CSRF token invalid'}), 403


app.before_request(_validate_csrf)


@app.before_request
def extract_identity():
    if request.method == 'OPTIONS':
        return
    if 'user_id' in session:
        now = time.time()
        expected_session_id = ACTIVE_SESSIONS.get(session['user_id'])
        if not expected_session_id or expected_session_id != session.get('session_id'):
            session.clear()
            g.user_id = None
            return
        if now - session.get('last_active', now) > SESSION_TIMEOUT:
            ACTIVE_SESSIONS.pop(session['user_id'], None)
            session.clear()
            g.user_id = None
            return
        session['last_active'] = now
        g.user_id = session['user_id']
        g.user_name = session['user_name']
        g.user_role = session['user_role']
        g.department = session['department']
        g.role_title = session['role_title']
        g.clearance_level = session['clearance_level']
    else:
        g.user_id = None


@app.route('/api/me', methods=['GET'])
def get_current_user():
    if not g.user_id:
        return jsonify({'authenticated': False}), 401
    if g.user_id in BLOCKED_USERS:
        ACTIVE_SESSIONS.pop(g.user_id, None)
        session.clear()
        return jsonify({'error': 'User blocked by admin'}), 403
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return jsonify({'authenticated': True, 'csrf_token': session['csrf_token'], 'user': {
        'id': g.user_id, 'name': g.user_name, 'role': g.user_role,
        'department': g.department, 'role_title': g.role_title, 'clearance_level': g.clearance_level,
    }})


@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    if not check_rate_limit(ip):
        msg = 'Too many login attempts. Try again later.'
        return (jsonify({'error': msg}), 429) if request.is_json else (render_template('login.html'), 429)

    if request.method == 'POST':
        data = request.get_json(silent=True) or {} if request.is_json else request.form
        username_input = data.get('username', '')
        password_input = data.get('password', '')

        auth_db = load_auth_db()
        user_key = next((k for k in auth_db if k.lower() == str(username_input).lower()), None)
        user = auth_db.get(user_key)
        dummy_hash = generate_password_hash('__sentinel_canary__', method='pbkdf2:sha256')
        ok = check_password_hash(user['password_hash'] if user else dummy_hash, password_input)

        if user and ok:
            session_id = secrets.token_hex(16)
            session.clear()
            session.update({
                'user_id': user['id'], 'user_name': user['name'], 'user_role': user['role'],
                'department': user['department'], 'role_title': user['role_title'], 'clearance_level': user['clearance_level'],
                'last_active': time.time(), 'csrf_token': secrets.token_hex(32), 'session_id': session_id,
            })
            ACTIVE_SESSIONS[user['id']] = session_id
            payload = {
                'success': True,
                'csrf_token': session['csrf_token'],
                'user': {
                    'id': user['id'], 'name': user['name'], 'role': user['role'], 'department': user['department'],
                    'role_title': user['role_title'], 'clearance_level': user['clearance_level'],
                },
            }
            return jsonify(payload) if request.is_json else redirect(url_for('dashboard_view'))

        if request.is_json:
            return jsonify({'error': 'Invalid credentials'}), 401

    return render_template('login.html')


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if session.get('user_id'):
        ACTIVE_SESSIONS.pop(session['user_id'], None)
    session.clear()
    return jsonify({'success': True}) if request.is_json else redirect(url_for('login'))


@app.route('/dashboard')
def dashboard_view():
    if 'user_id' not in session or session.get('role_title') != 'admin':
        return redirect(url_for('login'))
    return render_template('dashboard.html', user_name=session.get('user_name'), user_role=session.get('user_role'))


@app.route('/api/access', methods=['POST'])
def access_document():
    if not g.user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    if g.user_id in BLOCKED_USERS:
        ACTIVE_SESSIONS.pop(g.user_id, None)
        session.clear()
        return jsonify({'error': 'User blocked by admin'}), 403

    data = request.get_json(silent=True) or {}
    doc_id = data.get('documentId', '')
    approval_token = data.get('approvalToken', '') or request.headers.get('X-Approval-Token', '')

    if not isinstance(doc_id, str):
        return jsonify({'error': 'Document not found'}), 404

    doc = get_document(doc_id)
    if not doc:
        return jsonify({'error': 'Document not found'}), 404

    user = {
        'id': g.user_id, 'name': g.user_name, 'role': g.user_role,
        'department': g.department, 'role_title': g.role_title, 'clearance_level': g.clearance_level,
    }
    allowed, reason, restricted_flow = evaluate_access_policy(user, doc, approval_token)

    result = 'ALLOWED' if allowed else 'DENIED'
    log_access_event(g.user_id, g.user_name, g.user_role, doc_id, doc['title'], result, reason)
    is_threat = detect_insider_threat(g.user_id)

    response_doc = None
    if allowed:
        decrypted = decrypt_document(doc['encrypted_content'])
        response_doc = {
            'id': doc['id'], 'title': doc['title'], 'classification': doc['classification'],
            'department': doc['department'], 'required_clearance': doc['required_clearance'], 'content': decrypted,
        }

    return jsonify({'access': result, 'reason': reason, 'threat_detected': is_threat, 'requires_escalation': restricted_flow, 'document': response_doc})


@app.route('/api/request-access', methods=['POST'])
def request_temporary_access():
    if not g.user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    if g.user_id in BLOCKED_USERS:
        ACTIVE_SESSIONS.pop(g.user_id, None)
        session.clear()
        return jsonify({'error': 'User blocked by admin'}), 403

    data = request.get_json(silent=True) or {}
    doc_id = data.get('documentId', '')
    if not isinstance(doc_id, str):
        return jsonify({'error': 'Document not found'}), 404

    doc = get_document(doc_id)
    if not doc:
        return jsonify({'error': 'Document not found'}), 404

    now = time.time()
    REQUEST_RATE_TRACKER.setdefault(g.user_id, [])
    REQUEST_RATE_TRACKER[g.user_id] = [t for t in REQUEST_RATE_TRACKER[g.user_id] if now - t < 3600]
    if len(REQUEST_RATE_TRACKER[g.user_id]) >= 5:
        return jsonify({'error': 'Request limit exceeded'}), 429

    REQUEST_RATE_TRACKER[g.user_id].append(now)
    ACCESS_REQUESTS.append({
        'id': secrets.token_hex(8),
        'userId': g.user_id,
        'userName': g.user_name,
        'documentId': doc_id,
        'documentTitle': doc['title'],
        'timestamp': now,
        'status': 'PENDING',
    })
    return jsonify({'success': True})


@app.route('/api/admin/block-user', methods=['POST'])
def block_user():
    if not g.user_id or g.role_title != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    data = request.get_json(silent=True) or {}
    user_id = data.get('userId', '')
    if not isinstance(user_id, str) or not user_id:
        return jsonify({'error': 'Invalid userId'}), 400
    BLOCKED_USERS.add(user_id)
    ACTIVE_SESSIONS.pop(user_id, None)
    return jsonify({'success': True})


@app.route('/api/admin/live-stats', methods=['GET'])
def live_stats():
    if not g.user_id or g.role_title != 'admin':
        return jsonify({'error': 'Forbidden'}), 403

    allowed = sum(1 for e in ACCESS_EVENTS if e['result'] == 'ALLOWED')
    denied = sum(1 for e in ACCESS_EVENTS if e['result'] == 'DENIED')
    rejected = sum(1 for e in ACCESS_EVENTS if e['result'] == 'REJECTED')
    return jsonify({'allowed': allowed, 'denied': denied, 'rejected': rejected})


@app.route('/api/admin/requests', methods=['GET'])
def admin_pending_requests():
    if not g.user_id or g.role_title != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    pending = [r for r in ACCESS_REQUESTS if r['status'] == 'PENDING']
    return jsonify({'requests': pending})


@app.route('/api/admin/approve-request', methods=['POST'])
def approve_request():
    if not g.user_id or g.role_title != 'admin':
        return jsonify({'error': 'Forbidden'}), 403

    data = request.get_json(silent=True) or {}
    request_id = data.get('requestId', '')
    if not isinstance(request_id, str) or not request_id:
        return jsonify({'error': 'Invalid requestId'}), 400

    target_request = next((r for r in ACCESS_REQUESTS if r['id'] == request_id), None)
    if not target_request:
        return jsonify({'error': 'Request not found'}), 404

    token = secrets.token_urlsafe(32)
    target_request['status'] = 'APPROVED'
    target_request['approvalToken'] = token
    TEMP_APPROVALS[token] = {
        'user': target_request['userId'],
        'document_id': target_request['documentId'],
        'expires_at': time.time() + 600,
    }
    log_access_event(target_request['userId'], target_request['userName'], 'Escalation', target_request['documentId'], target_request['documentTitle'], 'TOKEN_CREATED', 'token_created')

    return jsonify({'success': True, 'approvalToken': token, 'expires_at': TEMP_APPROVALS[token]['expires_at']})


@app.route('/api/admin/stats', methods=['GET'])
def get_admin_stats():
    if not g.user_id or g.role_title != 'admin':
        return jsonify({'error': 'Forbidden'}), 403

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM access_logs')
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM access_logs WHERE access_result='DENIED'")
    denied = c.fetchone()[0]
    c.execute("SELECT * FROM access_logs ORDER BY timestamp DESC LIMIT 50")
    recent_events = [dict(r) for r in c.fetchall()]

    c.execute("SELECT role_title, COUNT(*) AS count FROM users GROUP BY role_title")
    role_breakdown = [dict(r) for r in c.fetchall()]
    c.execute("SELECT clearance_level, COUNT(*) AS count FROM users GROUP BY clearance_level ORDER BY clearance_level")
    clearance_distribution = [dict(r) for r in c.fetchall()]
    c.execute("SELECT COUNT(*) FROM access_logs WHERE access_result='DENIED' AND reason='Clearance level insufficient for document'")
    clearance_mismatch_denied = c.fetchone()[0]
    conn.close()

    violations = [event for event in recent_events if event['access_result'] == 'DENIED'][:10]
    return jsonify({
        'total_requests': total,
        'denied_requests': denied,
        'recent_events': recent_events,
        'violations': violations,
        'threats': get_flagged_users(),
        'role_breakdown': role_breakdown,
        'clearance_distribution': clearance_distribution,
        'clearance_mismatch_denied': clearance_mismatch_denied,
    })


init_db()

if __name__ == '__main__':
    _debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5001)), debug=_debug)
