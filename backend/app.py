"""
Sentinel Zero Trust Backend — Production (Render)
==================================================
Security layers in this build:
  - Fernet (AES-256) document encryption at rest (runtime key fallback supported)
  - Zero-Trust access sequencing with policy checks before decryption
  - Hybrid RBAC + hierarchical clearance levels for users/documents
  - Risk score-based insider detection with auto-block and admin unblock flow
  - Expiring temporary approval tokens for restricted document exceptions
"""

import sqlite3
import time
import os
import hmac
import secrets
from flask import Flask, request, jsonify, g, render_template, session, redirect, url_for, flash
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet, InvalidToken

app = Flask(__name__)

app.secret_key = os.environ.get('SECRET_KEY', 'sentinel-demo-secret-change-me')
_is_prod = os.environ.get('FLASK_ENV', 'development') == 'production'

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='None' if _is_prod else 'Lax',
    SESSION_COOKIE_SECURE=_is_prod,
)

_allowed_origins = [
    o.strip()
    for o in os.environ.get(
        'CORS_ORIGINS',
        'http://localhost:5173,http://127.0.0.1:5173,https://sentinel-zero-trust-vault.vercel.app'
    ).split(',')
    if o.strip()
]

CORS(app, supports_credentials=True, origins=_allowed_origins)

DB_PATH = os.environ.get('DB_PATH', os.path.join(os.path.dirname(__file__), 'sentinel.db'))
SESSION_TIMEOUT = 15 * 60
BLOCKED_USERS: set[str] = set()
AUTO_BLOCKED_USERS: set[str] = set()
ACTIVE_SESSIONS: dict[str, str] = {}
ACCESS_EVENTS: list[dict] = []
ACCESS_REQUESTS: list[dict] = []
TEMP_APPROVALS: dict[str, dict] = {}
REQUEST_RATE_TRACKER: dict[str, list[float]] = {}
USER_RISK: dict[str, dict] = {}


def _load_encryption_key() -> bytes:
    configured = os.environ.get('ENCRYPTION_KEY')
    if configured:
        try:
            Fernet(configured.encode('utf-8'))
            return configured.encode('utf-8')
        except Exception:
            print('[Sentinel][WARN] ENCRYPTION_KEY invalid; generating runtime-only key.')
    runtime_key = Fernet.generate_key()
    print('[Sentinel][WARN] ENCRYPTION_KEY missing; using runtime-only key (documents unreadable after restart).')
    return runtime_key


FERNET = Fernet(_load_encryption_key())


def encrypt_document(plaintext: str) -> bytes:
    return FERNET.encrypt(plaintext.encode('utf-8'))


def decrypt_document(ciphertext: bytes) -> str:
    return FERNET.decrypt(ciphertext).decode('utf-8')


_RATE_LIMIT_STORE: dict = {}


def check_rate_limit(ip: str, limit: int = 5, window: int = 60) -> bool:
    now = time.time()
    _RATE_LIMIT_STORE.setdefault(ip, [])
    _RATE_LIMIT_STORE[ip] = [t for t in _RATE_LIMIT_STORE[ip] if now - t < window]
    if len(_RATE_LIMIT_STORE[ip]) >= limit:
        return False
    _RATE_LIMIT_STORE[ip].append(now)
    return True


def _build_auth_db() -> dict:
    raw = {
        'admin1': {'pass': 'Admin@123', 'role': 'Admin', 'id': 'u1', 'name': 'Alice Admin', 'clearance_level': 5},
        'hr1': {'pass': 'HR@123', 'role': 'HR', 'id': 'u3', 'name': 'Charlie HR', 'clearance_level': 4},
        'dev1': {'pass': 'Dev@123', 'role': 'Developer', 'id': 'u2', 'name': 'Bob Dev', 'clearance_level': 3},
        'fin1': {'pass': 'Fin@123', 'role': 'Finance', 'id': 'u4', 'name': 'Dana Finance', 'clearance_level': 4},
    }

    return {
        username: {
            'hash': generate_password_hash(data['pass'], method='pbkdf2:sha256'),
            'role': data['role'], 'id': data['id'],
            'name': data['name'], 'username': username,
            'clearance_level': data['clearance_level'],
        }
        for username, data in raw.items()
    }


AUTH_DB = _build_auth_db()
_DUMMY_HASH = generate_password_hash('__sentinel_canary__', method='pbkdf2:sha256')

DOCUMENTS = {
    'd1': {'title': 'Company Handbook', 'classification': 'Public', 'department': 'General', 'required_clearance': 1, 'content': 'Company handbook and onboarding standards.'},
    'd2': {'title': 'Q3 Financial Report', 'classification': 'Confidential', 'department': 'Finance', 'required_clearance': 4, 'content': 'Quarterly financial performance and projections.'},
    'd3': {'title': 'Employee Salaries', 'classification': 'Restricted', 'department': 'HR', 'required_clearance': 4, 'content': 'Compensation matrix and payroll controls.'},
    'd4': {'title': 'Project Sentinel Source Code', 'classification': 'Internal', 'department': 'Developer', 'required_clearance': 3, 'content': 'Private source notes and deployment architecture.'},
    'd5': {'title': 'Admin Credentials Backup', 'classification': 'Restricted', 'department': 'Admin', 'required_clearance': 5, 'content': 'Emergency admin credentials recovery plan.'},
    'd6': {'title': 'Office Floor Plan', 'classification': 'Internal', 'department': 'General', 'required_clearance': 2, 'content': 'Office floor map and evacuation route references.'},
    'd7': {'title': 'Merger Strategy 2025', 'classification': 'Restricted', 'department': 'Finance', 'required_clearance': 5, 'content': 'Merger scenario analysis and board strategy.'},
    'd8': {'title': 'API Documentation', 'classification': 'Public', 'department': 'Developer', 'required_clearance': 1, 'content': 'API endpoint catalogue and examples.'},
    'd9': {'title': 'Termination Policy', 'classification': 'Confidential', 'department': 'HR', 'required_clearance': 3, 'content': 'Termination workflow and legal requirements.'},
    'd10': {'title': 'Audit Logs 2024', 'classification': 'Confidential', 'department': 'Admin', 'required_clearance': 5, 'content': 'Security audit log summary and remediation actions.'},
}
_VALID_DOC_IDS = frozenset(DOCUMENTS.keys())


def check_policy_engine(role: str, doc: dict) -> tuple[bool, str]:
    c = doc['classification']
    d = doc['department']
    if c == 'Public':
        return True, 'Public Classification'
    if role == 'Admin':
        return True, 'Admin Override [AUDITED]'
    same = (d == 'General') or (d == role)
    if c == 'Internal':
        return True, 'Internal Access Policy'
    if c == 'Confidential':
        return (True, 'Role-Based Access') if same else (False, 'Department Mismatch')
    if c == 'Restricted':
        return False, 'Restricted: Escalation Required'
    return False, 'Implicit Deny'


def check_department_rule(role: str, doc: dict) -> tuple[bool, str]:
    if role == 'Admin':
        return True, 'Admin department override'
    if doc['department'] in ('General', role):
        return True, 'Department validation passed'
    return False, 'department_mismatch'


def check_clearance_rule(user_clearance: int, required_clearance: int, role: str) -> tuple[bool, str]:
    if role == 'Admin':
        return True, 'Admin clearance override'
    if user_clearance >= required_clearance:
        return True, 'Clearance validation passed'
    return False, 'insufficient_clearance'


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    rows = conn.execute(f'PRAGMA table_info({table})').fetchall()
    return any(r['name'] == column for r in rows)


def _seed_documents(conn: sqlite3.Connection):
    for doc_id, doc in DOCUMENTS.items():
        encrypted_content = encrypt_document(doc['content'])
        conn.execute(
            '''
            INSERT INTO documents (id, title, classification, department, content, required_clearance)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              title=excluded.title,
              classification=excluded.classification,
              department=excluded.department,
              content=excluded.content,
              required_clearance=excluded.required_clearance
            ''',
            (doc_id, doc['title'], doc['classification'], doc['department'], encrypted_content, doc['required_clearance'])
        )


def _ensure_encrypted_documents(conn: sqlite3.Connection):
    """One-time migration guard: encrypt legacy plaintext rows at rest."""
    rows = conn.execute('SELECT id, content FROM documents').fetchall()
    for row in rows:
        content = row['content']
        if content is None:
            continue

        # sqlite may return TEXT as str for legacy databases.
        raw = content.encode('utf-8') if isinstance(content, str) else bytes(content)
        try:
            decrypt_document(raw)
            continue
        except Exception:
            pass

        encrypted = encrypt_document(raw.decode('utf-8', errors='replace'))
        conn.execute('UPDATE documents SET content=? WHERE id=?', (encrypted, row['id']))


def init_db():
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
    conn.execute('''
        CREATE TABLE IF NOT EXISTS documents (
            id                 TEXT PRIMARY KEY,
            title              TEXT NOT NULL,
            classification     TEXT NOT NULL,
            department         TEXT NOT NULL,
            content            BLOB NOT NULL,
            required_clearance INTEGER DEFAULT 1
        )
    ''')
    if not _column_exists(conn, 'documents', 'required_clearance'):
        conn.execute('ALTER TABLE documents ADD COLUMN required_clearance INTEGER DEFAULT 1')

    _seed_documents(conn)
    _ensure_encrypted_documents(conn)
    conn.commit()
    conn.close()
    print(f'[Sentinel] DB initialized at {DB_PATH}')


def log_access_event(user_id, user_name, user_role, doc_id, doc_title, result, reason):
    ACCESS_EVENTS.append({
        'timestamp': time.time(),
        'user_id': user_id,
        'doc_id': doc_id,
        'result': result,
    })
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
        print(f'[Sentinel] Log error: {e}')


def _risk_reset_if_inactive(username: str):
    risk = USER_RISK.get(username)
    if not risk:
        return
    now = time.time()
    if now - risk['last_activity'] > 600:
        USER_RISK[username] = {'score': 0, 'last_activity': now}
        user = AUTH_DB.get(username)
        if user:
            user_id = user['id']
            if user_id in AUTO_BLOCKED_USERS:
                AUTO_BLOCKED_USERS.discard(user_id)
                BLOCKED_USERS.discard(user_id)


def _clear_auto_block(username: str):
    user = AUTH_DB.get(username)
    if not user:
        return
    user_id = user['id']
    if user_id in AUTO_BLOCKED_USERS:
        AUTO_BLOCKED_USERS.discard(user_id)
        BLOCKED_USERS.discard(user_id)


def _apply_risk_signal(username: str, user_id: str, user_name: str, user_role: str, doc: dict, denied: bool):
    _risk_reset_if_inactive(username)
    now = time.time()
    risk = USER_RISK.setdefault(username, {'score': 0, 'last_activity': now})

    increment = 0
    if denied:
        increment += 2
    if doc['classification'] == 'Restricted':
        increment += 3
    current_hour = time.localtime(now).tm_hour
    if current_hour < 8 or current_hour >= 20:
        increment += 1

    risk['score'] += increment
    risk['last_activity'] = now

    if risk['score'] >= 6 and user_id not in BLOCKED_USERS:
        BLOCKED_USERS.add(user_id)
        AUTO_BLOCKED_USERS.add(user_id)
        ACTIVE_SESSIONS.pop(user_id, None)
        log_access_event(user_id, user_name, user_role, doc.get('id', 'risk'), doc.get('title', 'Risk Engine'), 'DENIED', 'risk_auto_block')


def get_flagged_users():
    flagged = []
    for username, data in USER_RISK.items():
        user = AUTH_DB.get(username)
        if user and data['score'] >= 6:
            flagged.append({'user_id': user['id'], 'user_name': user['name'], 'deny_count': data['score']})
    return flagged


def cleanup_expired_tokens():
    now = time.time()
    expired = [token for token, payload in TEMP_APPROVALS.items() if payload['expires_at'] <= now]
    for token in expired:
        payload = TEMP_APPROVALS.pop(token)
        log_access_event(payload['user'], payload['user_name'], payload['user_role'], payload['document_id'], payload['document_title'], 'DENIED', 'token_expired')


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
    cleanup_expired_tokens()
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
        g.username = session['username']
        g.user_clearance_level = session.get('clearance_level', 1)
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
        user = AUTH_DB.get(user_key)
        ok = check_password_hash(user['hash'] if user else _DUMMY_HASH, password_input)

        if user and ok:
            # Successful login resets risk state. If the account was
            # auto-blocked by the risk engine, clear that temporary block.
            _clear_auto_block(user['username'])
            session_id = secrets.token_hex(16)
            session.clear()
            session.update({
                'user_id': user['id'], 'user_name': user['name'],
                'user_role': user['role'], 'last_active': time.time(),
                'csrf_token': secrets.token_hex(32),
                'session_id': session_id,
                'username': user['username'],
                'clearance_level': user['clearance_level'],
            })
            ACTIVE_SESSIONS[user['id']] = session_id
            USER_RISK[user['username']] = {'score': 0, 'last_activity': time.time()}
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
    if session.get('user_id'):
        ACTIVE_SESSIONS.pop(session['user_id'], None)
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
def access_document():
    if not g.user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    if g.user_id in BLOCKED_USERS:
        ACTIVE_SESSIONS.pop(g.user_id, None)
        session.clear()
        return jsonify({'error': 'User blocked by admin'}), 403

    data = request.get_json(silent=True) or {}
    doc_id = data.get('documentId', '')
    provided_token = data.get('temporaryToken', '')

    if not isinstance(doc_id, str) or doc_id not in _VALID_DOC_IDS:
        return jsonify({'error': 'Document not found'}), 404

    doc_meta = DOCUMENTS[doc_id] | {'id': doc_id}

    # 1) session validated by middleware
    # 2) block status validated above

    # 3) classification policy
    allowed, reason = check_policy_engine(g.user_role, doc_meta)

    # 4) department rule
    if allowed:
        allowed, reason = check_department_rule(g.user_role, doc_meta)

    # 5) clearance level
    if allowed:
        allowed, reason = check_clearance_rule(g.user_clearance_level, doc_meta['required_clearance'], g.user_role)

    # 6) temporary approval token when required
    if not allowed and doc_meta['classification'] == 'Restricted':
        token_payload = TEMP_APPROVALS.get(provided_token) if isinstance(provided_token, str) else None
        if token_payload:
            if token_payload['expires_at'] <= time.time():
                TEMP_APPROVALS.pop(provided_token, None)
                log_access_event(g.user_id, g.user_name, g.user_role, doc_id, doc_meta['title'], 'DENIED', 'token_expired')
            elif token_payload['user'] == g.user_id and token_payload['document_id'] == doc_id:
                allowed = True
                reason = 'Temporary access approved by admin'
                log_access_event(g.user_id, g.user_name, g.user_role, doc_id, doc_meta['title'], 'ALLOWED', 'token_used')

    result = 'ALLOWED' if allowed else 'DENIED'
    log_access_event(g.user_id, g.user_name, g.user_role, doc_id, doc_meta['title'], result, reason)

    _apply_risk_signal(g.username, g.user_id, g.user_name, g.user_role, doc_meta, denied=(not allowed))

    if not allowed:
        return jsonify({
            'access': result,
            'reason': reason,
            'threat_detected': g.user_id in BLOCKED_USERS,
            'document': None,
        })

    # 7) decrypt only after policy + department + clearance + token pass
    conn = get_db()
    row = conn.execute('SELECT content FROM documents WHERE id=?', (doc_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'Document storage unavailable'}), 500

    try:
        plaintext_content = decrypt_document(row['content'])
    except (InvalidToken, TypeError):
        return jsonify({'error': 'Document decrypt failed'}), 500

    # 8) never log decrypted content
    return jsonify({
        'access': result,
        'reason': reason,
        'threat_detected': g.user_id in BLOCKED_USERS,
        'document': {
            'id': doc_id,
            'title': doc_meta['title'],
            'classification': doc_meta['classification'],
            'department': doc_meta['department'],
            'required_clearance': doc_meta['required_clearance'],
            'content': plaintext_content,
        }
    })


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
    if not isinstance(doc_id, str) or doc_id not in _VALID_DOC_IDS:
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
        'documentTitle': DOCUMENTS[doc_id]['title'],
        'timestamp': now,
        'status': 'PENDING'
    })

    return jsonify({'success': True})


@app.route('/api/admin/block-user', methods=['POST'])
def block_user():
    if not g.user_id or g.user_role != 'Admin':
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
    if not g.user_id or g.user_role != 'Admin':
        return jsonify({'error': 'Forbidden'}), 403

    allowed = sum(1 for e in ACCESS_EVENTS if e['result'] == 'ALLOWED')
    denied = sum(1 for e in ACCESS_EVENTS if e['result'] == 'DENIED')
    rejected = sum(1 for e in ACCESS_EVENTS if e['result'] == 'REJECTED')

    return jsonify({'allowed': allowed, 'denied': denied, 'rejected': rejected})


@app.route('/api/admin/requests', methods=['GET'])
def admin_pending_requests():
    if not g.user_id or g.user_role != 'Admin':
        return jsonify({'error': 'Forbidden'}), 403

    pending = [r for r in ACCESS_REQUESTS if r['status'] == 'PENDING']
    return jsonify({'requests': pending})


@app.route('/api/admin/approve-request', methods=['POST'])
def approve_request():
    if not g.user_id or g.user_role != 'Admin':
        return jsonify({'error': 'Forbidden'}), 403

    data = request.get_json(silent=True) or {}
    request_id = data.get('requestId', '')
    expires_in = data.get('expiresInSeconds', 600)
    if not isinstance(request_id, str) or not request_id:
        return jsonify({'error': 'Invalid requestId'}), 400

    target_request = next((r for r in ACCESS_REQUESTS if r['id'] == request_id), None)
    if not target_request:
        return jsonify({'error': 'Request not found'}), 404

    target_request['status'] = 'APPROVED'
    token = secrets.token_urlsafe(32)
    expiry = time.time() + (expires_in if isinstance(expires_in, int) and expires_in > 0 else 600)
    TEMP_APPROVALS[token] = {
        'user': target_request['userId'],
        'user_name': target_request['userName'],
        'user_role': next((u['role'] for u in AUTH_DB.values() if u['id'] == target_request['userId']), 'Unknown'),
        'document_id': target_request['documentId'],
        'document_title': target_request['documentTitle'],
        'expires_at': expiry,
    }
    log_access_event(target_request['userId'], target_request['userName'], TEMP_APPROVALS[token]['user_role'], target_request['documentId'], target_request['documentTitle'], 'ALLOWED', 'token_created')
    return jsonify({'success': True, 'token': token, 'expiresAt': expiry})


@app.route('/api/admin/stats', methods=['GET'])
def get_admin_stats():
    if not g.user_id or g.user_role != 'Admin':
        return jsonify({'error': 'Forbidden'}), 403

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM access_logs')
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM access_logs WHERE access_result='DENIED'")
    denied = c.fetchone()[0]
    c.execute("SELECT * FROM access_logs ORDER BY timestamp DESC LIMIT 50")
    recent_events = [dict(r) for r in c.fetchall()]
    violations = [event for event in recent_events if event['access_result'] == 'DENIED'][:10]
    conn.close()

    return jsonify({
        'total_requests': total,
        'denied_requests': denied,
        'recent_events': recent_events,
        'violations': violations,
        'threats': get_flagged_users(),
    })


init_db()

if __name__ == '__main__':
    _debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5001)), debug=_debug)
