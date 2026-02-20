import sqlite3
import time
import os
from functools import wraps
from flask import Flask, request, jsonify, g, render_template, session, redirect, url_for, flash
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)


# SECURITY PATCH: Use a strong secret key and enforce Cookie Security
app.secret_key = os.environ.get('SECRET_KEY', 'sentinel-zero-trust-super-secret-key-2025')
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,  # Prevent JS access to cookies (XSS protection)
    SESSION_COOKIE_SAMESITE='Lax', # CSRF protection
    SESSION_COOKIE_SECURE=False,   # Set to True in Production (requires HTTPS)
)

# Allow credentials for React Frontend (Vite default: 5173, CRA default: 3000)
CORS(app, supports_credentials=True, origins=[
    "http://localhost:5173", "http://127.0.0.1:5173",
    "http://localhost:3000", "http://127.0.0.1:3000"
])

DB_PATH = os.path.join(os.path.dirname(__file__), 'sentinel.db')
SESSION_TIMEOUT = 15 * 60  # 15 minutes

# --- In-Memory Rate Limiter (Brute Force Protection) ---
# Dictionary format: { 'ip_address': [timestamp1, timestamp2, ...] }
RATE_LIMIT_STORE = {}

def check_rate_limit(ip, limit=5, window=60):
    """
    Returns True if request is allowed, False if rate limited.
    Simple sliding window algorithm.
    """
    now = time.time()
    if ip not in RATE_LIMIT_STORE:
        RATE_LIMIT_STORE[ip] = []
    
    # Filter out timestamps older than the window
    RATE_LIMIT_STORE[ip] = [t for t in RATE_LIMIT_STORE[ip] if now - t < window]
    
    if len(RATE_LIMIT_STORE[ip]) >= limit:
        return False
    
    RATE_LIMIT_STORE[ip].append(now)
    return True

# --- Authentication Configuration ---
RAW_USERS = {
    "admin1": {"pass": "Admin@123", "role": "Admin", "id": "u1", "name": "Alice Admin"},
    "hr1":    {"pass": "HR@123",    "role": "HR",    "id": "u3", "name": "Charlie HR"},
    "dev1":   {"pass": "Dev@123",   "role": "Developer", "id": "u2", "name": "Bob Dev"},
    "fin1":   {"pass": "Fin@123",   "role": "Finance", "id": "u4", "name": "Dana Finance"},
    "eve1":   {"pass": "Hacker@123","role": "Developer", "id": "u5", "name": "Eve Hacker"} 
}

AUTH_DB = {}

def init_auth_db():
    for username, data in RAW_USERS.items():
        AUTH_DB[username] = {
            "hash": generate_password_hash(data["pass"], method="pbkdf2:sha256"),
            "role": data["role"],
            "id": data["id"],
            "name": data["name"],
            "username": username
        }
    print(f"Authentication DB initialized with {len(AUTH_DB)} users.")
init_auth_db()
# --- Database & Logging ---
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS access_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    user_id TEXT,
                    user_name TEXT,
                    user_role TEXT,
                    doc_id TEXT,
                    doc_title TEXT,
                    access_result TEXT,
                    reason TEXT
                )''')
    conn.commit()
    conn.close()

def log_access_event(user_id, user_name, user_role, doc_id, doc_title, result, reason):
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            INSERT INTO access_logs (timestamp, user_id, user_name, user_role, doc_id, doc_title, access_result, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (time.time(), user_id, user_name, user_role, doc_id, doc_title, result, reason))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Logging Error: {e}")

# --- Insider Threat Detection ---
def detect_insider_threat(user_id):
    conn = get_db()
    c = conn.cursor()
    window_start = time.time() - 60 
    c.execute('''
        SELECT COUNT(*) FROM access_logs 
        WHERE user_id = ? AND access_result = 'DENIED' AND timestamp > ?
    ''', (user_id, window_start))
    deny_count = c.fetchone()[0]
    conn.close()
    return deny_count >= 3

def get_flagged_users():
    conn = get_db()
    c = conn.cursor()
    window_start = time.time() - 60
    c.execute('''
        SELECT user_id, user_name, COUNT(*) as deny_count 
        FROM access_logs 
        WHERE access_result = 'DENIED' AND timestamp > ?
        GROUP BY user_id
        HAVING deny_count >= 3
    ''', (window_start,))
    return [dict(row) for row in c.fetchall()]

# --- Document Store (Source of Truth) ---
DOCUMENTS = {
    'd1': {'title': 'Company Handbook', 'classification': 'Public', 'department': 'General'},
    'd2': {'title': 'Q3 Financial Report', 'classification': 'Confidential', 'department': 'Finance'},
    'd3': {'title': 'Employee Salaries', 'classification': 'Restricted', 'department': 'HR'},
    'd4': {'title': 'Project Sentinel Source Code', 'classification': 'Internal', 'department': 'Developer'},
    'd5': {'title': 'Admin Credentials Backup', 'classification': 'Restricted', 'department': 'Admin'},
    'd6': {'title': 'Office Floor Plan', 'classification': 'Internal', 'department': 'General'},
    'd7': {'title': 'Merger Strategy 2025', 'classification': 'Restricted', 'department': 'Finance'},
    'd8': {'title': 'API Documentation', 'classification': 'Public', 'department': 'Developer'},
    'd9': {'title': 'Termination Policy', 'classification': 'Confidential', 'department': 'HR'},
    'd10': {'title': 'Audit Logs 2024', 'classification': 'Confidential', 'department': 'Admin'},
}

# --- Access Policy Engine (Backend Enforced) ---
def check_policy_engine(role, doc):
    classification = doc['classification']
    dept = doc['department']

    if classification == 'Public': return True, "Public Classification"
    if role == 'Admin': return True, "Admin Override"

    is_same_dept = (dept == 'General') or (dept == role)

    if classification == 'Internal': return True, "Internal Access Policy"
    if classification == 'Confidential':
        return (True, "Role-Based Access") if is_same_dept else (False, "Department Mismatch")
    if classification == 'Restricted':
        # Even stricter for restricted - strictly purely same dept or explicit deny
        if is_same_dept:
             return False, "Restricted: Escalation Required" 
        return False, "Restricted: Unauthorized"

    return False, "Implicit Deny"

# --- Middleware ---
@app.before_request
def extract_identity():
    if request.method == 'OPTIONS': return
    
    # Session Management
    if 'user_id' in session:
        now = time.time()
        last_active = session.get('last_active', now)
        if now - last_active > SESSION_TIMEOUT:
            session.clear()
            return
        session['last_active'] = now
        g.user_id = session['user_id']
        g.user_name = session['user_name']
        g.user_role = session['user_role']
    else:
        g.user_id = None

# --- Routes ---

# SECURITY PATCH: Endpoint for Frontend to check if session is active
@app.route('/api/me', methods=['GET'])
def get_current_user():
    if not g.user_id:
        return jsonify({'authenticated': False}), 401
    return jsonify({
        'authenticated': True,
        'user': {
            'id': g.user_id,
            'name': g.user_name,
            'role': g.user_role
        }
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    # SECURITY PATCH: Brute Force Protection
    if not check_rate_limit(request.remote_addr, limit=5, window=60):
        if request.is_json:
             return jsonify({'error': 'Too many login attempts. Try again later.'}), 429
        flash('Too many login attempts.', 'error')
        return render_template('login.html')

    if request.method == 'POST':
        # Support both JSON (React) and Form (Template)
        if request.is_json:
            data = request.json
            username_input = data.get('username')
            password_input = data.get('password')
        else:
            username_input = request.form.get('username')
            password_input = request.form.get('password')

        # Find user (case-insensitive username match)
        user_key = next((k for k in AUTH_DB if k.lower() == username_input.lower()), None)
        user = AUTH_DB.get(user_key)
        
        if user and check_password_hash(user['hash'], password_input):
            session.clear()
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['user_role'] = user['role']
            session['last_active'] = time.time()
            
            if request.is_json:
                return jsonify({'success': True, 'user': user})
            return redirect(url_for('dashboard_view'))
        
        if request.is_json:
            return jsonify({'error': 'Invalid credentials'}), 401
        flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    if request.is_json:
        return jsonify({'success': True})
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard_view():
    if 'user_id' not in session or session.get('user_role') != 'Admin':
        return redirect(url_for('login'))
    return render_template('dashboard.html', user_name=session.get('user_name'), user_role=session.get('user_role'))

@app.route('/api/access', methods=['POST'])
def request_access():
    if not g.user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json
    doc_id = data.get('documentId')
    doc = DOCUMENTS.get(doc_id)

    if not doc:
        return jsonify({'error': 'Document Not Found'}), 404

    # SECURITY PATCH: The Backend decides. Frontend cannot bypass this.
    allowed, reason = check_policy_engine(g.user_role, doc)
    result = "ALLOWED" if allowed else "DENIED"

    log_access_event(g.user_id, g.user_name, g.user_role, doc_id, doc['title'], result, reason)
    is_threat = detect_insider_threat(g.user_id)

    return jsonify({
        'access': result,
        'reason': reason,
        'threat_detected': is_threat,
        'document': doc if allowed else None 
        # Note: In a real app, 'document' here would contain the actual S3 link or content.
        # Since we use Gemini on frontend for content generation, we are authorizing the *intent* here.
    })

# Admin Routes (kept same but rely on g.user_role which is now secure)
@app.route('/api/admin/stats', methods=['GET'])
def get_admin_stats():
    if not g.user_id or g.user_role != 'Admin':
        return jsonify({'error': 'Forbidden'}), 403
        
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM access_logs')
    total_req = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM access_logs WHERE access_result='DENIED'")
    denied_req = c.fetchone()[0]
    c.execute("SELECT * FROM access_logs WHERE access_result='DENIED' ORDER BY timestamp DESC LIMIT 10")
    violations = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify({
        'total_requests': total_req,
        'denied_requests': denied_req,
        'violations': violations,
        'threats': get_flagged_users()
    })

if __name__ == '__main__':
    if not os.path.exists(DB_PATH):
        init_db()
    print("Sentinel Backend Active on Port 5000")
    app.run(host='0.0.0.0', port=5001, debug=True)


