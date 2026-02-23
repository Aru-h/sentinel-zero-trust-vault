diff --git a/backend/app.py b/backend/app.py
index 11d9b60420758568ef61a6cce85dec83b950bd00..eac12410f4884be75c1f7422a6ec5205a901bdbb 100644
--- a/backend/app.py
+++ b/backend/app.py
@@ -31,50 +31,63 @@ app.config.update(
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
 
 
+def _is_admin_session() -> bool:
+    role = session.get('user_role') or getattr(g, 'user_role', None)
+    role_title = session.get('role_title') or getattr(g, 'role_title', None)
+    return role == 'Admin' or role_title == 'admin'
+
+
+def _username_from_user_id(user_id: str) -> str | None:
+    for username, user in AUTH_DB.items():
+        if user['id'] == user_id:
+            return username
+    return None
+
+
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
@@ -348,51 +361,52 @@ def _validate_csrf():
 
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
-        g.username = session['username']
+        g.role_title = session.get('role_title', '')
+        g.username = session.get('username') or _username_from_user_id(g.user_id)
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
@@ -431,51 +445,51 @@ def login():
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
-    if 'user_id' not in session or session.get('user_role') != 'Admin':
+    if 'user_id' not in session or not _is_admin_session():
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
 
@@ -560,117 +574,117 @@ def request_temporary_access():
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
-    if not g.user_id or g.user_role != 'Admin':
+    if not g.user_id or not _is_admin_session():
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
-    if not g.user_id or g.user_role != 'Admin':
+    if not g.user_id or not _is_admin_session():
         return jsonify({'error': 'Forbidden'}), 403
 
     allowed = sum(1 for e in ACCESS_EVENTS if e['result'] == 'ALLOWED')
     denied = sum(1 for e in ACCESS_EVENTS if e['result'] == 'DENIED')
     rejected = sum(1 for e in ACCESS_EVENTS if e['result'] == 'REJECTED')
 
     return jsonify({'allowed': allowed, 'denied': denied, 'rejected': rejected})
 
 
 @app.route('/api/admin/requests', methods=['GET'])
 def admin_pending_requests():
-    if not g.user_id or g.user_role != 'Admin':
+    if not g.user_id or not _is_admin_session():
         return jsonify({'error': 'Forbidden'}), 403
 
     pending = [r for r in ACCESS_REQUESTS if r['status'] == 'PENDING']
     return jsonify({'requests': pending})
 
 
 @app.route('/api/admin/approve-request', methods=['POST'])
 def approve_request():
-    if not g.user_id or g.user_role != 'Admin':
+    if not g.user_id or not _is_admin_session():
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
-    if not g.user_id or g.user_role != 'Admin':
+    if not g.user_id or not _is_admin_session():
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
