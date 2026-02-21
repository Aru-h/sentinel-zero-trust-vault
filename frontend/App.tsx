import { useState, useEffect, useCallback } from 'react';
import { MOCK_DOCUMENTS, API_URL } from './constants';
import { User, Document, Role, AccessLog, ThreatAlert, AccessResult } from './types';
import { ThreatDashboard } from './components/ThreatDashboard';
import { AccessDenyModal } from './components/AccessDenyModal';
import { DocumentReader } from './components/DocumentReader';
import { LoginScreen } from './components/LoginScreen';

interface BackendAccessEvent {
  id: string;
  timestamp: number;
  user_id: string;
  user_name: string;
  user_role: Role;
  document_id: string;
  document_title: string;
  access_result: AccessResult;
  reason: string;
}

interface BackendThreat {
  user_id: string;
  user_name: string;
  deny_count: number;
}

interface AdminStatsResponse {
  recent_events?: BackendAccessEvent[];
  threats?: BackendThreat[];
}

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [currentUser, setCurrentUser]         = useState<User | null>(null);
  const [csrfToken, setCsrfToken]             = useState<string>('');
  const [logs, setLogs]                       = useState<AccessLog[]>([]);
  const [alerts, setAlerts]                   = useState<ThreatAlert[]>([]);
  const [deniedLog, setDeniedLog]             = useState<AccessLog | null>(null);
  const [openDocument, setOpenDocument]       = useState<Document | null>(null);
  const [activeTab, setActiveTab]             = useState<'documents' | 'admin'>('documents');

  // ---------------------------------------------------------------- //
  //  authFetch: every state-changing request carries the CSRF token  //
  // ---------------------------------------------------------------- //
  const authFetch = useCallback(
    (url: string, options: RequestInit = {}) => {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        ...(options.headers as Record<string, string>),
      };
      if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
      return fetch(url, { ...options, headers, credentials: 'include' });
    },
    [csrfToken]
  );

  // ---------------------------------------------------------------- //
  //  On mount: restore session if still valid                        //
  // ---------------------------------------------------------------- //
  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(`${API_URL}/api/me`, { credentials: 'include' });
        if (res.ok) {
          const data = await res.json();
          setCsrfToken(data.csrf_token ?? '');
          setCurrentUser({
            id:     data.user.id,
            name:   data.user.name,
            role:   data.user.role as Role,
            avatar: `https://picsum.photos/seed/${data.user.id}/100/100`,
          });
          setIsAuthenticated(true);
        }
      } catch {
        // Not authenticated — render login screen
      }
    })();
  }, []);

  const handleLogin = (user: User, token: string) => {
    setCsrfToken(token);
    setCurrentUser(user);
    setIsAuthenticated(true);
  };

  const handleLogout = async () => {
    await authFetch(`${API_URL}/logout`, { method: 'POST' });
    setIsAuthenticated(false);
    setCurrentUser(null);
    setCsrfToken('');
    setLogs([]);
    setAlerts([]);
  };

  const handleDocumentClick = async (doc: Document) => {
    if (!currentUser) return;
    try {
      const res = await authFetch(`${API_URL}/api/access`, {
        method: 'POST',
        body: JSON.stringify({ documentId: doc.id }),
      });

      if (res.status === 401) { handleLogout(); return; }

      const data = await res.json();

      const logEntry: AccessLog = {
        id:            `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
        timestamp:     Date.now(),
        userId:        currentUser.id,
        userName:      currentUser.name,
        userRole:      currentUser.role,
        documentId:    doc.id,
        documentTitle: doc.title,
        result:        data.access,
        reason:        data.reason,
      };

      setLogs(prev => [logEntry, ...prev]);

      if (data.threat_detected) {
        setAlerts(prev => {
          const alreadyFlagged = prev.some(
            a => a.userId === currentUser.id && Date.now() - a.timestamp < 60_000
          );
          if (alreadyFlagged) return prev;
          return [{
            id:          `${Date.now().toString(36)}-threat`,
            timestamp:   Date.now(),
            userId:      currentUser.id,
            userName:    currentUser.name,
            severity:    'HIGH' as const,
            description: 'Insider Threat Detected by Backend Security Engine',
          }, ...prev];
        });
      }

      if (data.access === 'ALLOWED') setOpenDocument(doc);
      else setDeniedLog(logEntry);

    } catch (e) {
      console.error('Access request failed', e);
    }
  };

  useEffect(() => {
    if (!isAuthenticated || currentUser?.role !== Role.ADMIN) return;

    const loadAdminStats = async () => {
      try {
        const res = await authFetch(`${API_URL}/api/admin/stats`);
        if (res.status === 401) { handleLogout(); return; }
        if (!res.ok) return;

        const data: AdminStatsResponse = await res.json();
        const syncedLogs: AccessLog[] = (data.recent_events ?? []).map((event) => ({
          id: event.id,
          timestamp: Math.round((event.timestamp ?? 0) * 1000),
          userId: event.user_id,
          userName: event.user_name,
          userRole: event.user_role,
          documentId: event.document_id,
          documentTitle: event.document_title,
          result: event.access_result,
          reason: event.reason,
        }));

        const syncedAlerts: ThreatAlert[] = (data.threats ?? []).map((threat) => ({
          id: `threat-${threat.user_id}`,
          timestamp: Date.now(),
          userId: threat.user_id,
          userName: threat.user_name,
          severity: 'HIGH',
          description: `${threat.deny_count} denied requests in the last minute`,
        }));

        setLogs(syncedLogs);
        setAlerts(syncedAlerts);
      } catch (error) {
        console.error('Failed to sync admin stats', error);
      }
    };

    loadAdminStats();
    const timer = setInterval(loadAdminStats, 3000);
    return () => clearInterval(timer);
  }, [isAuthenticated, currentUser, authFetch]);

  if (!isAuthenticated || !currentUser) {
    return <LoginScreen onLogin={handleLogin} />;
  }

  return (
    <div className="min-h-screen bg-vault-bg text-text-primary font-sans flex flex-col md:flex-row animate-fade-in">

      {/* Sidebar */}
      <aside className="w-full md:w-64 bg-vault-sidebar text-text-inverse border-r border-vault-border flex flex-col shrink-0">
        <div className="p-6 border-b border-vault-border">
          <h1 className="text-xl font-bold font-mono tracking-tighter text-text-inverse flex items-center gap-2">
            <div className="w-3 h-3 bg-primary rounded-full animate-pulse"></div>
            SENTINEL<span className="text-primary">ZERO</span>
          </h1>
          <p className="text-xs text-text-muted mt-1">Secure Knowledge Vault</p>
        </div>

        <nav className="flex-1 p-4 space-y-2">
          <button
            onClick={() => setActiveTab('documents')}
            className={`w-full text-left px-4 py-3 rounded-lg flex items-center gap-3 transition-all ${
              activeTab === 'documents'
                ? 'bg-primary/20 text-primary border border-primary/30'
                : 'text-text-muted hover:bg-white/5'
            }`}
          >
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
            </svg>
            <span className="text-sm font-medium">Knowledge Repository</span>
          </button>

          {currentUser.role === 'Admin' && (
            <button
              onClick={() => setActiveTab('admin')}
              className={`w-full text-left px-4 py-3 rounded-lg flex items-center gap-3 transition-all ${
                activeTab === 'admin'
                  ? 'bg-primary/20 text-primary border border-primary/30'
                  : 'text-text-muted hover:bg-white/5'
              }`}
            >
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              <span className="text-sm font-medium">Security Operations</span>
            </button>
          )}
        </nav>

        {/* User Card */}
        <div className="p-4 border-t border-vault-border">
          <div className="flex items-center gap-3">
            <img src={currentUser.avatar} alt={currentUser.name} className="w-9 h-9 rounded-full border-2 border-primary/30" />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold text-text-inverse truncate">{currentUser.name}</p>
              <p className="text-xs text-text-muted">{currentUser.role}</p>
            </div>
            <button onClick={handleLogout} title="Logout" className="text-text-muted hover:text-danger transition-colors">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
              </svg>
            </button>
          </div>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 flex flex-col overflow-hidden">
        <header className="px-6 py-4 border-b border-vault-border flex items-center justify-between bg-vault-surface/50">
          <h2 className="text-lg font-bold text-text-primary">
            {activeTab === 'documents' ? 'Knowledge Repository' : 'Security Operations Center'}
          </h2>
          {alerts.length > 0 && (
            <div className="hidden md:flex items-center gap-3 bg-danger/10 border border-danger/30 px-4 py-2 rounded-full">
              <span className="w-2 h-2 rounded-full bg-danger animate-pulse"></span>
              <span className="text-danger font-bold text-xs uppercase tracking-wider">Insider Threat Detected</span>
            </div>
          )}
        </header>

        <div className="flex-1 overflow-y-auto p-6">
          {activeTab === 'documents' && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
              {MOCK_DOCUMENTS.map(doc => {
                const borderColor =
                  doc.classification === 'Public'       ? 'border-badge-public/40 hover:border-badge-public' :
                  doc.classification === 'Internal'     ? 'border-badge-internal/40 hover:border-badge-internal' :
                  doc.classification === 'Confidential' ? 'border-badge-confidential/40 hover:border-badge-confidential' :
                  'border-badge-restricted/40 hover:border-badge-restricted';
                const iconColor =
                  doc.classification === 'Public'       ? 'text-badge-public' :
                  doc.classification === 'Internal'     ? 'text-badge-internal' :
                  doc.classification === 'Confidential' ? 'text-badge-confidential' :
                  'text-badge-restricted';

                return (
                  <div key={doc.id} onClick={() => handleDocumentClick(doc)}
                    className={`bg-vault-surface border ${borderColor} rounded-xl p-6 cursor-pointer transition-all duration-300 hover:shadow-lg hover:-translate-y-1 group relative overflow-hidden`}>
                    <div className="flex justify-between items-start mb-4">
                      <div className={`p-2 rounded-lg bg-black/30 ${iconColor}`}>
                        {doc.locked ? (
                          <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                          </svg>
                        ) : (
                          <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 002 2v6a2 2 0 002 2z" />
                          </svg>
                        )}
                      </div>
                      <span className={`text-[10px] uppercase font-bold tracking-wider border px-2 py-0.5 rounded ${iconColor} border-current opacity-70`}>
                        {doc.classification}
                      </span>
                    </div>
                    <h3 className="text-lg font-bold text-text-primary mb-1 group-hover:text-primary">{doc.title}</h3>
                    <p className="text-xs text-text-secondary mb-4">{doc.department} Dept.</p>
                    <div className="flex items-center text-xs text-text-muted">
                      <span className="mr-2">ID: {doc.id}</span>
                      <span className="w-1 h-1 bg-text-muted rounded-full mx-1"></span>
                      <span>Encrypted</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {activeTab === 'admin' && (
            <ThreatDashboard logs={logs} alerts={alerts} currentUser={currentUser} />
          )}
        </div>
      </main>

      <AccessDenyModal log={deniedLog} onClose={() => setDeniedLog(null)} />
      {openDocument && (
        <DocumentReader document={openDocument} user={currentUser} onClose={() => setOpenDocument(null)} />
      )}
    </div>
  );
}

export default App;
