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

interface RequestAccessResponse {
  error?: string;
}

function App() {
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    if (typeof window === 'undefined') return 'light';
    const savedTheme = window.localStorage.getItem('vault-theme');
    return savedTheme === 'dark' ? 'dark' : 'light';
  });
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [currentUser, setCurrentUser]         = useState<User | null>(null);
  const [csrfToken, setCsrfToken]             = useState<string>('');
  const [logs, setLogs]                       = useState<AccessLog[]>([]);
  const [alerts, setAlerts]                   = useState<ThreatAlert[]>([]);
  const [deniedLog, setDeniedLog]             = useState<AccessLog | null>(null);
  const [openDocument, setOpenDocument]       = useState<Document | null>(null);
  const [activeTab, setActiveTab]             = useState<'documents' | 'admin'>('documents');
  const departments = Array.from(new Set(MOCK_DOCUMENTS.map((doc) => doc.department)));
  const [selectedDepartment, setSelectedDepartment] = useState<string>(departments[0] ?? 'General');

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
    window.localStorage.setItem('vault-theme', theme);
  }, [theme]);

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
        } else if (res.status === 403) {
          const data = await res.json();
          if (data?.error === 'User blocked by admin') {
            await handleLogout();
          }
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
      if (res.status === 403) {
        const data = await res.json();
        if (data?.error === 'User blocked by admin') {
          await handleLogout();
        }
        return;
      }

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

  const handleRequestAccess = async (documentId: string) => {
    try {
      const res = await authFetch(`${API_URL}/api/request-access`, {
        method: 'POST',
        body: JSON.stringify({ documentId }),
      });
      if (res.status === 403) {
        const data: RequestAccessResponse = await res.json();
        if (data.error === 'User blocked by admin') {
          await handleLogout();
        }
      }
    } catch (error) {
      console.error('Failed to request temporary access', error);
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
    <div className={`min-h-screen font-sans flex flex-col md:flex-row animate-fade-in transition-colors ${theme === 'dark' ? 'bg-slate-950 text-slate-100' : 'bg-vault-bg text-text-primary'}`}>

      {/* Sidebar */}
      <aside className={`w-full md:w-64 border-r flex flex-col shrink-0 transition-colors ${theme === 'dark' ? 'bg-slate-900 border-slate-800 text-slate-100' : 'bg-vault-sidebar border-vault-border text-text-inverse'}`}>
        <div className={`p-6 border-b ${theme === 'dark' ? 'border-slate-800' : 'border-vault-border'}`}>
          <h1 className="text-xl font-bold font-mono tracking-tighter flex items-center gap-2">
            <div className="w-3 h-3 bg-primary rounded-full animate-pulse"></div>
            SENTINEL<span className="text-primary">ZERO</span>
          </h1>
          <p className={`text-xs mt-1 ${theme === 'dark' ? 'text-slate-400' : 'text-text-muted'}`}>Secure Knowledge Vault</p>
        </div>

        <nav className="flex-1 p-4 space-y-2">
          <div className={`px-4 pt-2 pb-1 text-[11px] uppercase tracking-wider font-semibold ${theme === 'dark' ? 'text-slate-500' : 'text-text-muted'}`}>
            Departments
          </div>
          {departments.map((department) => (
            <button
              key={department}
              onClick={() => {
                setActiveTab('documents');
                setSelectedDepartment(department);
              }}
              className={`w-full text-left px-4 py-3 rounded-lg flex items-center gap-3 transition-all ${
                activeTab === 'documents' && selectedDepartment === department
                  ? 'bg-primary/20 text-primary border border-primary/30'
                  : theme === 'dark' ? 'text-slate-400 hover:bg-slate-800/90' : 'text-text-muted hover:bg-white/5'
              }`}
            >
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7h18M3 12h18M3 17h18" />
              </svg>
              <span className="text-sm font-medium">{department}</span>
            </button>
          ))}

          {currentUser.role === 'Admin' && (
            <button
              onClick={() => setActiveTab('admin')}
              className={`w-full text-left px-4 py-3 rounded-lg flex items-center gap-3 transition-all ${
                activeTab === 'admin'
                  ? 'bg-primary/20 text-primary border border-primary/30'
                  : theme === 'dark' ? 'text-slate-400 hover:bg-slate-800/90' : 'text-text-muted hover:bg-white/5'
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
        <div className={`p-4 border-t ${theme === 'dark' ? 'border-slate-800' : 'border-vault-border'}`}>
          <div className="flex items-center gap-3">
            <img src={currentUser.avatar} alt={currentUser.name} className="w-9 h-9 rounded-full border-2 border-primary/30" />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold truncate">{currentUser.name}</p>
              <p className={`text-xs ${theme === 'dark' ? 'text-slate-400' : 'text-text-muted'}`}>{currentUser.role}</p>
            </div>
            <button onClick={handleLogout} title="Logout" className={`${theme === 'dark' ? 'text-slate-400' : 'text-text-muted'} hover:text-danger transition-colors`}>
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
              </svg>
            </button>
          </div>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 flex flex-col overflow-hidden">
        <header className={`px-6 py-4 border-b flex items-center justify-between ${theme === 'dark' ? 'border-slate-800 bg-slate-900/70' : 'border-vault-border bg-vault-surface/50'}`}>
          <h2 className={`text-lg font-bold ${theme === 'dark' ? 'text-slate-100' : 'text-text-primary'}`}>
            {activeTab === 'documents' ? `${selectedDepartment} Department` : 'Security Operations Center'}
          </h2>
          <div className="flex items-center gap-3">
<div
  className={`flex items-center gap-2 rounded-full border px-3 py-1.5 ${
    theme === 'dark'
      ? 'border-slate-700 bg-slate-800/70'
      : 'border-vault-border bg-white'
  }`}
>
  <span
    className={`text-[11px] font-semibold uppercase tracking-wider ${
      theme === 'light' ? 'text-primary' : 'text-slate-400'
    }`}
  >
    Light
  </span>

  <button
    type="button"
    onClick={() => setTheme(prev => (prev === 'light' ? 'dark' : 'light'))}
    className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
      theme === 'dark' ? 'bg-primary/80' : 'bg-slate-300'
    }`}
    aria-label="Toggle light and dark mode"
    aria-pressed={theme === 'dark'}
  >
    <span
      className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
        theme === 'dark' ? 'translate-x-6' : 'translate-x-1'
      }`}
    />
  </button>

  <span
    className={`text-[11px] font-semibold uppercase tracking-wider ${
      theme === 'dark' ? 'text-primary' : 'text-text-muted'
    }`}
  >
    Dark
  </span>
</div>
            {alerts.length > 0 && (
              <div className="hidden md:flex items-center gap-3 bg-danger/10 border border-danger/30 px-4 py-2 rounded-full">
                <span className="w-2 h-2 rounded-full bg-danger animate-pulse"></span>
                <span className="text-danger font-bold text-xs uppercase tracking-wider">Insider Threat Detected</span>
              </div>
            )}
          </div>
        </header>

        <div className="flex-1 overflow-y-auto p-6">
          {activeTab === 'documents' && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
              {MOCK_DOCUMENTS.map(doc => {
                if (doc.department !== selectedDepartment) return null;
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
                    className={`${theme === 'dark' ? 'bg-slate-900/90 hover:shadow-slate-950/50' : 'bg-vault-surface'} border ${borderColor} rounded-xl p-6 cursor-pointer transition-all duration-300 hover:shadow-lg hover:-translate-y-1 group relative overflow-hidden`}>
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
                    <h3 className={`text-lg font-bold mb-1 group-hover:text-primary ${theme === 'dark' ? 'text-slate-100' : 'text-text-primary'}`}>{doc.title}</h3>
                    <p className={`text-xs mb-4 ${theme === 'dark' ? 'text-slate-400' : 'text-text-secondary'}`}>{doc.department} Dept.</p>
                    <div className={`flex items-center text-xs ${theme === 'dark' ? 'text-slate-500' : 'text-text-muted'}`}>
                      <span className="mr-2">ID: {doc.id}</span>
                      <span className={`w-1 h-1 rounded-full mx-1 ${theme === 'dark' ? 'bg-slate-500' : 'bg-text-muted'}`}></span>
                      <span>Encrypted</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {activeTab === 'admin' && (
            <ThreatDashboard logs={logs} alerts={alerts} currentUser={currentUser} authFetch={authFetch} onBlocked={handleLogout} />
          )}
        </div>
      </main>

      <AccessDenyModal log={deniedLog} onClose={() => setDeniedLog(null)} onRequestAccess={handleRequestAccess} />
      {openDocument && (
        <DocumentReader document={openDocument} user={currentUser} onClose={() => setOpenDocument(null)} />
      )}
    </div>
  );
}

export default App;
