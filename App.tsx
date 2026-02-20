import React, { useState, useEffect } from 'react';
import { MOCK_DOCUMENTS, API_URL } from './constants';
import { User, Document, Role, AccessLog, ThreatAlert, AccessResult } from './types';
import { ThreatDashboard } from './components/ThreatDashboard';
import { AccessDenyModal } from './components/AccessDenyModal';
import { DocumentReader } from './components/DocumentReader';
import { LoginScreen } from './components/LoginScreen';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [logs, setLogs] = useState<AccessLog[]>([]);
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  
  // Modal states
  const [deniedLog, setDeniedLog] = useState<AccessLog | null>(null);
  const [openDocument, setOpenDocument] = useState<Document | null>(null);
  
  const [activeTab, setActiveTab] = useState<'documents' | 'admin'>('documents');

  // Check auth on mount (Persistence)
  useEffect(() => {
    const checkAuth = async () => {
      try {
        const res = await fetch(`${API_URL}/api/me`, { credentials: 'include' });
        if (res.ok) {
          const data = await res.json();
          setCurrentUser({
             id: data.user.id,
             name: data.user.name,
             role: data.user.role,
             avatar: `https://picsum.photos/seed/${data.user.id}/100/100`
          });
          setIsAuthenticated(true);
        }
      } catch (e) {
        console.log('Not authenticated');
      }
    };
    checkAuth();
  }, []);

  const handleLogin = (user: User) => {
    setCurrentUser(user);
    setIsAuthenticated(true);
  };

  const handleLogout = async () => {
    await fetch(`${API_URL}/logout`, { method: 'POST', credentials: 'include' });
    setIsAuthenticated(false);
    setCurrentUser(null);
  };

  const handleDocumentClick = async (doc: Document) => {
    try {
      // SECURITY PATCH: Ask the backend for permission.
      const res = await fetch(`${API_URL}/api/access`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ documentId: doc.id }),
        credentials: 'include'
      });
      
      const data = await res.json();

      if (res.status === 401) {
        handleLogout();
        return;
      }

      // Construct a log object for UI (Real log is in DB)
      const mockLogForUI: AccessLog = {
        id: Date.now().toString(),
        timestamp: Date.now(),
        userId: currentUser?.id || '',
        userName: currentUser?.name || '',
        userRole: currentUser?.role || Role.DEVELOPER,
        documentId: doc.id,
        documentTitle: doc.title,
        result: data.access,
        reason: data.reason
      };

      setLogs(prev => [mockLogForUI, ...prev]);

      if (data.threat_detected) {
        setAlerts(prev => [...prev, {
            id: Date.now().toString(),
            timestamp: Date.now(),
            userId: currentUser?.id || '',
            userName: currentUser?.name || '',
            severity: 'HIGH',
            description: 'Insider Threat Detected by Backend Security Engine'
        }]);
      }

      if (data.access === 'ALLOWED') {
        setOpenDocument(doc);
      } else {
        setDeniedLog(mockLogForUI);
      }

    } catch (e) {
      console.error("Access Request Failed", e);
    }
  };

  if (!isAuthenticated || !currentUser) {
    return <LoginScreen onLogin={handleLogin} />;
  }

  return (
    <div className="min-h-screen bg-vault-bg text-text-primary font-sans flex flex-col md:flex-row animate-fade-in">
    
      {/* Sidebar / Navigation */}
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
                 ? 'bg-primary/20 text-text-inverse border border-primary/40'
          : 'text-text-muted hover:bg-primary/10 hover:text-text-inverse'
                        }`}

           >
             <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
               <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 10h16M4 14h16M4 18h16" />
             </svg>
             Documents
           </button>
           
           {currentUser.role === Role.ADMIN && (
             <button
  onClick={() => setActiveTab('admin')}
  className={`w-full text-left px-4 py-3 rounded-lg flex items-center gap-3 transition-all ${
    activeTab === 'admin'
      ? 'bg-primary/20 text-text-inverse border border-primary/40'
      : 'text-text-muted hover:bg-primary/10 hover:text-text-inverse'
  }`}
>

               <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                 <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
               </svg>
               Admin Console
               {alerts.length > 0 && <span className="ml-auto bg-danger text-text-inverse text-[10px] font-bold px-1.5 py-0.5 rounded-full">{alerts.length}</span>}
             </button>
           )}
        </nav>

        {/* User Info & Logout */}
        <div className="p-4 bg-primary/5 border-t border-vault-border">
           <div className="flex items-center gap-3 mb-3">
              <img src={currentUser.avatar} alt="User" className="w-8 h-8 rounded-full border border-vault-border" />
              <div className="overflow-hidden">
                <p className="text-sm font-bold truncate">{currentUser.name}</p>
                <p className="text-[10px] text-text-muted uppercase tracking-wider">{currentUser.role}</p>
              </div>
           </div>
           <button 
             onClick={handleLogout} 
             className="w-full text-xs bg-red-500/10 text-red-400 hover:bg-red-500 hover:text-white py-2 rounded transition-colors"
           >
             SECURE LOGOUT
           </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-y-auto p-4 md:p-8 bg-vault-bg relative">
        <header className="mb-8 flex justify-between items-center">
           <div><h2 className="text-2xl font-bold text-text-primary tracking-tight">
  {activeTab === 'documents' 
    ? 'Knowledge Repository' 
    : 'Security Operations Center'}
</h2>

           </div>
           
           {/* Security Banner if threats exist */}
           {alerts.length > 0 && (
             <div className="hidden md:flex items-center gap-3 bg-danger/10 border border-danger/30 px-4 py-2 rounded-full animate-pulse-slow">
                <span className="w-2 h-2 rounded-full bg-danger"></span>
                <span className="text-danger font-bold text-xs uppercase tracking-wider">Insider Threat Detected</span>
             </div>
           )}
        </header>

        {activeTab === 'documents' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
            {MOCK_DOCUMENTS.map(doc => {
              // Determine visual style based on classification
              const borderColor = 
                doc.classification === 'Public' ? 'border-badge-public/40 hover:border-badge-public' :
                doc.classification === 'Internal' ? 'border-badge-internal/40 hover:border-badge-internal' :
                doc.classification === 'Confidential' ? 'border-badge-confidential/40 hover:border-badge-confidential' :
                  'border-badge-restricted/40 hover:border-badge-restricted';

              
              const iconColor = 
  doc.classification === 'Public' ? 'text-badge-public' :
  doc.classification === 'Internal' ? 'text-badge-internal' :
  doc.classification === 'Confidential' ? 'text-badge-confidential' :
  'text-badge-restricted';


              return (
                <div 
                  key={doc.id}
                  onClick={() => handleDocumentClick(doc)}
                  className={`bg-vault-surface border ${borderColor} rounded-xl p-6 cursor-pointer transition-all duration-300 hover:shadow-lg hover:-translate-y-1 group relative overflow-hidden`}
                >
                  <div className={`absolute top-0 right-0 p-2 opacity-10 group-hover:opacity-20 transition-opacity`}>
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-24 w-24" fill="currentColor" viewBox="0 0 24 24">
                       <path d="M7 3a1 1 0 000 2h6a1 1 0 100-2H7zM4 7a1 1 0 011-1h10a1 1 0 110 2H5a1 1 0 01-1-1zM2 11a2 2 0 012-2h12a2 2 0 012 2v4a2 2 0 01-2 2H4a2 2 0 01-2-2v-4z" />
                    </svg>
                  </div>

                  <div className="flex justify-between items-start mb-4">
                     <div className={`p-2 rounded-lg bg-black/30 ${iconColor}`}>
                        {doc.locked ? (
                          <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                          </svg>
                        ) : (
                          <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z" />
                          </svg>
                        )}
                     </div>
                     <span className={`text-[10px] uppercase font-bold tracking-wider border px-2 py-0.5 rounded ${iconColor} border-current opacity-70`}>
                       {doc.classification}
                     </span>
                  </div>
                  
                  <h3 className="text-lg font-bold text-text-primary mb-1 group-hover:text-primary">
  {doc.title}
</h3><p className="text-xs text-text-secondary mb-4">
  {doc.department} Dept.
</p>

                  <div className="flex items-center text-xs text-text-muted group-hover:text-text-secondary">
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
      </main>

      {/* Overlays */}
      <AccessDenyModal log={deniedLog} onClose={() => setDeniedLog(null)} />
      {openDocument && (
        <DocumentReader 
          document={openDocument} 
          user={currentUser} 
          onClose={() => setOpenDocument(null)} 
        />
      )}
    </div>
  );
}

export default App;