import React, { useMemo, useState } from 'react';
import { User, Role } from '../types';
import { API_URL } from '../constants';

interface LoginScreenProps {
  onLogin: (user: User, csrfToken: string) => void;
}

export const LoginScreen: React.FC<LoginScreenProps> = ({ onLogin }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError]       = useState('');
  const [loading, setLoading]   = useState(false);

  const demoUsers = useMemo(() => [
    { label: 'Admin', username: 'admin1' },
    { label: 'Finance', username: 'fin1' },
    { label: 'HR', username: 'hr1' },
    { label: 'Developer', username: 'dev1' },
  ], []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (loading) return;

    setError('');

    if (!username.trim() || !password.trim()) {
      setError('All fields are required.');
      return;
    }

    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password }),
        credentials: 'include',
      });

      const data = await res.json();

      if (res.status === 429) {
        setError('Too many attempts. Please wait a minute before trying again.');
        setLoading(false);
        return;
      }

      if (res.ok && data.success) {
        const user: User = {
          id:     data.user.id,
          name:   data.user.name,
          role:   data.user.role as Role,
          role_title: data.user.role_title,
          department: data.user.department,
          clearance_level: data.user.clearance_level,
          avatar: `https://picsum.photos/seed/${data.user.id}/100/100`,
        };
        // Pass CSRF token to parent — stored in React state, never in localStorage
        onLogin(user, data.csrf_token ?? '');
      } else {
        setLoading(false);
        // Generic error — never tell the client whether username or password was wrong
        setError('Authentication failed. Check your credentials.');
      }
    } catch {
      setLoading(false);
      setError('Connection error. Ensure the backend server is running.');
    }
  };

  return (
    <div className="min-h-screen bg-background relative overflow-hidden">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(59,130,246,0.2),transparent_40%),linear-gradient(rgba(15,23,42,0.95),rgba(2,6,23,0.95)),url('https://img.freepik.com/free-vector/dark-hexagonal-background-with-gradient-color_79603-1409.jpg')] bg-cover bg-center" />

      <div className="relative z-10 min-h-screen flex items-center justify-center p-4">
        <div className="w-full max-w-5xl grid lg:grid-cols-2 rounded-2xl overflow-hidden border border-gray-800/80 bg-black/70 backdrop-blur-xl shadow-[0_0_80px_rgba(59,130,246,0.15)]">
          <section className="hidden lg:flex flex-col justify-between p-10 border-r border-gray-800/80 bg-slate-950/60">
            <div>
              <p className="text-[11px] uppercase tracking-[0.35em] text-primary/80 font-mono">Sentinel Zero</p>
              <h2 className="mt-5 text-3xl font-black text-white leading-tight">Zero-Trust Access
                <span className="block text-primary">Control Center</span>
              </h2>
              <p className="mt-4 text-sm text-gray-400 leading-relaxed">Authenticate with your assigned role to access protected department repositories and monitored workflows.</p>
            </div>

            <div className="space-y-3">
              <p className="text-[10px] uppercase tracking-[0.2em] text-gray-500 font-mono">Demo Usernames</p>
              <div className="flex flex-wrap gap-2">
                {demoUsers.map((user) => (
                  <button
                    key={user.username}
                    type="button"
                    onClick={() => setUsername(user.username)}
                    className="px-3 py-1.5 rounded-full border border-primary/30 text-xs text-primary hover:bg-primary/10 transition-colors"
                  >
                    {user.label}: {user.username}
                  </button>
                ))}
              </div>
            </div>
          </section>

          <section className="p-6 sm:p-8 lg:p-10">
            <div className="mb-8 text-center lg:text-left">
              <h1 className="text-3xl font-black text-white tracking-widest font-mono">
                SENTINEL<span className="text-primary">ZERO</span>
              </h1>
              <p className="text-xs text-primary/80 uppercase tracking-[0.3em] mt-2">Secure Access Gateway</p>
            </div>

            <form onSubmit={handleSubmit} className="space-y-5" noValidate>
              <div className="space-y-1.5">
                <label htmlFor="username" className="block text-[10px] uppercase text-gray-500 font-bold font-mono tracking-widest">
                  Identity
                </label>
                <input
                  id="username"
                  type="text"
                  autoComplete="username"
                  value={username}
                  onChange={e => setUsername(e.target.value)}
                  className="w-full bg-gray-900/60 border border-gray-700 rounded-lg px-4 py-3 text-white text-sm font-mono placeholder-gray-600 focus:outline-none focus:border-primary/60 focus:ring-2 focus:ring-primary/20 transition-all"
                  placeholder="username"
                />
              </div>

              <div className="space-y-1.5">
                <label htmlFor="password" className="block text-[10px] uppercase text-gray-500 font-bold font-mono tracking-widest">
                  Credentials
                </label>
                <input
                  id="password"
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  className="w-full bg-gray-900/60 border border-gray-700 rounded-lg px-4 py-3 text-white text-sm font-mono placeholder-gray-600 focus:outline-none focus:border-primary/60 focus:ring-2 focus:ring-primary/20 transition-all"
                  placeholder="••••••••"
                />
              </div>

              {error && (
                <div role="alert" className="bg-red-900/30 border border-red-700/50 rounded-lg p-3 text-red-400 text-xs font-mono text-center">
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-primary hover:bg-primary/80 disabled:opacity-50 text-white font-bold py-3 rounded-lg transition-all font-mono uppercase tracking-widest text-sm flex items-center justify-center gap-2"
              >
                {loading ? (
                  <>
                    <svg className="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                    <span>VERIFYING...</span>
                  </>
                ) : (
                  <span>AUTHENTICATE</span>
                )}
              </button>
            </form>

            <p className="mt-8 text-center lg:text-left text-[10px] text-gray-600 font-mono">
              ENCRYPTED GATEWAY // V.3.1.0-UI
            </p>
          </section>
        </div>
      </div>
    </div>
  );
};
