import React, { useState } from 'react';
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
    <div className="min-h-screen bg-background flex flex-col items-center justify-center p-4 relative overflow-hidden">
      <div className="absolute inset-0 bg-[linear-gradient(rgba(15,23,42,0.9),rgba(15,23,42,0.9)),url('https://img.freepik.com/free-vector/dark-hexagonal-background-with-gradient-color_79603-1409.jpg')] bg-cover bg-center z-0" />

      <div className="relative z-10 w-full max-w-md rounded-2xl overflow-hidden border border-gray-800 bg-black/80 backdrop-blur-xl shadow-[0_0_100px_rgba(59,130,246,0.2)]">
        <div className="p-8">
          <div className="mb-8 text-center">
            <h1 className="text-3xl font-black text-white tracking-widest font-mono">
              SENTINEL<span className="text-primary">ZERO</span>
            </h1>
            <p className="text-xs text-primary/80 uppercase tracking-[0.3em] mt-1">Secure Access Gateway</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-6" noValidate>
            <div className="space-y-1">
              <label htmlFor="username" className="block text-[10px] uppercase text-gray-500 font-bold font-mono tracking-widest">
                Identity
              </label>
              <input
                id="username"
                type="text"
                autoComplete="username"
                value={username}
                onChange={e => setUsername(e.target.value)}
                className="w-full bg-gray-900/50 border border-gray-700 rounded-lg px-4 py-3 text-white text-sm font-mono placeholder-gray-600 focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/30 transition-all"
                placeholder="username"
              />
            </div>

            <div className="space-y-1">
              <label htmlFor="password" className="block text-[10px] uppercase text-gray-500 font-bold font-mono tracking-widest">
                Credentials
              </label>
              <input
                id="password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                className="w-full bg-gray-900/50 border border-gray-700 rounded-lg px-4 py-3 text-white text-sm font-mono placeholder-gray-600 focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/30 transition-all"
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

          <p className="mt-8 text-center text-[10px] text-gray-600 font-mono">
            ENCRYPTED GATEWAY // V.3.0.0-HARDENED
          </p>
        </div>
      </div>
    </div>
  );
};
