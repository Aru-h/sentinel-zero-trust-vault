import React, { useState } from 'react';
import { User } from '../types';
import { API_URL } from '../constants';

interface LoginScreenProps {
  onLogin: (user: User) => void;
}

export const LoginScreen: React.FC<LoginScreenProps> = ({ onLogin }) => {
  const [userIdInput, setUserIdInput] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isAnimating, setIsAnimating] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isAnimating) return;
    
    setError('');

    if (!userIdInput.trim() || !password.trim()) {
      setError('Credentials required.');
      return;
    }

    setIsAnimating(true);

    try {
      // SECURITY PATCH: Send credentials to backend. Do not validate in browser.
      const response = await fetch(`${API_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: userIdInput, password: password }),
        credentials: 'include' // Important: Accept the HttpOnly session cookie
      });

      const data = await response.json();

      if (response.ok && data.success) {
        // Normalize backend user to frontend User type
        const user: User = {
          id: data.user.id,
          name: data.user.name,
          role: data.user.role,
          avatar: `https://picsum.photos/seed/${data.user.id}/100/100`
        };
        onLogin(user);
      } else {
        setIsAnimating(false);
        setError(data.error || 'Authentication Failed.');
      }
    } catch (err) {
      setIsAnimating(false);
      setError('Connection Error. Ensure Backend is running.');
    }
  };

  return (
    <div className="min-h-screen bg-background flex flex-col items-center justify-center p-4 relative overflow-hidden">
      {/* Background Cyber-grid effect */}
      <div className="absolute inset-0 bg-[linear-gradient(rgba(15,23,42,0.9),rgba(15,23,42,0.9)),url('https://img.freepik.com/free-vector/dark-hexagonal-background-with-gradient-color_79603-1409.jpg')] bg-cover bg-center z-0"></div>
      
      <div className="relative z-10 w-full max-w-md shadow-[0_0_100px_rgba(59,130,246,0.2)] rounded-2xl overflow-hidden border border-gray-800 bg-black/80 backdrop-blur-xl">
        
        <div className="p-8">
          <div className="mb-8 text-center">
            <h1 className="text-3xl font-black text-white tracking-widest font-mono">SENTINEL<span className="text-primary">ZERO</span></h1>
            <p className="text-xs text-primary/80 uppercase tracking-[0.3em] mt-1">Secure Access Gateway</p>
          </div>

          <form onSubmit={handleLogin} className="space-y-6">
            
            <div className="space-y-1 group">
              <label className="block text-[10px] uppercase text-gray-500 font-bold mb-1 tracking-wider">User Identity</label>
              <div className="relative">
                <input 
                  type="text" 
                  value={userIdInput}
                  onChange={(e) => setUserIdInput(e.target.value)}
                  placeholder="Username"
                  className="w-full bg-surface border border-gray-700 rounded p-3 pl-4 text-gray-900 font-mono placeholder-gray-600 focus:outline-none focus:border-primary focus:shadow-[0_0_20px_rgba(59,130,246,0.2)] transition-all"
                  autoComplete="off"
                />
              </div>
            </div>

            <div className="space-y-1 group">
              <label className="block text-[10px] uppercase text-gray-500 font-bold mb-1 tracking-wider">Password</label>
              <div className="relative">
                <input 
                  type="password" 
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full bg-gray-800 border border-gray-600 rounded p-3 pl-4 text-yellow-100 caret-blue-400 font-mono placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all"
                />
              </div>
            </div>

            {error && (
              <div className="bg-red-500/10 border border-red-500/50 text-red-400 text-xs p-3 rounded flex items-center gap-2 animate-pulse">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={isAnimating}
              className="w-full relative overflow-hidden h-12 rounded font-bold tracking-widest uppercase transition-all duration-300 bg-primary hover:bg-blue-600 text-white shadow-[0_0_30px_rgba(59,130,246,0.4)] disabled:opacity-70 disabled:cursor-not-allowed"
            >
              <div className="relative z-10 flex items-center justify-center gap-2">
                {isAnimating ? (
                  <>
                    <svg className="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    <span>VERIFYING...</span>
                  </>
                ) : (
                  <span>AUTHENTICATE</span>
                )}
              </div>
            </button>
          </form>
          
          <div className="mt-8 text-center space-y-2">
            <p className="text-[10px] text-gray-600 font-mono">ENCRYPTED GATEWAY // V.2.5.1-PATCHED</p>
          </div>
        </div>
      </div>
    </div>
  );
};