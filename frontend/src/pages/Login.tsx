import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, Eye, EyeOff, Lock, User, AlertTriangle } from 'lucide-react';
import { authService } from '../services/api';

const Login: React.FC = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const result = await authService.login(username, password);
      if (result.force_reset) {
        navigate('/reset-password');
      } else {
        navigate('/');
      }
    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.detail || 'Invalid username or password. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 text-slate-100 relative overflow-hidden px-4">
      {/* Background glow effects */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-blue-500/10 rounded-full blur-[128px]"></div>
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-indigo-500/10 rounded-full blur-[128px]"></div>
      
      <div className="w-full max-w-md glass-card p-8 border border-slate-800 shadow-2xl relative z-10">
        <div className="flex flex-col items-center mb-8">
          <div className="w-12 h-12 bg-blue-600 rounded-xl flex items-center justify-center shadow-lg shadow-blue-500/30 mb-4 border border-blue-400/20 animate-pulse">
            <Shield size={26} className="text-white" />
          </div>
          <h2 className="text-2xl font-bold font-display tracking-tight bg-gradient-to-r from-white to-slate-400 bg-clip-text text-transparent">
            K-NETSCAN
          </h2>
          <p className="text-slate-400 text-sm mt-1">Network Forensics & Threat Intelligence</p>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-rose-500/10 border border-rose-500/20 rounded-lg flex items-start gap-3 text-rose-400 text-sm">
            <AlertTriangle size={18} className="shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
              Username
            </label>
            <div className="relative">
              <User size={18} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                required
                className="w-full bg-slate-900/60 border border-slate-800 rounded-lg pl-11 pr-4 py-2.5 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none transition-all duration-200"
                placeholder="Enter investigator ID"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                disabled={loading}
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
              Password
            </label>
            <div className="relative">
              <Lock size={18} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type={showPassword ? 'text' : 'password'}
                required
                className="w-full bg-slate-900/60 border border-slate-800 rounded-lg pl-11 pr-11 py-2.5 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none transition-all duration-200"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={loading}
              />
              <button
                type="button"
                className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
                onClick={() => setShowPassword(!showPassword)}
                disabled={loading}
              >
                {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
          </div>

          <button
            type="submit"
            className="w-full py-3 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-medium rounded-lg transition-all duration-200 shadow-lg shadow-blue-500/20 active:scale-[0.98] disabled:opacity-50 disabled:pointer-events-none text-sm font-semibold mt-8"
            disabled={loading}
          >
            {loading ? 'Authenticating...' : 'Sign In'}
          </button>
        </form>


      </div>
    </div>
  );
};

export default Login;
