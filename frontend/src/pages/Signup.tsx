import React from 'react';
import { Link } from 'react-router-dom';
import { Shield } from 'lucide-react';

const Signup: React.FC = () => {
  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 text-slate-100 relative overflow-hidden px-4">
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-blue-500/10 rounded-full blur-[128px]"></div>
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-indigo-500/10 rounded-full blur-[128px]"></div>
      
      <div className="w-full max-w-md glass-card p-8 border border-slate-800 shadow-2xl relative z-10 text-center">
        <div className="flex flex-col items-center mb-8">
          <div className="w-12 h-12 bg-blue-600 rounded-xl flex items-center justify-center shadow-lg shadow-blue-500/30 mb-4 border border-blue-400/20 animate-pulse">
            <Shield size={26} className="text-white" />
          </div>
          <h2 className="text-2xl font-bold font-display tracking-tight bg-gradient-to-r from-white to-slate-400 bg-clip-text text-transparent">
            SIGNUP DISABLED
          </h2>
        </div>
        
        <p className="text-slate-400 mb-8">
          Public registration is disabled. All accounts are provisioned by the system administrator.
        </p>

        <Link to="/login" className="px-6 py-2 bg-blue-600 hover:bg-blue-500 rounded-lg text-white font-semibold transition-colors">
          Return to Login
        </Link>
      </div>
    </div>
  );
};

export default Signup;

