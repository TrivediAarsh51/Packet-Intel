import React, { useState, useEffect } from 'react';
import { Routes, Route, Link, useLocation, useNavigate } from 'react-router-dom';
import { 
  BarChart3, 
  Shield, 
  FileSearch, 
  Settings, 
  Bell, 
  User as UserIcon,
  Search,
  Activity,
  LogOut,
  HelpCircle
} from 'lucide-react';
import Dashboard from './pages/Dashboard';
import PacketExplorer from './pages/PacketExplorer';
import LiveCapture from './pages/LiveCapture';
import CrimeBoard from './pages/CrimeBoard';
import Login from './pages/Login';
import Signup from './pages/Signup';
import Forbidden from './pages/Forbidden';
import ResetPassword from './pages/ResetPassword';
import UserManagement from './pages/UserManagement';
import ProtectedRoute from './components/ProtectedRoute';
import { authService } from './services/api';
import { hasPermission } from './utils/permissions';

const App: React.FC = () => {
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const [user, setUser] = useState<any>(null);
  const location = useLocation();
  const navigate = useNavigate();

  // Check auth status
  const isAuthenticated = authService.isAuthenticated();

  useEffect(() => {
    if (!isAuthenticated) {
      if (location.pathname !== '/login' && location.pathname !== '/signup') {
        navigate('/login');
      }
    } else {
      setUser(authService.getCurrentUser());
      if (location.pathname === '/login' || location.pathname === '/signup') {
        navigate('/');
      }
    }
  }, [isAuthenticated, location.pathname, navigate]);

  const handleLogout = () => {
    authService.logout();
    setUser(null);
    navigate('/login');
  };

  // If on login/signup pages, render them without sidebar/header layout
  if (location.pathname === '/login' || location.pathname === '/signup' || location.pathname === '/reset-password') {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />
        <Route path="/reset-password" element={<ResetPassword />} />
      </Routes>
    );
  }

  const navItems = [
    { name: 'Dashboard', path: '/', icon: BarChart3 },
    { name: 'Packet Explorer', path: '/packets', icon: FileSearch },
    { name: 'Live Capture', path: '/live', icon: Activity, permission: 'manage_capture' },
    { name: 'Crime Board', path: '/crime', icon: Shield },
    { name: 'Users', path: '/users', icon: Settings, permission: 'manage_users' }
  ];

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 font-sans">
      {/* Sidebar */}
      <aside className={`bg-slate-900 border-r border-slate-800/80 transition-all duration-300 flex flex-col ${isSidebarOpen ? 'w-64' : 'w-20'}`}>
        <div className="p-6 flex items-center gap-3 border-b border-slate-800/50">
          <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center shadow-md shadow-blue-500/20 shrink-0">
            <Shield size={18} className="text-white" />
          </div>
          {isSidebarOpen && <span className="font-bold text-lg tracking-tight bg-gradient-to-r from-white to-slate-300 bg-clip-text text-transparent">K-NETSCAN</span>}
        </div>

        <nav className="flex-1 px-4 py-6 space-y-2 overflow-y-auto custom-scrollbar">
          {navItems.map((item) => {
            if (item.permission && user && !hasPermission(user, item.permission)) return null;
            const isActive = location.pathname === item.path;
            return (
              <Link
                key={item.name}
                to={item.path}
                className={`flex items-center gap-3 px-3.5 py-2.5 rounded-xl transition-all duration-200 group ${
                  isActive 
                    ? 'bg-blue-600/10 text-blue-400 border border-blue-500/20 font-semibold' 
                    : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
                }`}
              >
                <item.icon size={20} className={`shrink-0 ${isActive ? 'text-blue-450' : 'text-slate-500 group-hover:text-slate-400'}`} />
                {isSidebarOpen && <span className="text-sm">{item.name}</span>}
              </Link>
            );
          })}
        </nav>

        <div className="p-4 border-t border-slate-800/50">
          <button 
            onClick={handleLogout}
            className="flex items-center gap-3 w-full px-3.5 py-2.5 text-slate-400 hover:text-rose-450 hover:bg-rose-500/5 border border-transparent hover:border-rose-500/10 rounded-xl transition-all duration-250 font-medium"
          >
            <LogOut size={20} className="shrink-0" />
            {isSidebarOpen && <span className="text-sm">Logout</span>}
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Header */}
        <header className="h-16 bg-slate-900/40 backdrop-blur-md border-b border-slate-800/50 px-8 flex items-center justify-between z-10">
          <div className="flex items-center gap-3">
            <button 
              onClick={() => setIsSidebarOpen(!isSidebarOpen)}
              className="text-slate-500 hover:text-slate-350 p-1 rounded-lg hover:bg-slate-800/50 transition-colors mr-2 hidden md:block"
            >
              <Activity size={18} />
            </button>
            <div className="text-xs text-slate-500 font-medium border border-slate-800 rounded-full px-3 py-1 bg-slate-950 font-mono">
              ROLE: <span className="text-blue-400 font-semibold">{user?.role?.toUpperCase() || 'INVESTIGATOR'}</span>
            </div>
          </div>

          <div className="flex items-center gap-6">
            <button className="text-slate-500 hover:text-slate-300 relative transition-colors">
              <Bell size={18} />
              <span className="absolute top-0 right-0 w-1.5 h-1.5 bg-rose-500 rounded-full"></span>
            </button>
            <div className="flex items-center gap-3 pl-6 border-l border-slate-850">
              <div className="text-right">
                <p className="text-xs font-semibold text-slate-200">{user?.username || 'Investigator'}</p>
                <p className="text-[10px] text-slate-500 font-medium font-mono">{user?.email || 'ccb@agency.gov'}</p>
              </div>
              <div className="w-9 h-9 bg-slate-800 border border-slate-700/80 rounded-xl flex items-center justify-center shrink-0">
                <UserIcon size={18} className="text-slate-400" />
              </div>
            </div>
          </div>
        </header>

        {/* Content Area */}
        <div className="flex-1 overflow-y-auto p-8 custom-scrollbar">
          <Routes>
            <Route path="/" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
            <Route path="/packets" element={<ProtectedRoute><PacketExplorer /></ProtectedRoute>} />
            <Route path="/live" element={<ProtectedRoute requiredPermission="manage_capture"><LiveCapture /></ProtectedRoute>} />
            <Route path="/crime" element={<ProtectedRoute><CrimeBoard /></ProtectedRoute>} />
            <Route path="/users" element={<ProtectedRoute requiredPermission="manage_users"><UserManagement /></ProtectedRoute>} />
            <Route path="/403" element={<Forbidden />} />
          </Routes>
        </div>
      </main>
    </div>
  );
};


export default App;
