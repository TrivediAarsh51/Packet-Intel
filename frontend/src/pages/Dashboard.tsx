import React, { useEffect, useState, useCallback } from 'react';
import { 
  Activity, 
  ShieldAlert, 
  Layers, 
  Cpu, 
  Clock, 
  FileCheck, 
  Trash2,
  AlertTriangle,
  FolderOpen
} from 'lucide-react';
import { 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  AreaChart,
  Area,
  PieChart,
  Pie,
  Cell
} from 'recharts';
import { packetService, authService } from '../services/api';
import { hasPermission } from '../utils/permissions';
import UploadPCAP from '../components/UploadPCAP';

const PROTO_COLORS = ['#3b82f6', '#8b5cf6', '#10b981', '#f59e0b', '#ef4444', '#ec4899', '#14b8a6', '#6366f1'];

const StatCard = ({ title, value, label, icon: Icon, color }: any) => (
  <div className="glass-card p-6">
    <div className="flex justify-between items-start mb-4">
      <div className={`p-3 rounded-xl bg-${color}-500/10 text-${color}-400 border border-${color}-500/20`}>
        <Icon size={22} />
      </div>
      <span className="text-[10px] text-slate-500 font-semibold tracking-wider uppercase bg-slate-900 border border-slate-800 px-2 py-0.5 rounded-full">
        Real-time
      </span>
    </div>
    <h3 className="text-slate-400 text-sm font-medium">{title}</h3>
    <p className="text-3xl font-bold text-white mt-1.5 tracking-tight">{value}</p>
    <p className="text-xs text-slate-500 mt-1">{label}</p>
  </div>
);

const Dashboard: React.FC = () => {
  const [sessions, setSessions] = useState<any[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState<number | undefined>(undefined);
  const [stats, setStats] = useState<any>(null);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const user = authService.getCurrentUser();
  const canDelete = hasPermission(user, 'delete_session');

  const loadDashboardData = useCallback(async () => {
    setLoading(true);
    try {
      // Load sessions
      const sessionsList = await packetService.getSessions();
      setSessions(sessionsList);

      // Default to the first session if none selected and sessions exist
      let currentSessionId = selectedSessionId;
      if (currentSessionId === undefined && sessionsList.length > 0) {
        currentSessionId = sessionsList[0].id;
        setSelectedSessionId(currentSessionId);
      }

      // Fetch stats
      const dashboardStats = await packetService.getDashboardStats(currentSessionId);
      setStats(dashboardStats);

      // Fetch alerts
      const alertsList = await packetService.getAlerts(currentSessionId);
      setAlerts(alertsList);
      
      setError('');
    } catch (err: any) {
      console.error(err);
      setError('Could not load dashboard metrics. Check backend connection.');
    } finally {
      setLoading(false);
    }
  }, [selectedSessionId]);

  useEffect(() => {
    loadDashboardData();
  }, [loadDashboardData]);

  // Acknowledge alert helper
  const handleAcknowledgeAlert = async (id: number) => {
    try {
      await packetService.acknowledgeAlert(id);
      // Reload alerts
      const alertsList = await packetService.getAlerts(selectedSessionId);
      setAlerts(alertsList);
    } catch (err) {
      console.error(err);
    }
  };

  // Delete session helper
  const handleDeleteSession = async (id: number) => {
    if (!window.confirm("Are you sure you want to delete this session and all its parsed packet logs?")) {
      return;
    }
    try {
      await packetService.deleteSession(id);
      if (selectedSessionId === id) {
        setSelectedSessionId(undefined);
      }
      loadDashboardData();
    } catch (err) {
      console.error(err);
    }
  };

  const handleUploadSuccess = () => {
    loadDashboardData();
  };

  const selectedSession = sessions.find(s => s.id === selectedSessionId);

  // Format bytes
  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="space-y-8">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h1 className="text-3xl font-display font-bold text-white tracking-tight">Security Incident Dashboard</h1>
          <p className="text-slate-400 mt-1">Deep Packet Inspection & Network Forensic Intelligence</p>
        </div>

        {/* Session Selector */}
        <div className="flex items-center gap-3">
          <FolderOpen size={18} className="text-slate-400" />
          <select 
            className="bg-slate-900 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-200 outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all cursor-pointer min-w-[200px]"
            value={selectedSessionId || ''}
            onChange={(e) => setSelectedSessionId(e.target.value ? Number(e.target.value) : undefined)}
          >
            <option value="">All Sessions (Combined)</option>
            {sessions.map((session) => (
              <option key={session.id} value={session.id}>
                {session.name} ({session.status})
              </option>
            ))}
          </select>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-rose-500/10 border border-rose-500/20 rounded-xl flex items-center gap-3 text-rose-400 text-sm">
          <AlertTriangle size={20} className="shrink-0" />
          <div>{error}</div>
        </div>
      )}

      {/* Grid of Stats Cards & Ingest Component */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2 grid grid-cols-1 md:grid-cols-2 gap-6">
          <StatCard 
            title="Ingested Packets" 
            value={stats?.total_packets?.toLocaleString() || '0'} 
            label="Total parsed frame events" 
            icon={Activity} 
            color="blue" 
          />
          <StatCard 
            title="Threat Flags" 
            value={stats?.total_alerts || '0'} 
            label="Suspicious packet anomalies" 
            icon={ShieldAlert} 
            color="rose" 
          />
          <StatCard 
            title="Capture Files" 
            value={stats?.total_sessions || '0'} 
            label="Active storage partitions" 
            icon={Layers} 
            color="emerald" 
          />
          <StatCard 
            title="Active Session status" 
            value={selectedSession ? selectedSession.status.toUpperCase() : 'ALL'} 
            label={selectedSession ? `Hash: ${selectedSession.sha256_hash?.substring(0, 16) || 'N/A'}...` : 'Consolidated threat feed'} 
            icon={Cpu} 
            color="amber" 
          />
        </div>
        <div>
          <UploadPCAP onUploadSuccess={handleUploadSuccess} />
        </div>
      </div>

      {/* Charts section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Main Traffic Chart */}
        <div className="lg:col-span-2 glass-card p-6">
          <h3 className="text-lg font-semibold mb-6 text-white flex items-center gap-2">
            <Clock size={18} className="text-slate-400" />
            Bandwidth Utilization Timeframe (Bytes/min)
          </h3>
          <div className="h-80 w-full">
            {stats?.traffic_over_time && stats.traffic_over_time.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={stats.traffic_over_time}>
                  <defs>
                    <linearGradient id="colorBytes" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                  <XAxis dataKey="time" stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} />
                  <YAxis stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} tickFormatter={(val) => formatBytes(val)} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }}
                    itemStyle={{ color: '#cbd5e1' }}
                    labelStyle={{ color: '#64748b', fontWeight: 'bold' }}
                    formatter={(val: any) => [formatBytes(val), 'Bytes']}
                  />
                  <Area type="monotone" dataKey="bytes" stroke="#3b82f6" fillOpacity={1} fill="url(#colorBytes)" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-slate-500 text-sm">
                No active traffic data available for this session.
              </div>
            )}
          </div>
        </div>

        {/* Protocol Share */}
        <div className="glass-card p-6">
          <h3 className="text-lg font-semibold mb-6 text-white">L4/L7 Protocol Share</h3>
          <div className="h-56 w-full flex items-center justify-center">
            {stats?.top_protocols && stats.top_protocols.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={stats.top_protocols}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={75}
                    paddingAngle={4}
                    dataKey="count"
                    nameKey="name"
                  >
                    {stats.top_protocols.map((entry: any, index: number) => (
                      <Cell key={`cell-${index}`} fill={PROTO_COLORS[index % PROTO_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }}
                    itemStyle={{ color: '#cbd5e1' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-slate-500 text-sm">No protocols detected</div>
            )}
          </div>
          <div className="mt-4 space-y-2 max-h-36 overflow-y-auto custom-scrollbar pr-2">
            {stats?.top_protocols?.map((proto: any, idx: number) => {
              const total = stats.top_protocols.reduce((acc: number, curr: any) => acc + curr.count, 0);
              return (
                <div key={proto.name} className="flex justify-between items-center text-sm">
                  <div className="flex items-center gap-2">
                    <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: PROTO_COLORS[idx % PROTO_COLORS.length] }}></div>
                    <span className="text-slate-300 font-mono text-xs">{proto.name}</span>
                  </div>
                  <span className="font-semibold text-white">
                    {((proto.count / (total || 1)) * 100).toFixed(1)}%
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Forensic Alerts Feed */}
      <div className="glass-card overflow-hidden">
        <div className="p-6 border-b border-slate-800 flex justify-between items-center bg-slate-900/40">
          <div>
            <h3 className="text-lg font-semibold text-white">Security Alerts Intelligence</h3>
            <p className="text-xs text-slate-500 mt-0.5">IDS pattern logs triggered during PCAP analysis</p>
          </div>
        </div>
        <div className="overflow-x-auto">
          {alerts.length > 0 ? (
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-900/80 text-slate-400 text-[10px] uppercase tracking-wider border-b border-slate-850">
                  <th className="px-6 py-4 font-medium">Timestamp</th>
                  <th className="px-6 py-4 font-medium">Risk Signature</th>
                  <th className="px-6 py-4 font-medium">Source IP</th>
                  <th className="px-6 py-4 font-medium">Destination IP</th>
                  <th className="px-6 py-4 font-medium">Severity</th>
                  <th className="px-6 py-4 font-medium">Description</th>
                  <th className="px-6 py-4 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850">
                {alerts.map((alert) => (
                  <tr key={alert.id} className={`hover:bg-slate-900/30 transition-colors ${alert.is_acknowledged ? 'opacity-40' : ''}`}>
                    <td className="px-6 py-4 text-xs whitespace-nowrap text-slate-500">
                      {new Date(alert.created_at).toLocaleTimeString()}
                    </td>
                    <td className="px-6 py-4 text-sm font-semibold text-slate-200 font-mono">{alert.alert_type}</td>
                    <td className="px-6 py-4 text-sm text-slate-400 font-mono">{alert.src_ip || 'N/A'}</td>
                    <td className="px-6 py-4 text-sm text-slate-400 font-mono">{alert.dst_ip || 'N/A'}</td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        alert.severity === 'high' 
                          ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20' 
                          : alert.severity === 'medium'
                            ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                            : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                      }`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-xs text-slate-400 max-w-xs truncate">{alert.description}</td>
                    <td className="px-6 py-4">
                      {!alert.is_acknowledged ? (
                        <button 
                          onClick={() => handleAcknowledgeAlert(alert.id)}
                          className="px-2.5 py-1 text-xs bg-slate-850 hover:bg-slate-750 text-blue-400 hover:text-blue-300 rounded-lg border border-slate-800 font-medium transition-colors"
                        >
                          Acknowledge
                        </button>
                      ) : (
                        <span className="text-xs text-slate-500 font-medium">Acknowledged</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="py-12 text-center text-slate-500 text-sm">
              No alert flags triggered. Network session clean.
            </div>
          )}
        </div>
      </div>

      {/* Captured PCAP Sessions Management */}
      <div className="glass-card overflow-hidden">
        <div className="p-6 border-b border-slate-800 flex justify-between items-center bg-slate-900/40">
          <div>
            <h3 className="text-lg font-semibold text-white">Capture Session Archives</h3>
            <p className="text-xs text-slate-500 mt-0.5">Manage and audit uploaded network captures</p>
          </div>
        </div>
        <div className="overflow-x-auto">
          {sessions.length > 0 ? (
            <table className="w-full text-left">
              <thead>
                <tr className="bg-slate-900/80 text-slate-400 text-[10px] uppercase tracking-wider">
                  <th className="px-6 py-4 font-medium">File Name</th>
                  <th className="px-6 py-4 font-medium">SHA256 Hash</th>
                  <th className="px-6 py-4 font-medium">Status</th>
                  <th className="px-6 py-4 font-medium">Packets</th>
                  <th className="px-6 py-4 font-medium">Size</th>
                  <th className="px-6 py-4 font-medium">Ingested At</th>
                  <th className="px-6 py-4 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850">
                {sessions.map((session) => (
                  <tr key={session.id} className="hover:bg-slate-900/20 transition-colors group">
                    <td className="px-6 py-4 text-sm font-semibold text-slate-200">{session.name}</td>
                    <td className="px-6 py-4 text-xs font-mono text-slate-500">{session.sha256_hash || 'Calculating...'}</td>
                    <td className="px-6 py-4 text-sm">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        session.status === 'completed' 
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' 
                          : session.status === 'processing'
                            ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20 animate-pulse'
                            : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                      }`}>
                        {session.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-slate-400 font-mono">{session.packet_count?.toLocaleString()}</td>
                    <td className="px-6 py-4 text-sm text-slate-400 font-mono">{formatBytes(session.file_size)}</td>
                    <td className="px-6 py-4 text-xs text-slate-500">{new Date(session.created_at).toLocaleString()}</td>
                    <td className="px-6 py-4">
                      {canDelete && (
                        <button 
                          onClick={() => handleDeleteSession(session.id)}
                          className="p-1.5 hover:bg-rose-500/10 text-slate-500 hover:text-rose-400 rounded-lg transition-colors border border-transparent hover:border-rose-500/20"
                        >
                          <Trash2 size={16} />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="py-12 text-center text-slate-500 text-sm">
              No capture sessions uploaded. Start by ingesting a PCAP file.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
