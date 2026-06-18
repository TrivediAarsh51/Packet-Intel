import React, { useState, useEffect, useRef } from 'react';
import { 
  Activity, 
  Play, 
  Square, 
  AlertTriangle, 
  Wifi, 
  ShieldAlert, 
  Clock, 
  Cpu, 
  CheckCircle2, 
  FileText 
} from 'lucide-react';
import { packetService } from '../services/api';

const LiveCapture: React.FC = () => {
  const [interfaces, setInterfaces] = useState<any[]>([]);
  const [selectedInterface, setSelectedInterface] = useState('');
  const [sessionName, setSessionName] = useState('');
  const [description, setDescription] = useState('');

  // Sniffing states
  const [activeSession, setActiveSession] = useState<any>(null);
  const [isSniffing, setIsSniffing] = useState(false);
  const [packetCount, setPacketCount] = useState(0);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [latestPackets, setLatestPackets] = useState<any[]>([]);
  
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // References for timers/intervals
  const pollIntervalRef = useRef<any | null>(null);
  const timerRef = useRef<any | null>(null);

  // Fetch interfaces on mount
  useEffect(() => {
    const fetchInterfaces = async () => {
      try {
        const data = await packetService.getInterfaces();
        setInterfaces(data);
        if (data.length > 0) {
          // Select default interface if available (prefer loopback or Wi-Fi/Ethernet)
          const preferred = data.find((i: any) => 
            i.name.toLowerCase().includes('wi-fi') || 
            i.name.toLowerCase().includes('ethernet') || 
            i.id.includes('Loopback')
          );
          setSelectedInterface(preferred ? preferred.id : data[0].id);
        }
      } catch (err) {
        console.error(err);
        setError('Unable to load network adapters. Ensure backend has correct privileges.');
      }
    };
    fetchInterfaces();

    // Clean up timers on unmount
    return () => {
      stopIntervals();
    };
  }, []);

  const stopIntervals = () => {
    if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    if (timerRef.current) clearInterval(timerRef.current);
  };

  const handleStartSniffing = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const session = await packetService.startLiveCapture(
        selectedInterface,
        sessionName || undefined,
        description || undefined
      );

      setActiveSession(session);
      setIsSniffing(true);
      setPacketCount(0);
      setAlerts([]);
      setLatestPackets([]);
      setElapsedSeconds(0);

      // Start elapsed timer
      timerRef.current = setInterval(() => {
        setElapsedSeconds((prev) => prev + 1);
      }, 1000);

      // Start status polling interval (every 1.5 seconds)
      pollIntervalRef.current = setInterval(async () => {
        try {
          // Poll session status to get updated packet count
          const updatedSession = await packetService.getSession(session.id);
          setPacketCount(updatedSession.packet_count);
          
          if (updatedSession.status === 'completed' || updatedSession.status === 'failed') {
            handleSniffingStopped(updatedSession);
          }

          // Fetch recent alerts
          const sessionAlerts = await packetService.getAlerts(session.id);
          setAlerts(sessionAlerts);

          // Fetch latest sniffed packets (recent 10)
          const sessionPackets = await packetService.getPackets(session.id, 0, 10);
          setLatestPackets(sessionPackets);

        } catch (pollErr) {
          console.error('Error polling live capture stats:', pollErr);
        }
      }, 1500);

    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.detail || 'Failed to start sniffing session. Ensure Npcap driver is installed.');
      setIsSniffing(false);
    } finally {
      setLoading(false);
    }
  };

  const handleStopSniffing = async () => {
    if (!activeSession) return;
    setLoading(true);
    try {
      await packetService.stopLiveCapture(activeSession.id);
      
      // Fetch final details
      const finalSession = await packetService.getSession(activeSession.id);
      handleSniffingStopped(finalSession);
    } catch (err) {
      console.error(err);
      setError('Error halting capture session.');
    } finally {
      setLoading(false);
    }
  };

  const handleSniffingStopped = (session: any) => {
    stopIntervals();
    setIsSniffing(false);
    setActiveSession(session);
  };

  // Helper to format duration
  const formatDuration = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-display font-bold text-white tracking-tight">Live Sniff & Capture</h1>
        <p className="text-slate-400 mt-1">Bind to network sockets and run deep packet inspection in real-time</p>
      </div>

      {error && (
        <div className="p-4 bg-rose-500/10 border border-rose-500/20 rounded-xl flex items-center gap-3 text-rose-400 text-sm">
          <AlertTriangle size={20} className="shrink-0" />
          <div>{error}</div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-start">
        
        {/* Configuration Pane / Active sniffer status */}
        <div className="lg:col-span-1 space-y-6">
          
          {!isSniffing ? (
            <div className="glass-card p-6">
              <h3 className="text-lg font-semibold mb-6 text-white flex items-center gap-2">
                <Wifi size={18} className="text-blue-500" />
                Adapter Sniffer Bindings
              </h3>
              
              <form onSubmit={handleStartSniffing} className="space-y-6">
                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                    Network Interface Adapter
                  </label>
                  <select 
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-sm text-slate-200 outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all cursor-pointer"
                    value={selectedInterface}
                    onChange={(e) => setSelectedInterface(e.target.value)}
                    disabled={loading || interfaces.length === 0}
                  >
                    {interfaces.length === 0 ? (
                      <option>Detecting hardware adapters...</option>
                    ) : (
                      interfaces.map((i) => (
                        <option key={i.id} value={i.id}>
                          {i.name} ({i.description})
                        </option>
                      ))
                    )}
                  </select>
                  <p className="text-[10px] text-slate-500 mt-1.5 font-mono">
                    Device: {selectedInterface}
                  </p>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                    Capture Session Title
                  </label>
                  <input 
                    type="text"
                    placeholder="e.g. LAN Sniff - Host 1"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-sm text-slate-200 outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all"
                    value={sessionName}
                    onChange={(e) => setSessionName(e.target.value)}
                    disabled={loading}
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                    Forensic Notes
                  </label>
                  <textarea 
                    rows={3}
                    placeholder="Document intent, suspect IP, or scope details"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-4 text-sm text-slate-200 outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all resize-none"
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    disabled={loading}
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading || interfaces.length === 0}
                  className="w-full py-3 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-medium rounded-lg transition-all duration-200 shadow-lg shadow-blue-500/25 active:scale-[0.98] disabled:opacity-40 disabled:pointer-events-none flex items-center justify-center gap-2 text-sm font-semibold"
                >
                  <Play size={16} />
                  {loading ? 'Initializing Interface...' : 'Begin Sniffer Snare'}
                </button>
              </form>
            </div>
          ) : (
            <div className="glass-card p-6 border-blue-500/35 relative overflow-hidden">
              {/* Radar pulse animation */}
              <div className="absolute -top-12 -right-12 w-36 h-36 bg-blue-500/5 rounded-full flex items-center justify-center">
                <div className="w-24 h-24 bg-blue-500/5 rounded-full animate-ping"></div>
              </div>

              <h3 className="text-lg font-semibold mb-6 text-white flex items-center gap-2.5">
                <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></span>
                Active Live Capture
              </h3>

              <div className="space-y-6">
                <div className="flex items-center gap-4">
                  <div className="p-3 rounded-xl bg-blue-500/10 text-blue-400 border border-blue-500/20">
                    <Clock size={20} />
                  </div>
                  <div>
                    <p className="text-xs text-slate-500 font-semibold uppercase tracking-wider">Elapsed Sniff Duration</p>
                    <p className="text-2xl font-bold font-mono text-white mt-0.5">{formatDuration(elapsedSeconds)}</p>
                  </div>
                </div>

                <div className="flex items-center gap-4">
                  <div className="p-3 rounded-xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                    <Cpu size={20} />
                  </div>
                  <div>
                    <p className="text-xs text-slate-500 font-semibold uppercase tracking-wider">Snares Registered</p>
                    <p className="text-2xl font-bold font-mono text-white mt-0.5">{packetCount.toLocaleString()}</p>
                  </div>
                </div>

                <div className="flex items-center gap-4">
                  <div className="p-3 rounded-xl bg-rose-500/10 text-rose-400 border border-rose-500/20">
                    <ShieldAlert size={20} />
                  </div>
                  <div>
                    <p className="text-xs text-slate-500 font-semibold uppercase tracking-wider">Anomalies Detected</p>
                    <p className="text-2xl font-bold font-mono text-rose-450 mt-0.5">{alerts.length}</p>
                  </div>
                </div>

                <div className="pt-4 border-t border-slate-850">
                  <button
                    onClick={handleStopSniffing}
                    disabled={loading}
                    className="w-full py-3 bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white font-medium rounded-lg transition-all duration-200 shadow-lg shadow-red-500/20 active:scale-[0.98] disabled:opacity-40 disabled:pointer-events-none flex items-center justify-center gap-2 text-sm font-semibold"
                  >
                    <Square size={14} fill="currentColor" />
                    {loading ? 'Halting Sniffer...' : 'Halt Capture Session'}
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Post-Capture completed message */}
          {activeSession && !isSniffing && activeSession.status === 'completed' && (
            <div className="glass-card p-6 border-emerald-500/30">
              <div className="flex items-start gap-4">
                <div className="p-2.5 bg-emerald-500/10 text-emerald-500 rounded-lg border border-emerald-500/20 mt-0.5">
                  <CheckCircle2 size={18} />
                </div>
                <div>
                  <h4 className="font-semibold text-emerald-450 text-sm">Capture Completed Successfully</h4>
                  <p className="text-xs text-slate-400 mt-1">
                    Captured <span className="text-slate-200 font-bold font-mono">{activeSession.packet_count}</span> packets.
                  </p>
                  <p className="text-[10px] text-slate-500 mt-1 font-mono">
                    SHA256: {activeSession.sha256_hash?.substring(0, 32)}...
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Live Sniffed Packets & Alert Logs */}
        <div className="lg:col-span-2 space-y-6">
          {/* Live Alerts feed */}
          <div className="glass-card overflow-hidden">
            <div className="p-5 border-b border-slate-800 bg-slate-900/40">
              <h3 className="font-semibold text-white text-sm">IDS Anomalies (Live Session)</h3>
            </div>
            <div className="max-h-60 overflow-y-auto custom-scrollbar">
              {alerts.length > 0 ? (
                <div className="divide-y divide-slate-850">
                  {alerts.map((alert) => (
                    <div key={alert.id} className="p-4 flex gap-4 items-start hover:bg-slate-900/10">
                      <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase shrink-0 mt-0.5 ${
                        alert.severity === 'high' 
                          ? 'bg-rose-500/10 text-rose-400 border border-rose-500/25' 
                          : 'bg-amber-500/10 text-amber-400 border border-amber-500/25'
                      }`}>
                        {alert.severity}
                      </span>
                      <div className="flex-1">
                        <p className="text-xs font-semibold text-slate-200 font-mono">{alert.alert_type}</p>
                        <p className="text-[11px] text-slate-400 mt-0.5">{alert.description}</p>
                        <p className="text-[10px] text-slate-500 font-mono mt-1">
                          Src: {alert.src_ip || 'N/A'} &rarr; Dst: {alert.dst_ip || 'N/A'}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="py-8 text-center text-slate-500 text-xs font-mono">
                  {isSniffing ? 'Sniffing adapter sockets... No alert flags triggered yet.' : 'Incidents log empty.'}
                </div>
              )}
            </div>
          </div>

          {/* Real-time packet scrolling view */}
          <div className="glass-card overflow-hidden">
            <div className="p-5 border-b border-slate-800 bg-slate-900/40 flex justify-between items-center">
              <h3 className="font-semibold text-white text-sm">Snared Frames Feed (Recent 10)</h3>
              {isSniffing && (
                <span className="flex items-center gap-1.5 text-[10px] text-blue-400 font-semibold font-mono animate-pulse">
                  <Activity size={12} className="animate-spin" />
                  SCROLLING
                </span>
              )}
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="bg-slate-900/60 text-slate-400 text-[9px] uppercase tracking-wider border-b border-slate-850">
                    <th className="px-5 py-3 font-medium w-12">No.</th>
                    <th className="px-5 py-3 font-medium">Source IP</th>
                    <th className="px-5 py-3 font-medium">Destination IP</th>
                    <th className="px-5 py-3 font-medium w-16">Proto</th>
                    <th className="px-5 py-3 font-medium w-16">Size</th>
                    <th className="px-5 py-3 font-medium">Summary</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-850">
                  {latestPackets.length > 0 ? (
                    latestPackets.map((pkt) => (
                      <tr key={pkt.id} className="hover:bg-slate-900/20 transition-colors">
                        <td className="px-5 py-2.5 text-[10px] text-slate-500 font-mono">{pkt.packet_number}</td>
                        <td className="px-5 py-2.5 text-xs text-blue-400 font-mono font-semibold">{pkt.src_ip}</td>
                        <td className="px-5 py-2.5 text-xs text-emerald-400 font-mono font-semibold">{pkt.dst_ip}</td>
                        <td className="px-5 py-2.5">
                          <span className="px-1.5 py-0.5 rounded text-[8px] font-bold uppercase bg-slate-850 text-slate-300 font-mono">
                            {pkt.protocol}
                          </span>
                        </td>
                        <td className="px-5 py-2.5 text-[10px] text-slate-400 font-mono">{pkt.length} B</td>
                        <td className="px-5 py-2.5 text-[10px] text-slate-400 font-mono truncate max-w-xs">{pkt.raw_summary}</td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={6} className="py-12 text-center text-slate-500 text-xs font-mono">
                        {isSniffing ? 'Waiting for first frames...' : 'No frames captured in this session.'}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

        </div>

      </div>
    </div>
  );
};

export default LiveCapture;
