import React, { useState, useEffect, useCallback } from 'react';
import { Filter, Search, Download, Eye, ArrowLeft, ArrowRight, ShieldAlert, FileText, ChevronRight } from 'lucide-react';
import { packetService } from '../services/api';

const PacketExplorer: React.FC = () => {
  const [sessions, setSessions] = useState<any[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState<number | undefined>(undefined);
  const [packets, setPackets] = useState<any[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  
  // Filtering & Pagination state
  const [srcIp, setSrcIp] = useState('');
  const [dstIp, setDstIp] = useState('');
  const [protocol, setProtocol] = useState('');
  const [skip, setSkip] = useState(0);
  const limit = 50;

  // Selected packet for detailed drawer
  const [selectedPacket, setSelectedPacket] = useState<any | null>(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Fetch session list
  useEffect(() => {
    const loadSessions = async () => {
      try {
        const sessionsList = await packetService.getSessions();
        setSessions(sessionsList);
        if (sessionsList.length > 0 && selectedSessionId === undefined) {
          setSelectedSessionId(sessionsList[0].id);
        }
      } catch (err) {
        console.error(err);
        setError('Failed to fetch capture session archives.');
      }
    };
    loadSessions();
  }, [selectedSessionId]);

  // Fetch packets
  const loadPackets = useCallback(async () => {
    if (selectedSessionId === undefined) return;
    setLoading(true);
    try {
      const filters = { srcIp, dstIp, protocol: protocol === 'ALL' ? undefined : protocol };
      const data = await packetService.getPackets(selectedSessionId, skip, limit, filters);
      setPackets(data);

      const countData = await packetService.getPacketsCount(selectedSessionId, filters);
      setTotalCount(countData.count);
      setError('');
    } catch (err) {
      console.error(err);
      setError('Error query packets from backend.');
    } finally {
      setLoading(false);
    }
  }, [selectedSessionId, skip, srcIp, dstIp, protocol]);

  useEffect(() => {
    loadPackets();
  }, [loadPackets]);

  // Reset pagination when session or filters change
  const handleFilterChange = () => {
    setSkip(0);
  };

  const handlePrevPage = () => {
    if (skip - limit >= 0) {
      setSkip(skip - limit);
    }
  };

  const handleNextPage = () => {
    if (skip + limit < totalCount) {
      setSkip(skip + limit);
    }
  };

  // CSV Export helper
  const handleExportCSV = () => {
    if (packets.length === 0) return;
    
    const headers = ['No.', 'Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Length', 'TTL', 'Flags', 'Summary'];
    const rows = packets.map(p => [
      p.packet_number,
      p.timestamp,
      p.src_ip,
      p.dst_ip,
      p.protocol,
      p.length,
      p.ttl || '',
      p.flags || '',
      p.raw_summary?.replace(/"/g, '""') || ''
    ]);

    const csvContent = "data:text/csv;charset=utf-8," 
      + [headers.join(','), ...rows.map(e => e.map(val => `"${val}"`).join(','))].join('\n');
    
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `session_${selectedSessionId}_packets.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="space-y-6 relative">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h1 className="text-3xl font-display font-bold text-white tracking-tight">Deep Packet Explorer</h1>
          <p className="text-slate-400 mt-1">Detailed protocol analysis, metadata headers & payload decoding</p>
        </div>
        <div className="flex items-center gap-3">
          <select 
            className="bg-slate-900 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-200 outline-none focus:border-blue-500 cursor-pointer min-w-[200px]"
            value={selectedSessionId || ''}
            onChange={(e) => {
              setSelectedSessionId(e.target.value ? Number(e.target.value) : undefined);
              setSkip(0);
              setSelectedPacket(null);
            }}
          >
            {sessions.map((session) => (
              <option key={session.id} value={session.id}>
                {session.name} ({session.packet_count} packets)
              </option>
            ))}
          </select>
          <button 
            onClick={handleExportCSV}
            disabled={packets.length === 0}
            className="flex items-center gap-2 px-4 py-2 bg-slate-900 hover:bg-slate-800 text-slate-200 hover:text-white rounded-lg transition-colors border border-slate-800 text-sm font-semibold disabled:opacity-50 disabled:pointer-events-none"
          >
            <Download size={16} />
            Export CSV
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-rose-500/10 border border-rose-500/20 rounded-lg text-rose-400 text-sm">
          {error}
        </div>
      )}

      {/* Filter Options Card */}
      <div className="glass-card p-4 grid grid-cols-1 md:grid-cols-4 gap-4 items-center">
        <div className="flex items-center gap-3 bg-slate-950 border border-slate-800 px-4 py-2 rounded-lg">
          <Search size={16} className="text-slate-500" />
          <input 
            type="text" 
            placeholder="Src IP..." 
            className="bg-transparent border-none outline-none text-xs w-full text-slate-200 placeholder:text-slate-600"
            value={srcIp}
            onChange={(e) => { setSrcIp(e.target.value); handleFilterChange(); }}
          />
        </div>
        <div className="flex items-center gap-3 bg-slate-950 border border-slate-800 px-4 py-2 rounded-lg">
          <Search size={16} className="text-slate-500" />
          <input 
            type="text" 
            placeholder="Dst IP..." 
            className="bg-transparent border-none outline-none text-xs w-full text-slate-200 placeholder:text-slate-600"
            value={dstIp}
            onChange={(e) => { setDstIp(e.target.value); handleFilterChange(); }}
          />
        </div>
        <div>
          <select 
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-xs text-slate-300 outline-none focus:border-blue-500 cursor-pointer"
            value={protocol}
            onChange={(e) => { setProtocol(e.target.value); handleFilterChange(); }}
          >
            <option value="">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="HTTP">HTTP</option>
            <option value="HTTPS">HTTPS</option>
            <option value="DNS">DNS</option>
            <option value="ICMP">ICMP</option>
            <option value="DHCP">DHCP</option>
            <option value="SSH">SSH</option>
          </select>
        </div>
        <div className="text-right text-xs text-slate-500">
          Matched: <span className="text-blue-400 font-semibold">{totalCount.toLocaleString()}</span> frames
        </div>
      </div>

      <div className="flex gap-6 items-start">
        {/* Packet Table Card */}
        <div className="flex-1 glass-card overflow-hidden">
          <div className="overflow-x-auto custom-scrollbar">
            <table className="w-full text-left">
              <thead>
                <tr className="bg-slate-900/80 text-slate-400 text-[10px] uppercase tracking-widest border-b border-slate-850">
                  <th className="px-6 py-4 font-medium w-16">No.</th>
                  <th className="px-6 py-4 font-medium w-24">Time</th>
                  <th className="px-6 py-4 font-medium">Source IP</th>
                  <th className="px-6 py-4 font-medium">Destination IP</th>
                  <th className="px-6 py-4 font-medium w-24">Protocol</th>
                  <th className="px-6 py-4 font-medium w-20">Length</th>
                  <th className="px-6 py-4 font-medium max-w-xs">Frame Summary</th>
                  <th className="px-6 py-4 font-medium w-12 text-center">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850">
                {loading ? (
                  <tr>
                    <td colSpan={8} className="py-12 text-center text-slate-500 text-sm">
                      <div className="inline-block animate-spin border-2 border-t-blue-500 border-blue-500/10 rounded-full w-6 h-6 mr-3 align-middle"></div>
                      Loading session packet feed...
                    </td>
                  </tr>
                ) : packets.length > 0 ? (
                  packets.map((pkt) => (
                    <tr 
                      key={pkt.id} 
                      onClick={() => setSelectedPacket(pkt)}
                      className={`hover:bg-slate-900/30 transition-colors cursor-pointer group ${
                        selectedPacket?.id === pkt.id ? 'bg-blue-600/10 border-l-2 border-blue-500' : ''
                      }`}
                    >
                      <td className="px-6 py-3.5 text-xs text-slate-500 font-mono">{pkt.packet_number}</td>
                      <td className="px-6 py-3.5 text-xs text-slate-400">
                        {new Date(pkt.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="px-6 py-3.5 text-sm text-blue-400 font-mono">{pkt.src_ip || 'N/A'}</td>
                      <td className="px-6 py-3.5 text-sm text-emerald-400 font-mono">{pkt.dst_ip || 'N/A'}</td>
                      <td className="px-6 py-3.5">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-blue-500/10 text-blue-400 border border-blue-500/20 font-mono">
                          {pkt.protocol}
                        </span>
                      </td>
                      <td className="px-6 py-3.5 text-sm text-slate-400 font-mono">{pkt.length} B</td>
                      <td className="px-6 py-3.5 text-xs text-slate-300 font-mono truncate max-w-xs">
                        {pkt.raw_summary}
                      </td>
                      <td className="px-6 py-3.5 text-center">
                        <ChevronRight size={16} className="text-slate-600 group-hover:text-slate-300 transition-colors inline-block" />
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={8} className="py-12 text-center text-slate-500 text-sm">
                      No matching packets found in this capture log.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          
          {/* Pagination bar */}
          <div className="p-4 border-t border-slate-850 flex items-center justify-between bg-slate-900/20">
            <p className="text-xs text-slate-500">
              Showing <span className="text-slate-300 font-semibold">{packets.length > 0 ? skip + 1 : 0}</span> to{' '}
              <span className="text-slate-300 font-semibold">{skip + packets.length}</span> of{' '}
              <span className="text-slate-300 font-semibold">{totalCount.toLocaleString()}</span> frames
            </p>
            <div className="flex gap-2">
              <button 
                onClick={handlePrevPage}
                disabled={skip === 0}
                className="p-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg text-slate-400 hover:text-white transition-colors disabled:opacity-30 disabled:pointer-events-none"
              >
                <ArrowLeft size={16} />
              </button>
              <button 
                onClick={handleNextPage}
                disabled={skip + limit >= totalCount}
                className="p-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg text-slate-400 hover:text-white transition-colors disabled:opacity-30 disabled:pointer-events-none"
              >
                <ArrowRight size={16} />
              </button>
            </div>
          </div>
        </div>

        {/* Detailed Packet Inspection Drawer */}
        {selectedPacket && (
          <div className="w-96 glass-card p-6 border border-slate-800 space-y-6 slide-in shrink-0">
            <div className="flex justify-between items-center pb-4 border-b border-slate-800">
              <div>
                <h3 className="font-bold text-white text-base">Frame #{selectedPacket.packet_number}</h3>
                <p className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold mt-0.5">Deep Packet Inspection</p>
              </div>
              <button 
                onClick={() => setSelectedPacket(null)}
                className="text-xs text-slate-500 hover:text-slate-300 font-medium"
              >
                Close (Esc)
              </button>
            </div>

            {/* Key details */}
            <div className="space-y-4">
              <div>
                <h4 className="text-xs text-slate-500 uppercase font-semibold mb-1">Time Captured</h4>
                <p className="text-sm font-mono text-slate-300">{new Date(selectedPacket.timestamp).toLocaleString()}</p>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h4 className="text-xs text-slate-500 uppercase font-semibold mb-1">Source Host</h4>
                  <p className="text-sm font-mono font-semibold text-blue-400">{selectedPacket.src_ip || 'N/A'}</p>
                  <p className="text-xs text-slate-500 font-mono mt-0.5">Port: {selectedPacket.src_port || 'N/A'}</p>
                </div>
                <div>
                  <h4 className="text-xs text-slate-500 uppercase font-semibold mb-1">Destination Host</h4>
                  <p className="text-sm font-mono font-semibold text-emerald-400">{selectedPacket.dst_ip || 'N/A'}</p>
                  <p className="text-xs text-slate-500 font-mono mt-0.5">Port: {selectedPacket.dst_port || 'N/A'}</p>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h4 className="text-xs text-slate-500 uppercase font-semibold mb-1">L4 Protocol</h4>
                  <p className="text-sm font-mono text-slate-300 font-semibold">{selectedPacket.protocol}</p>
                </div>
                <div>
                  <h4 className="text-xs text-slate-500 uppercase font-semibold mb-1">Frame Length</h4>
                  <p className="text-sm font-mono text-slate-300">{selectedPacket.length} Bytes</p>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h4 className="text-xs text-slate-500 uppercase font-semibold mb-1">TTL Field</h4>
                  <p className="text-sm font-mono text-slate-300">{selectedPacket.ttl || 'N/A'}</p>
                </div>
                <div>
                  <h4 className="text-xs text-slate-500 uppercase font-semibold mb-1">TCP Flags</h4>
                  <p className="text-sm font-mono text-slate-300">{selectedPacket.flags || 'None'}</p>
                </div>
              </div>
            </div>

            {/* Raw Summary */}
            <div className="space-y-2">
              <h4 className="text-xs text-slate-500 uppercase font-semibold flex items-center gap-1.5">
                <FileText size={14} />
                Decoded Headers (Scapy summary)
              </h4>
              <div className="p-3 bg-slate-950 border border-slate-900 rounded-lg text-xs font-mono text-slate-400 break-words">
                {selectedPacket.raw_summary}
              </div>
            </div>

            {/* Payload Preview */}
            <div className="space-y-2">
              <h4 className="text-xs text-slate-500 uppercase font-semibold flex items-center gap-1.5">
                <ShieldAlert size={14} />
                ASCII Payload Decode
              </h4>
              <div className="p-3 bg-slate-950 border border-slate-900 rounded-lg text-xs font-mono text-slate-400 break-words whitespace-pre-wrap max-h-40 overflow-y-auto custom-scrollbar">
                {selectedPacket.payload_preview ? selectedPacket.payload_preview : '(Empty frame payload payload)'}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default PacketExplorer;
