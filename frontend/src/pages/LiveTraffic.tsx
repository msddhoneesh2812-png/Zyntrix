import { useEffect, useState } from 'react';
import { getFlows, startDemo, stopDemo, injectFlow, resetSystem } from '../services/api';
import type { FlowRecord } from '../types';
import { Play, Square, FastForward, Trash2, Bug } from 'lucide-react';

const LiveTraffic = () => {
  const [flows, setFlows] = useState<FlowRecord[]>([]);

  const fetchFlows = async () => {
    try {
      const data = await getFlows();
      setFlows(data);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchFlows();
    const interval = setInterval(fetchFlows, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleStart = async () => {
    try { await startDemo(); } catch (e) { console.error(e); }
  };

  const handleStop = async () => {
    try { await stopDemo(); } catch (e) { console.error(e); }
  };

  const handleClear = async () => {
    try { 
      await resetSystem(); 
      fetchFlows();
    } catch (e) { console.error(e); }
  };

  const handleInject = async () => {
    try {
      const suspiciousFlow = {
        id: `inj_${Date.now()}`,
        timestamp: new Date().toISOString(),
        src_ip: "192.168.1.99",
        src_port: Math.floor(Math.random() * 10000) + 10000,
        dst_ip: "185.15.2.1",
        dst_port: 4444,
        protocol: "TCP",
        packets: 5000,
        bytes: 1500000,
        duration: 10.5,
        mean_iat: 0.002,
        mean_packet_size: 300,
        status: "COMPLETED"
      };
      await injectFlow(suspiciousFlow);
      fetchFlows();
    } catch (e) {
      console.error(e);
    }
  };

  const getThreatColor = (classification?: string) => {
    switch (classification) {
      case 'MALICIOUS': return 'text-cyber-critical bg-cyber-critical/10';
      case 'OUTLIER': return 'text-cyber-warning bg-cyber-warning/10';
      case 'BENIGN': return 'text-cyber-safe bg-cyber-safe/10';
      default: return 'text-slate-600 bg-slate-100';
    }
  };

  return (
    <div className="flex flex-col gap-6 h-full">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 mb-1 flex items-center gap-3">
            Live Traffic Stream
            <span className="flex items-center gap-1.5 text-xs font-semibold bg-cyber-critical/20 text-cyber-critical px-2.5 py-1 rounded-full border border-cyber-critical/30 shadow-[0_0_10px_rgba(239,68,68,0.2)] animate-pulse">
              <span className="w-1.5 h-1.5 bg-cyber-critical rounded-full"></span> LIVE
            </span>
          </h1>
          <p className="text-slate-600">Real-time unidirectional flow inspection</p>
        </div>
        <div className="flex gap-2 bg-white p-1 rounded-lg border border-slate-200">
          <button className="p-2 text-slate-600 hover:text-slate-900 rounded hover:bg-slate-100 transition min-w-[44px] min-h-[44px] flex items-center justify-center" aria-label="Start stream" onClick={handleStart}>
            <Play size={18} />
          </button>
          <button className="p-2 text-slate-600 hover:text-slate-900 rounded hover:bg-slate-100 transition min-w-[44px] min-h-[44px] flex items-center justify-center" aria-label="Pause stream" onClick={handleStop}>
            <Square size={18} />
          </button>
          <button className="p-2 text-slate-600 hover:text-slate-900 rounded hover:bg-slate-100 transition min-w-[44px] min-h-[44px] flex items-center justify-center" aria-label="Inject suspicious test flow" onClick={handleInject}>
            <Bug size={18} />
          </button>
          <button className="p-2 text-slate-600 hover:text-slate-900 rounded hover:bg-slate-100 transition min-w-[44px] min-h-[44px] flex items-center justify-center" aria-label="Clear all flows" onClick={handleClear}>
            <Trash2 size={18} />
          </button>
        </div>
      </div>

      <div className="glass-panel flex-1 overflow-hidden flex flex-col">
        <div className="overflow-x-auto flex-1">
          <table className="w-full text-left border-collapse">
            <thead className="bg-white/80 sticky top-0 z-10 backdrop-blur-md">
              <tr className="border-b border-slate-200/50">
                <th className="py-3 px-4 text-xs font-semibold text-slate-600 uppercase tracking-wider">Timestamp</th>
                <th className="py-3 px-4 text-xs font-semibold text-slate-600 uppercase tracking-wider">Source</th>
                <th className="py-3 px-4 text-xs font-semibold text-slate-600 uppercase tracking-wider">Destination</th>
                <th className="py-3 px-4 text-xs font-semibold text-slate-600 uppercase tracking-wider">Proto</th>
                <th className="py-3 px-4 text-xs font-semibold text-slate-600 uppercase tracking-wider text-right">Packets / Bytes</th>
                <th className="py-3 px-4 text-xs font-semibold text-slate-600 uppercase tracking-wider">Class</th>
                <th className="py-3 px-4 text-xs font-semibold text-slate-600 uppercase tracking-wider">Score</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 font-mono text-sm">
              {[...flows].reverse().map((flow) => (
                <tr key={flow.id} className="hover:bg-slate-100/80 transition-all duration-300 hover:shadow-[inset_0_0_15px_rgba(59,130,246,0.15)] group relative">
                  <td className="py-3 px-4 text-slate-700">{new Date(flow.timestamp).toLocaleTimeString()}</td>
                  <td className="py-3 px-4 text-slate-700">{flow.src_ip}:{flow.src_port}</td>
                  <td className="py-3 px-4 text-slate-700">{flow.dst_ip}:{flow.dst_port}</td>
                  <td className="py-3 px-4 text-slate-600">{flow.protocol}</td>
                  <td className="py-3 px-4 text-right text-slate-600">
                    <span className="text-slate-700">{flow.packets}</span> / {flow.bytes}
                  </td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-1 rounded text-xs font-semibold font-sans ${getThreatColor(flow.threat_class)}`}>
                      {flow.threat_class || 'PENDING'}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-slate-700">
                    {flow.detection_score ? (flow.detection_score * 100).toFixed(1) + '%' : '-'}
                  </td>
                </tr>
              ))}
              {flows.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500 font-sans">
                    No traffic loaded. Start the live demo.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default LiveTraffic;
