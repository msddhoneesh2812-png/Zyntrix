import { useEffect, useState } from 'react';
import { getSystemStatus, stopDemo, resetSystem } from '../services/api';
import type { SystemStatus } from '../types';
import { Power, Settings as SettingsIcon, Database, Cpu, Search, Activity, Network, FileCheck } from 'lucide-react';

const Settings = () => {
  const [status, setStatus] = useState<SystemStatus | null>(null);

  const fetchStatus = async () => {
    try {
      const data = await getSystemStatus();
      setStatus(data);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 2000);
    return () => clearInterval(interval);
  }, []);

  const handleStopAndReset = async () => {
    await stopDemo();
    await resetSystem();
    fetchStatus();
  };

  const StatusIndicator = ({ label, state, icon }: { label: string; state?: string; icon: React.ReactNode }) => (
    <div className="flex items-center justify-between p-4 bg-slate-50 border border-slate-200 rounded-lg">
      <div className="flex items-center gap-3">
        <div className="p-2 bg-white rounded text-slate-600">
          {icon}
        </div>
        <span className="font-medium text-slate-700">{label}</span>
      </div>
      <div className={`flex items-center gap-2 text-sm font-bold ${state === 'ONLINE' ? 'text-cyber-safe' : 'text-slate-500'}`}>
        <div className={`w-2 h-2 rounded-full ${state === 'ONLINE' ? 'bg-cyber-safe' : 'bg-slate-500'}`}></div>
        {state}
      </div>
    </div>
  );

  return (
    <div className="flex flex-col gap-6 h-full max-w-4xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold text-slate-900 mb-1">System Status</h1>
        <p className="text-slate-600">Manage prototype services and demo mode</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="glass-panel p-6 flex flex-col gap-4">
           <h3 className="text-lg font-medium text-slate-900 mb-2 flex items-center gap-2">
             <SettingsIcon size={20} className="text-cyber-info" /> Engine Status
           </h3>
           <StatusIndicator label="Flow Ingestion" state={status?.flow_ingestion} icon={<Activity size={18} />} />
           <StatusIndicator label="Feature Extraction" state={status?.feature_extraction} icon={<Database size={18} />} />
           <StatusIndicator label="Detection Engine" state={status?.detection_engine} icon={<Cpu size={18} />} />
           <StatusIndicator label="Graph Engine" state={status?.graph_engine} icon={<Network size={18} />} />
           <StatusIndicator label="Alert Engine" state={status?.alert_engine} icon={<Search size={18} />} />
           <StatusIndicator label="Evidence Ledger" state={status?.evidence_ledger} icon={<FileCheck size={18} />} />
        </div>

        <div className="flex flex-col gap-6">
           <div className="glass-panel p-6">
              <h3 className="text-lg font-medium text-slate-900 mb-4">Demo Control</h3>
              <p className="text-sm text-slate-600 mb-6">Current Mode: <span className="font-bold text-cyber-info">{status?.mode || 'LOADING'}</span></p>
              
              <button 
                onClick={handleStopAndReset}
                className="w-full btn-outline border-cyber-critical text-cyber-critical hover:bg-cyber-critical hover:text-slate-900 flex items-center justify-center gap-2"
                disabled={status?.mode !== 'DEMO MODE'}
              >
                <Power size={18} /> STOP DEMO & RESET
              </button>
           </div>
           
           <div className="glass-panel p-6">
              <h3 className="text-lg font-medium text-slate-900 mb-4">Model Configuration</h3>
              <p className="text-sm text-slate-600">Prototype uses a trained RandomForestClassifier ensemble over demonstration data for live inference.</p>
           </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;
