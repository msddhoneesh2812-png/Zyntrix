import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { getAlerts } from '../services/api';
import type { Alert } from '../types';
import { ShieldAlert, ArrowRight, Activity } from 'lucide-react';

const ThreatAlerts = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const navigate = useNavigate();

  const fetchAlerts = async () => {
    try {
      const data = await getAlerts();
      setAlerts(data);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 2000);
    return () => clearInterval(interval);
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'bg-cyber-critical text-slate-900';
      case 'HIGH': return 'bg-red-500 text-slate-900';
      case 'MEDIUM': return 'bg-cyber-warning text-navy-900';
      case 'LOW': return 'bg-cyber-info text-slate-900';
      default: return 'bg-slate-700 text-slate-900';
    }
  };

  return (
    <div className="flex flex-col gap-6 h-full">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 mb-1">Threat Alerts</h1>
          <p className="text-slate-600">Actionable detections from the AI Ensemble</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
        {[...alerts].reverse().map((alert) => (
          <div key={alert.id} className="glass-panel p-0 overflow-hidden flex flex-col group cursor-pointer hover:border-slate-500 transition-colors" onClick={() => navigate(`/alerts/${alert.id}`)}>
            <div className={`px-4 py-2 flex justify-between items-center ${getSeverityColor(alert.severity)}`}>
              <span className="font-bold text-sm tracking-wider uppercase">{alert.severity} SEVERITY</span>
              <ShieldAlert size={16} />
            </div>
            <div className="p-5 flex-1 flex flex-col">
              <div className="flex justify-between items-start mb-4">
                <h3 className="font-semibold text-lg text-slate-900 truncate pr-2" title={alert.threat_type || alert.classification}>
                  {alert.threat_type || alert.classification}
                </h3>
                <div className="text-xs font-mono bg-slate-50 text-slate-700 px-2 py-1 rounded border border-slate-200">
                  {alert.id}
                </div>
              </div>
              
              <div className="space-y-3 mb-6 flex-1">
                <div className="flex justify-between text-sm">
                  <span className="text-slate-500">Target</span>
                  <span className="text-slate-700 font-mono">{alert.dst_ip}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-slate-500">Source</span>
                  <span className="text-slate-700 font-mono">{alert.src_ip}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-slate-500">Detection Score</span>
                  <span className="text-cyber-info font-mono">{(alert.detection_score * 100).toFixed(1)}%</span>
                </div>
              </div>

              <div className="flex items-center text-cyber-info text-sm font-medium group-hover:text-blue-400 transition-colors mt-auto pt-4 border-t border-slate-200/50">
                Investigate Alert <ArrowRight size={16} className="ml-2 group-hover:translate-x-1 transition-transform" />
              </div>
            </div>
          </div>
        ))}

        {alerts.length === 0 && (
          <div className="col-span-full glass-panel py-16 flex flex-col items-center justify-center text-slate-500">
            <ShieldAlert size={48} className="mb-4 text-slate-600" />
            <h3 className="text-xl font-medium text-slate-600 mb-2">No Active Threats</h3>
            <p>The system is monitoring for anomalous activity.</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default ThreatAlerts;
