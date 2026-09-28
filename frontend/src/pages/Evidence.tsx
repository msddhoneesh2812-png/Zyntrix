import { useEffect, useState } from 'react';
import { getEvidence, verifyEvidence } from '../services/api';
import type { EvidenceRecord } from '../types';
import { FileCheck, ShieldAlert, CheckCircle, XCircle } from 'lucide-react';

const Evidence = () => {
  const [evidence, setEvidence] = useState<EvidenceRecord[]>([]);
  const [verifications, setVerifications] = useState<Record<string, boolean>>({});

  const fetchEvidence = async () => {
    try {
      const data = await getEvidence();
      setEvidence(data);
    } catch (e) {
      console.error(e);
    }
  };

  const handleVerify = async (alertId: string) => {
    try {
      const res = await verifyEvidence(alertId);
      setVerifications(prev => ({ ...prev, [alertId]: res.verified }));
    } catch (e) {
      console.error(e);
      setVerifications(prev => ({ ...prev, [alertId]: false }));
    }
  };

  const handleVerifyAll = async () => {
    const results = await Promise.allSettled(
      evidence.map((record) => handleVerify(record.alert_id))
    );
    // errors already handled inside handleVerify
  };

  useEffect(() => {
    fetchEvidence();
    const interval = setInterval(fetchEvidence, 3000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="flex flex-col gap-6 h-full">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 mb-1">Evidence Ledger</h1>
          <p className="text-slate-600">Tamper-Evident Prototype Ledger based on Proof by Design</p>
        </div>
        <button className="btn-outline flex items-center gap-2" onClick={handleVerifyAll}>
          <FileCheck size={18} /> VERIFY ALL
        </button>
      </div>

      <div className="glass-panel flex-1 overflow-hidden flex flex-col">
        <div className="overflow-x-auto flex-1 p-6">
          <div className="space-y-6">
            {[...evidence].reverse().map((record, index) => (
              <div key={record.id} className="relative pl-8">
                {/* Timeline line */}
                {index !== evidence.length - 1 && (
                  <div className="absolute left-3 top-8 bottom-[-24px] w-0.5 bg-slate-700"></div>
                )}
                {/* Timeline dot */}
                <div className="absolute left-[9px] top-1.5 w-3 h-3 rounded-full bg-cyber-safe border-2 border-navy-900 z-10"></div>
                
                <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
                   <div className="flex justify-between mb-2">
                     <span className="font-mono text-sm text-cyber-info">{record.id}</span>
                     <span className="text-sm text-slate-500">{new Date(record.timestamp).toLocaleString()}</span>
                   </div>
                   
                   <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm font-mono break-all">
                      <div>
                        <div className="text-xs font-sans text-slate-500 mb-1">Previous Hash</div>
                        <div className="text-slate-600">{record.previous_hash}</div>
                      </div>
                      <div>
                        <div className="text-xs font-sans text-slate-500 mb-1">Current Hash</div>
                        <div className="text-cyber-safe">{record.current_hash}</div>
                      </div>
                   </div>
                   
                   <div className="mt-4 pt-4 border-t border-slate-800 flex justify-between items-center text-sm font-sans">
                      <span className="text-slate-600">Linked to Alert: <span className="text-slate-900">{record.alert_id}</span></span>
                      
                      <div className="flex items-center gap-4">
                        {verifications[record.alert_id] !== undefined && (
                          <span className={`flex items-center gap-1 ${verifications[record.alert_id] ? 'text-cyber-safe' : 'text-cyber-critical'}`}>
                            {verifications[record.alert_id] ? <CheckCircle size={16} /> : <XCircle size={16} />}
                            {verifications[record.alert_id] ? 'VERIFIED' : 'TAMPERED'}
                          </span>
                        )}
                        <button 
                          className="btn-outline text-xs px-2 py-1"
                          onClick={() => handleVerify(record.alert_id)}
                        >
                          VERIFY
                        </button>
                        <span className={`px-2 py-1 rounded text-xs font-bold ${
                          record.alert_classification === 'CRITICAL' ? 'bg-cyber-critical text-slate-900' : 'bg-cyber-warning text-navy-900'
                        }`}>
                          {record.alert_classification}
                        </span>
                      </div>
                   </div>
                </div>
              </div>
            ))}
            
            {evidence.length === 0 && (
              <div className="py-12 flex flex-col items-center justify-center text-slate-500">
                <FileCheck size={48} className="mb-4 text-slate-600" />
                <h3 className="text-xl font-medium text-slate-600 mb-2">No Evidence Records</h3>
                <p>Alert hashes will appear here once threats are detected.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Evidence;
