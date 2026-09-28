import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { getAlert, verifyEvidence } from '../services/api';
import type { Alert } from '../types';
import { ArrowLeft, ShieldAlert, CheckCircle, Database, FileCheck, Brain, Lock, Network } from 'lucide-react';

const AlertDetailSkeleton = () => (
  <div className="flex flex-col gap-6 max-w-5xl mx-auto" aria-busy="true" aria-label="Loading alert details">
    <div className="flex items-center gap-4">
      <div className="skeleton w-10 h-10 rounded-lg" />
      <div>
        <div className="skeleton h-7 w-56 mb-2" />
        <div className="skeleton h-4 w-72" />
      </div>
    </div>
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <div className="lg:col-span-2 flex flex-col gap-6">
        <div className="glass-panel p-6">
          <div className="skeleton h-5 w-64 mb-4" />
          <div className="skeleton h-32 w-full rounded" />
        </div>
        <div className="glass-panel p-6">
          <div className="skeleton h-5 w-56 mb-4" />
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
            {[1, 2, 3, 4].map(i => <div key={i} className="skeleton h-16 rounded" />)}
          </div>
        </div>
      </div>
      <div className="flex flex-col gap-6">
        <div className="glass-panel p-6"><div className="skeleton h-40 w-full rounded" /></div>
        <div className="glass-panel p-6"><div className="skeleton h-24 w-full rounded" /></div>
      </div>
    </div>
  </div>
);

const AlertDetail = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [alert, setAlert] = useState<Alert | null>(null);
  const [loading, setLoading] = useState(true);
  const [verification, setVerification] = useState<{ verified: boolean; hash: string } | null>(null);

  useEffect(() => {
    const fetchAlert = async () => {
      if (id) {
        try {
          const data = await getAlert(id);
          setAlert(data);
        } catch {
          // error handled by interceptor
        } finally {
          setLoading(false);
        }
      }
    };
    fetchAlert();
  }, [id]);

  const handleVerify = async () => {
    if (id) {
      try {
        const result = await verifyEvidence(id);
        setVerification(result);
      } catch {
        // error handled by interceptor
      }
    }
  };

  if (loading || !alert) {
    return <AlertDetailSkeleton />;
  }

  return (
    <div className="flex flex-col gap-6 max-w-5xl mx-auto">
      <div className="flex items-center gap-4">
        <button
          onClick={() => navigate(-1)}
          className="p-2 bg-white hover:bg-slate-100 rounded-lg text-slate-600 transition-colors min-w-[44px] min-h-[44px] flex items-center justify-center"
          aria-label="Go back to previous page"
        >
          <ArrowLeft size={20} />
        </button>
        <div>
          <div className="flex items-center gap-3 mb-1">
            <h1 className="text-2xl font-bold text-slate-900">Threat Investigation</h1>
            <span className={`px-2 py-1 text-xs font-bold rounded ${
              alert.severity === 'CRITICAL' ? 'bg-cyber-critical text-slate-900' : 'bg-red-500 text-slate-900'
            }`}>
              {alert.severity}
            </span>
          </div>
          <p className="text-slate-600 font-mono text-sm">{alert.id} | {new Date(alert.timestamp).toLocaleString()}</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 flex flex-col gap-6">
          <div className="glass-panel p-6 border-l-4 border-l-cyber-critical">
            <h2 className="text-lg font-semibold text-slate-900 mb-4 flex items-center gap-2">
              <Brain size={20} className="text-cyber-info" />
              Ensemble Decision: Why was this flagged?
            </h2>
            <div className="bg-slate-50 rounded p-4 border border-slate-200 font-mono text-sm text-slate-700">
              <p className="text-cyber-info mb-2 font-sans font-medium">Detection Score: {(alert.detection_score * 100).toFixed(1)}%</p>
              <ul className="list-disc pl-5 space-y-2">
                {alert.reasons.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            </div>
          </div>

          <div className="glass-panel p-6">
            <h2 className="text-lg font-semibold text-slate-900 mb-4 flex items-center gap-2">
              <Database size={20} className="text-cyber-info" />
              Observed Directional Features
            </h2>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
              <div className="bg-slate-50 p-3 rounded border border-slate-200">
                <div className="text-xs text-slate-500 mb-1">Source IP</div>
                <div className="font-mono text-sm text-slate-700">{alert.src_ip}</div>
              </div>
              <div className="bg-slate-50 p-3 rounded border border-slate-200">
                <div className="text-xs text-slate-500 mb-1">Destination IP</div>
                <div className="font-mono text-sm text-slate-700">{alert.dst_ip}</div>
              </div>
              <div className="bg-slate-50 p-3 rounded border border-slate-200">
                <div className="text-xs text-slate-500 mb-1">Protocol</div>
                <div className="font-mono text-sm text-slate-700">{alert.protocol}</div>
              </div>
              <div className="bg-slate-50 p-3 rounded border border-slate-200">
                <div className="text-xs text-slate-500 mb-1">Flow ID</div>
                <div className="font-mono text-xs text-slate-700 truncate">{alert.flow_id}</div>
              </div>
            </div>
          </div>
        </div>

        <div className="flex flex-col gap-6">
          <div className="glass-panel p-6 bg-slate-100/50">
            <h2 className="text-lg font-semibold text-slate-900 mb-4 flex items-center gap-2">
              <FileCheck size={20} className="text-cyber-safe" />
              Tamper-Evident Ledger
            </h2>
            <p className="text-sm text-slate-600 mb-4">
              This alert has been cryptographically hashed and linked to the evidence chain to ensure immutability.
            </p>
            <div className="bg-slate-50 p-3 rounded border border-slate-200 break-all mb-4">
              <div className="text-xs text-slate-500 mb-1">SHA-256 Record Hash</div>
              <div className="font-mono text-xs text-slate-700">{alert.evidence_hash}</div>
            </div>
            
            {!verification ? (
              <button onClick={handleVerify} className="w-full btn-outline flex items-center justify-center gap-2">
                <Lock size={16} /> VERIFY EVIDENCE
              </button>
            ) : (
              <div className={`p-3 rounded flex items-center gap-2 ${verification.verified ? 'bg-cyber-safe/20 text-cyber-safe border border-cyber-safe/30' : 'bg-cyber-critical/20 text-cyber-critical border border-cyber-critical/30'}`}>
                {verification.verified ? <CheckCircle size={20} /> : <ShieldAlert size={20} />}
                <span className="font-medium text-sm">
                  {verification.verified ? 'Hash Verified against Ledger' : 'Verification Failed'}
                </span>
              </div>
            )}
          </div>
          
          <div className="glass-panel p-6">
             <h2 className="text-lg font-semibold text-slate-900 mb-4 flex items-center gap-2">
              <Network size={20} className="text-slate-600" />
              Recommended Action
            </h2>
            <p className="text-sm text-slate-600">
              Isolate source endpoint <span className="font-mono text-slate-900 bg-slate-50 px-1 rounded">{alert.src_ip}</span> and investigate processes communicating on {alert.protocol}.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AlertDetail;
