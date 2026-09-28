import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { getStats, startDemo } from '../services/api';
import type { Stats } from '../types';
import { Activity, AlertTriangle, ShieldAlert, ShieldCheck, Play, Upload, Search } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

// ---------------------------------------------------------------------------
// MetricCard — typed props (replaces `any`)
// ---------------------------------------------------------------------------
interface MetricCardProps {
  title: string;
  value: number | string;
  icon: React.ReactNode;
  colorClass: string;
  subtitle?: string;
}

const MetricCard = ({ title, value, icon, colorClass, subtitle }: MetricCardProps) => (
  <div className="glass-panel p-6 flex flex-col justify-between transition-all duration-300 hover:-translate-y-1 hover:shadow-[0_10px_30px_-10px_rgba(255,255,255,0.1)] cursor-default">
    <div className="flex justify-between items-start">
      <div>
        <h3 className="text-slate-600 font-medium mb-1">{title}</h3>
        <div className={`text-3xl font-bold ${colorClass}`}>{value}</div>
      </div>
      <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
        {icon}
      </div>
    </div>
    {subtitle && <div className="text-sm text-slate-500 mt-4">{subtitle}</div>}
  </div>
);

// ---------------------------------------------------------------------------
// Loading skeleton for the dashboard
// ---------------------------------------------------------------------------
const DashboardSkeleton = () => (
  <div className="flex flex-col gap-6" aria-busy="true" aria-label="Loading dashboard">
    <div className="flex justify-between items-center">
      <div>
        <div className="skeleton h-7 w-48 mb-2" />
        <div className="skeleton h-4 w-72" />
      </div>
      <div className="flex gap-4">
        <div className="skeleton h-10 w-44 rounded" />
        <div className="skeleton h-10 w-44 rounded" />
      </div>
    </div>
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      {[1, 2, 3, 4].map((i) => (
        <div key={i} className="glass-panel p-6">
          <div className="skeleton h-4 w-32 mb-3" />
          <div className="skeleton h-8 w-20 mb-4" />
          <div className="skeleton h-3 w-40" />
        </div>
      ))}
    </div>
    <div className="glass-panel p-6 h-[400px]">
      <div className="skeleton h-5 w-64 mb-6" />
      <div className="skeleton h-full w-full rounded-lg" />
    </div>
  </div>
);

// ---------------------------------------------------------------------------
// Default empty chart data (no more stale hardcoded numbers)
// ---------------------------------------------------------------------------
const EMPTY_HISTORY = [{ time: "—", benign: 0, suspicious: 0, malicious: 0 }];

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------
const Dashboard = () => {
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  const fetchStats = async () => {
    try {
      const data = await getStats();
      setStats(data);
    } catch {
      // keep previous stats on transient failure
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 2000);
    return () => clearInterval(interval);
  }, []);

  const handleStartDemo = async () => {
    try {
      await startDemo();
    } catch {
      // error handled by interceptor
    }
  };

  if (loading && !stats) {
    return <DashboardSkeleton />;
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 mb-1">SOC Overview</h1>
          <p className="text-slate-600">Monitoring Unidirectional Flow Analytics</p>
        </div>
        <div className="flex gap-4 flex-wrap">
          <button 
            className="btn-outline flex items-center gap-2"
            onClick={() => navigate('/analyzer')}
          >
            <Upload size={18} />
            UPLOAD FLOW DATA
          </button>
          <button 
            className="btn-primary flex items-center gap-2 bg-cyber-warning hover:bg-amber-600 text-navy-900"
            onClick={handleStartDemo}
            disabled={stats?.is_running}
          >
            <Play size={18} />
            {stats?.is_running ? 'DEMO RUNNING' : 'START LIVE DEMO'}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <MetricCard 
          title="Flows Processed" 
          value={stats?.flows_processed ?? 0} 
          icon={<Activity size={24} className="text-cyber-info" />}
          colorClass="text-slate-900"
          subtitle="Total unidirectional flows"
        />
        <MetricCard 
          title="Suspicious / Outliers" 
          value={stats?.suspicious_flows ?? 0} 
          icon={<Search size={24} className="text-cyber-warning" />}
          colorClass="text-cyber-warning"
          subtitle="Requires investigation"
        />
        <MetricCard 
          title="Malicious Flows" 
          value={stats?.malicious_flows ?? 0} 
          icon={<ShieldAlert size={24} className="text-cyber-critical" />}
          colorClass="text-cyber-critical"
          subtitle="High Detection Score threats"
        />
        <MetricCard 
          title="Active Alerts" 
          value={stats?.active_alerts ?? 0} 
          icon={<AlertTriangle size={24} className="text-cyber-critical" />}
          colorClass="text-cyber-critical"
          subtitle="Generated from ML ensemble"
        />
      </div>

      <div className="glass-panel p-6 h-[400px]">
        <h3 className="text-lg font-medium text-slate-900 mb-6 flex items-center gap-2">
          <Activity size={20} className="text-cyber-info" />
          Traffic Volume & Threat Distribution {stats?.is_running ? '(LIVE)' : ''}
        </h3>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={stats?.history || EMPTY_HISTORY} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="colorBenign" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#10b981" stopOpacity={0.6}/>
                <stop offset="95%" stopColor="#10b981" stopOpacity={0}/>
              </linearGradient>
              <linearGradient id="colorMalicious" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ef4444" stopOpacity={0.6}/>
                <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
            <XAxis dataKey="time" stroke="#94a3b8" />
            <YAxis stroke="#94a3b8" />
            <Tooltip 
              contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
              itemStyle={{ color: '#e2e8f0' }}
            />
            <Area type="monotone" dataKey="benign" stroke="#10b981" fillOpacity={1} fill="url(#colorBenign)" />
            <Area type="monotone" dataKey="malicious" stroke="#ef4444" fillOpacity={1} fill="url(#colorMalicious)" />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

export default Dashboard;
