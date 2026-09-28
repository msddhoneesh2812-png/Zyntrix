import { useCallback, useEffect, useRef, useState } from 'react';
import { format } from 'date-fns';
import { getSystemStatus, getStats } from '../services/api';
import { ShieldAlert, Menu } from 'lucide-react';

interface TopNavProps {
  onMenuToggle: () => void;
}

const TopNav = ({ onMenuToggle }: TopNavProps) => {
  const [time, setTime] = useState(new Date());
  const [status, setStatus] = useState<string>("IDLE");
  const [activeAlerts, setActiveAlerts] = useState<number>(0);
  const [showNotifications, setShowNotifications] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  
  // Clock
  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  // System status polling
  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const sysStatus = await getSystemStatus();
        setStatus(sysStatus.mode);
        const stats = await getStats();
        setActiveAlerts(stats.active_alerts);
      } catch {
        setStatus("ERROR");
      }
    };
    fetchStatus();
    const statusTimer = setInterval(fetchStatus, 2000);
    return () => clearInterval(statusTimer);
  }, []);

  // Click-outside handler for notification dropdown
  const handleClickOutside = useCallback((event: MouseEvent) => {
    if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
      setShowNotifications(false);
    }
  }, []);

  useEffect(() => {
    if (showNotifications) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [showNotifications, handleClickOutside]);

  // Close on Escape key
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setShowNotifications(false);
    };
    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, []);

  return (
    <div className="h-16 bg-white border-b border-slate-200/50 flex items-center justify-between px-4 md:px-6 z-10">
      <div className="flex items-center gap-4 md:gap-6">
        {/* Hamburger menu — mobile only */}
        <button
          className="lg:hidden p-2 text-slate-600 hover:text-slate-900 transition-colors rounded-md hover:bg-slate-100 min-w-[44px] min-h-[44px] flex items-center justify-center"
          onClick={onMenuToggle}
          aria-label="Toggle navigation menu"
        >
          <Menu size={22} />
        </button>

        <div className="flex items-center gap-2">
          <div
            className={`w-2 h-2 rounded-full ${
              status === 'ERROR'
                ? 'bg-cyber-critical shadow-[0_0_8px_#ef4444]'
                : status === 'DEMO MODE'
                  ? 'bg-cyber-warning animate-pulse shadow-[0_0_8px_#f59e0b]'
                  : 'bg-cyber-safe shadow-[0_0_8px_#10b981]'
            }`}
            aria-hidden="true"
          />
          <span className="text-sm font-medium text-slate-700">
            {status === 'ERROR' ? 'Backend Unavailable' : `Mode: ${status}`}
          </span>
        </div>
      </div>
      
      <div className="flex items-center gap-4 md:gap-6">
        <div className="text-sm font-mono text-slate-600 hidden sm:block">
          {format(time, 'yyyy-MM-dd HH:mm:ss')}
        </div>
        <div className="relative" ref={dropdownRef}>
          <button 
            className="relative p-2 text-slate-600 hover:text-slate-900 transition-all duration-300 rounded-full hover:bg-slate-100 hover:shadow-[0_0_15px_rgba(255,255,255,0.1)] min-w-[44px] min-h-[44px] flex items-center justify-center focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyber-info focus-visible:ring-offset-2 focus-visible:ring-offset-navy-800"
            onClick={() => setShowNotifications(!showNotifications)}
            aria-label={`Notifications${activeAlerts > 0 ? ` — ${activeAlerts} active alerts` : ''}`}
            aria-expanded={showNotifications}
            aria-haspopup="true"
          >
            <ShieldAlert size={20} />
            {activeAlerts > 0 && (
              <span
                className="absolute top-1 right-1 w-2.5 h-2.5 bg-cyber-critical rounded-full border border-navy-800 shadow-[0_0_5px_#ef4444] animate-pulse"
                aria-hidden="true"
              />
            )}
          </button>
          
          {showNotifications && (
            <div
              className="absolute right-0 mt-2 w-72 bg-white/95 backdrop-blur-md border border-slate-200 rounded-xl shadow-[0_10px_40px_-10px_rgba(0,0,0,0.5)] overflow-hidden z-50 origin-top-right animate-[fadeIn_0.15s_ease-out]"
              role="dialog"
              aria-label="Notifications panel"
            >
              <div className="p-3 bg-white border-b border-slate-200 flex justify-between items-center">
                <span className="text-sm font-medium text-slate-900">Notifications</span>
                <span className="text-xs bg-slate-700 text-slate-700 px-2 py-0.5 rounded-full">
                  {activeAlerts} new
                </span>
              </div>
              <div className="p-4 text-center text-sm text-slate-600">
                {activeAlerts > 0 
                  ? `${activeAlerts} active alerts generated by the detection ensemble. Check Evidence Ledger.` 
                  : 'No active alerts. System is secure.'}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default TopNav;
