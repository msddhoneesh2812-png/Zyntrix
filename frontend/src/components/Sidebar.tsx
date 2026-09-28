import { NavLink } from 'react-router-dom';
import { LayoutDashboard, Activity, AlertTriangle, Network, Search, Cpu, FileCheck, Settings, X } from 'lucide-react';

interface SidebarProps {
  isOpen: boolean;
  onClose: () => void;
}

const Sidebar = ({ isOpen, onClose }: SidebarProps) => {
  const navItems = [
    { to: "/dashboard", icon: <LayoutDashboard size={20} />, label: "Dashboard" },
    { to: "/traffic", icon: <Activity size={20} />, label: "Live Traffic" },
    { to: "/alerts", icon: <AlertTriangle size={20} />, label: "Threat Alerts" },
    { to: "/analyzer", icon: <Search size={20} />, label: "Flow Analyzer" },
    { to: "/graph", icon: <Network size={20} />, label: "Network Graph" },
    { to: "/evidence", icon: <FileCheck size={20} />, label: "Evidence Ledger" },
    { to: "/settings", icon: <Settings size={20} />, label: "Settings" },
  ];

  return (
    <nav
      className={`
        fixed lg:static inset-y-0 left-0 z-40
        w-64 bg-white border-r border-slate-200/50 flex flex-col
        transform transition-transform duration-300 ease-in-out
        ${isOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
      `}
      aria-label="Main navigation"
    >
      <div className="h-16 flex items-center justify-between px-6 border-b border-slate-200/50">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 bg-cyber-info rounded flex items-center justify-center">
            <Network size={20} className="text-slate-900" />
          </div>
          <span className="font-bold text-lg text-slate-900 tracking-wider">ZYNTRIX</span>
        </div>
        {/* Close button — mobile only */}
        <button
          className="lg:hidden p-1 text-slate-600 hover:text-slate-900 transition-colors rounded-md hover:bg-slate-100"
          onClick={onClose}
          aria-label="Close navigation menu"
        >
          <X size={20} />
        </button>
      </div>
      
      <div className="flex-1 py-6 flex flex-col gap-2 px-4 overflow-y-auto">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            onClick={onClose}
            className={({ isActive }) =>
              `relative flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-300 hover:translate-x-1 min-h-[44px] ${
                isActive 
                  ? 'bg-cyber-info/10 text-cyber-info shadow-[inset_3px_0_0_0_#3b82f6,0_0_10px_rgba(59,130,246,0.2)]' 
                  : 'text-slate-600 hover:text-slate-200 hover:bg-slate-100'
              }`
            }
          >
            {item.icon}
            <span className="font-medium">{item.label}</span>
          </NavLink>
        ))}
      </div>
      
      <div className="p-4 border-t border-slate-200/50">
        <div className="text-xs text-slate-500 text-center">
          SIH 2026 Prototype<br/>Team ID: 119392
        </div>
      </div>
    </nav>
  );
};

export default Sidebar;
