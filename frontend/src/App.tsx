import { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import ErrorBoundary from './components/ErrorBoundary';
import Sidebar from './components/Sidebar';
import TopNav from './components/TopNav';
import Dashboard from './pages/Dashboard';
import LiveTraffic from './pages/LiveTraffic';
import ThreatAlerts from './pages/ThreatAlerts';
import AlertDetail from './pages/AlertDetail';
import FlowAnalyzer from './pages/FlowAnalyzer';
import NetworkGraph from './pages/NetworkGraph';
import Evidence from './pages/Evidence';
import Settings from './pages/Settings';

function App() {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <Router>
      <div className="flex h-screen bg-slate-50 overflow-hidden">
        {/* Mobile overlay backdrop */}
        {sidebarOpen && (
          <div
            className="fixed inset-0 bg-black/50 backdrop-blur-sm z-30 lg:hidden"
            onClick={() => setSidebarOpen(false)}
            aria-hidden="true"
          />
        )}

        <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />

        <div className="flex-1 flex flex-col h-screen overflow-hidden">
          <TopNav onMenuToggle={() => setSidebarOpen(!sidebarOpen)} />
          <main className="flex-1 overflow-x-hidden overflow-y-auto bg-slate-50 p-4 md:p-6">
            <ErrorBoundary>
              <Routes>
                <Route path="/" element={<Navigate to="/dashboard" replace />} />
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/traffic" element={<LiveTraffic />} />
                <Route path="/alerts" element={<ThreatAlerts />} />
                <Route path="/alerts/:id" element={<AlertDetail />} />
                <Route path="/analyzer" element={<FlowAnalyzer />} />
                <Route path="/graph" element={<NetworkGraph />} />
                <Route path="/evidence" element={<Evidence />} />
                <Route path="/settings" element={<Settings />} />
              </Routes>
            </ErrorBoundary>
          </main>
        </div>
      </div>
    </Router>
  );
}

export default App;
