import React, { useState, useEffect, useCallback, createContext, useContext } from 'react';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import ThreatMap from './components/ThreatMap';
import SupplyChain from './pages/SupplyChain';
import Sandbox from './pages/Sandbox';
import LogTable from './components/LogTable';
import Forensics from './pages/Forensics';
import DatabaseExplorer from './pages/DatabaseExplorer';
import GlobalIntel from './pages/GlobalIntel';
import DreamBackdrop from './components/DreamBackdrop';
import { RefreshCw } from 'lucide-react';

const VIEW_LABELS = {
  dashboard: 'Dashboard',
  supplychain: 'Supply Chain',
  threatmap: 'Threat Map',
  globalintel: 'Global Intel',
  logs: 'Telemetry',
  forensics: 'Forensics',
  dbexplorer: 'Database',
  sandbox: 'Shield Sandbox',
};

const WS_URL = import.meta.env.DEV
  ? 'ws://localhost:4173'
  : `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}`;

export const PhishGuardContext = createContext(null);
export const usePhishGuard = () => useContext(PhishGuardContext);

export default function App() {
  const [activeView, setActiveView] = useState('dashboard');
  const [logs, setLogs] = useState([]);
  const [isConnected, setIsConnected] = useState(false);
  const [scanSummary, setScanSummary] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(null);
  const [project, setProject] = useState(null);
  const [autoscan, setAutoscan] = useState(null);
  const [quarantineNonce, setQuarantineNonce] = useState(0);
  const [nonce, setNonce] = useState(0); // bump to make pages re-fetch after a scan

  useEffect(() => {
    fetch('/api/project').then(r => r.json()).then(setProject).catch(() => {});
  }, []);

  useEffect(() => {
    let ws;
    let retry;
    const connect = () => {
      ws = new WebSocket(WS_URL);
      ws.onopen = () => setIsConnected(true);
      ws.onmessage = (evt) => {
        try {
          const { type, data } = JSON.parse(evt.data);
          if (type === 'SEEDED_LOGS') setLogs(data);
          else if (type === 'NEW_LOG') setLogs(prev => [data, ...prev]);
          else if (type === 'SCAN_STARTED') { setScanning(true); setScanProgress(null); }
          else if (type === 'SCAN_PROGRESS') setScanProgress(data);
          else if (type === 'AUTOSCAN') setAutoscan(data);
          else if (type === 'QUARANTINE' || type === 'QUARANTINE_RELEASED') {
            // A remediation changes the posture everywhere, so bump the shared
            // nonce too: every panel that refreshes after a scan refreshes now.
            setQuarantineNonce(n => n + 1);
            setNonce(n => n + 1);
          }
          else if (type === 'SCAN_COMPLETE') {
            setScanning(false);
            setScanProgress(null);
            setScanSummary(data);
            setNonce(n => n + 1);
          }
        } catch { /* ignore */ }
      };
      ws.onclose = () => { setIsConnected(false); retry = setTimeout(connect, 4000); };
      ws.onerror = () => ws.close();
    };
    connect();
    return () => { if (ws) ws.close(); if (retry) clearTimeout(retry); };
  }, []);

  const runScan = useCallback(async () => {
    setScanning(true);
    try {
      const res = await fetch('/api/scan/run', { method: 'POST' });
      const report = await res.json();
      if (report && !report.error) {
        setScanSummary({
          at: report.generatedAt, score: report.score, grade: report.grade,
          status: report.status, counts: report.counts, project: report.project, lockfile: report.lockfile,
        });
        setNonce(n => n + 1);
      }
      return report;
    } finally {
      setScanning(false);
    }
  }, []);

  const ctx = { logs, isConnected, scanSummary, scanning, scanProgress, project, runScan, nonce, autoscan, quarantineNonce };

  const renderActiveView = () => {
    switch (activeView) {
      case 'dashboard': return <Dashboard />;
      case 'dbexplorer': return <DatabaseExplorer />;
      case 'threatmap': return <ThreatMap />;
      case 'supplychain': return <SupplyChain />;
      case 'sandbox': return <Sandbox />;
      case 'forensics': return <Forensics />;
      case 'globalintel': return <GlobalIntel />;
      case 'logs': return <LogTable logs={logs} />;
      default: return <Dashboard />;
    }
  };

  return (
    <PhishGuardContext.Provider value={ctx}>
      <div className="relative flex h-screen w-screen text-slate-100 overflow-hidden font-sans">
        <DreamBackdrop />

        <Sidebar activeView={activeView} setActiveView={setActiveView} isConnected={isConnected} project={project} />

        <main className="relative z-10 flex-1 flex flex-col min-w-0 h-screen">
          <header className="h-[52px] px-5 flex justify-between items-center shrink-0 select-none border-b border-white/[0.06] bg-[#1C1C1E]/90">
            <div className="flex items-baseline gap-2">
              <span className="text-[15px] font-semibold text-white">{VIEW_LABELS[activeView] || activeView}</span>
              <span className="text-[12px] text-slate-500">{project ? project.name : 'phishguard'}</span>
            </div>

            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2 text-[13px]">
                <span className={`w-2 h-2 rounded-full ${isConnected ? 'bg-cyber-success' : 'bg-cyber-danger'}`} />
                <span className="text-slate-300">{isConnected ? 'Agent listening' : 'Offline'}</span>
              </div>
              <button
                onClick={runScan}
                disabled={scanning}
                className="dg-pearl flex items-center gap-2 text-[13px] font-semibold px-3.5 py-1.5 rounded-[10px] disabled:opacity-60 transition-colors"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${scanning ? 'animate-spin' : ''}`} />
                {scanning ? (scanProgress ? `${scanProgress.phase}…` : 'Scanning…') : 'Scan'}
              </button>
            </div>
          </header>

          <div className="flex-1 px-8 pt-6 pb-6 overflow-hidden relative z-10">
            {renderActiveView()}
          </div>
        </main>
      </div>
    </PhishGuardContext.Provider>
  );
}
