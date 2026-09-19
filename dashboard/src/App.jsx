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
          <header className="mx-6 mt-5 h-14 px-5 flex justify-between items-center shrink-0 select-none dg-pill !rounded-[22px]">
            <div className="flex items-center gap-2.5">
              <span className="text-sm text-slate-300">{project ? project.name : 'phishguard'}</span>
              <span className="text-sm text-slate-500">/</span>
              <span className="text-sm text-white font-semibold">{VIEW_LABELS[activeView] || activeView}</span>
            </div>

            <div className="flex items-center gap-5">
              <button
                onClick={runScan}
                disabled={scanning}
                className="dg-pearl flex items-center gap-2 text-[13px] font-semibold px-4 py-2 rounded-full hover:brightness-105 disabled:opacity-60 transition-all"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${scanning ? 'animate-spin' : ''}`} />
                {scanning ? (scanProgress ? `${scanProgress.phase}…` : 'Scanning…') : 'Scan again'}
              </button>

              <div className="flex items-center gap-2 text-[13px]">
                <span className="relative flex h-2 w-2">
                  {isConnected ? (
                    <>
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyber-success opacity-75" />
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-cyber-success" />
                    </>
                  ) : (
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-cyber-danger" />
                  )}
                </span>
                <span className="text-slate-200 font-medium">{isConnected ? 'Agent listening' : 'Offline'}</span>
              </div>
            </div>
          </header>

          <div className="flex-1 px-6 pt-6 pb-6 overflow-hidden relative z-10">
            {renderActiveView()}
          </div>
        </main>
      </div>
    </PhishGuardContext.Provider>
  );
}
