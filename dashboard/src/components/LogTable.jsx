import React, { useState } from 'react';
import { 
  Search, 
  Terminal, 
  ShieldAlert, 
  ShieldCheck, 
  FileText, 
  AlertTriangle, 
  Info,
  ChevronRight,
  FilterX,
  Play,
  Cpu,
  Sparkles
} from 'lucide-react';
import ReplayPlayer from './ReplayPlayer';

export default function LogTable({ logs }) {
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [selectedLog, setSelectedLog] = useState(null);
  const [replayLog, setReplayLog] = useState(null);
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  // Filter logs based on search string and status selection
  const filteredLogs = logs.filter(log => {
    const matchesSearch = 
      log.sourcePackage.toLowerCase().includes(search.toLowerCase()) ||
      log.action.toLowerCase().includes(search.toLowerCase()) ||
      log.details.toLowerCase().includes(search.toLowerCase());
      
    const matchesStatus = 
      statusFilter === 'ALL' || 
      log.status === statusFilter ||
      (statusFilter === 'WARNINGS' && log.severity === 'warning') ||
      (statusFilter === 'CRITICAL' && log.severity === 'critical');

    return matchesSearch && matchesStatus;
  });

  const getSeverityColor = (sev) => {
    switch (sev) {
      case 'critical': return 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/30';
      case 'warning': return 'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/30';
      case 'info':
      default: return 'text-cyber-primary bg-cyber-primary/10 border-cyber-primary/30';
    }
  };

  const getStatusColor = (status) => {
    return status === 'BLOCKED' 
      ? 'text-cyber-danger border-cyber-danger/35 bg-cyber-danger/10 glow-text-danger' 
      : 'text-cyber-success border-cyber-success/35 bg-cyber-success/10 glow-text-success';
  };

  return (
    <div className="flex gap-6 h-full items-stretch">
      {/* Main Table Segment */}
      <div className="flex-1 glass-panel rounded-xl border border-cyber-border/40 p-5 flex flex-col min-w-0">
        
        {/* Search & Actions Bar */}
        <div className="flex flex-col md:flex-row gap-4 justify-between items-center mb-5 shrink-0 select-none">
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-cyber-primary/10 rounded-lg text-cyber-primary">
              <Terminal className="w-4.5 h-4.5" />
            </div>
            <div>
              <h2 className="font-sans font-bold text-base text-slate-100">
                Telemetry Log Stream
              </h2>
              <p className="text-[11px] text-slate-400">
                Real-time interceptor logs capturing browser-scope network and storage actions
              </p>
            </div>
          </div>

          <div className="flex gap-3 w-full md:w-auto">
            {/* Search Input */}
            <div className="relative flex-1 md:w-64">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <input
                type="text"
                placeholder="Search packages or actions..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full pl-9 pr-4 py-1.5 text-sm font-sans bg-cyber-bg/80 border border-cyber-border/50 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyber-primary transition-colors"
              />
            </div>

            {/* Filter buttons */}
            <div className="flex border border-cyber-border/45 rounded-lg p-0.5 bg-cyber-bg/50">
              {['ALL', 'BLOCKED', 'WARNINGS'].map(filter => (
                <button
                  key={filter}
                  onClick={() => setStatusFilter(filter)}
                  className={`px-3 py-1 rounded-md text-[10px] font-mono font-bold tracking-wider uppercase transition-all ${
                    statusFilter === filter
                      ? 'bg-slate-800 text-slate-100 border border-slate-700 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {filter}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Dynamic Event Table container */}
        <div className="flex-1 overflow-y-auto rounded-lg border border-cyber-border/30 bg-cyber-bg/30">
          {filteredLogs.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-64 text-cyber-muted p-6">
              <FilterX className="w-12 h-12 text-cyber-muted/40 mb-3 animate-pulse" />
              <span className="font-mono text-sm uppercase font-semibold">No telemetries logged matching filters</span>
              <span className="text-[10px] font-mono text-cyber-muted/70 mt-1">Interceptors are awaiting client actions</span>
            </div>
          ) : (
            <table className="w-full border-collapse text-left">
              <thead>
                <tr className="border-b border-cyber-border/40 bg-cyber-panel/60 sticky top-0 z-10">
                  <th className="p-4 text-[10px] font-mono font-bold text-cyber-muted tracking-wider uppercase">Timestamp</th>
                  <th className="p-4 text-[10px] font-mono font-bold text-cyber-muted tracking-wider uppercase">Caller Context</th>
                  <th className="p-4 text-[10px] font-mono font-bold text-cyber-muted tracking-wider uppercase">Action / Event</th>
                  <th className="p-4 text-[10px] font-mono font-bold text-cyber-muted tracking-wider uppercase">Telemetry Severity</th>
                  <th className="p-4 text-[10px] font-mono font-bold text-cyber-muted tracking-wider uppercase">Status</th>
                  <th className="p-4 text-[10px] font-mono font-bold text-cyber-muted tracking-wider uppercase"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border/20 font-mono text-xs">
                {filteredLogs.map((log) => (
                  <tr 
                    key={log.id} 
                    onClick={() => {
                      setSelectedLog(log);
                      setAiAnalysis(null);
                      setIsAnalyzing(false);
                    }}
                    className={`hover:bg-cyber-panel/30 cursor-pointer transition-colors ${
                      log.status === 'BLOCKED' ? 'bg-cyber-danger/[0.02]' : ''
                    } ${selectedLog?.id === log.id ? 'bg-cyber-primary/[0.04] border-l-2 border-l-cyber-primary' : ''}`}
                  >
                    <td className="p-4 text-cyber-muted select-none">
                      {new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </td>
                    <td className="p-4 font-semibold text-slate-200">
                      <span className="px-2 py-1 rounded bg-cyber-panel border border-cyber-border/30 max-w-[150px] inline-block truncate" title={log.sourcePackage}>
                        {log.sourcePackage}
                      </span>
                    </td>
                    <td className="p-4">
                      <div className="font-semibold text-slate-300">{log.action}</div>
                      <div className="text-[10px] text-cyber-muted/80 truncate max-w-[280px]" title={log.details}>
                        {log.details}
                      </div>
                    </td>
                    <td className="p-4">
                      <span className={`px-2 py-0.5 rounded-full border text-[9px] font-bold tracking-widest uppercase inline-flex items-center gap-1 ${getSeverityColor(log.severity)}`}>
                        {log.severity === 'critical' ? (
                          <ShieldAlert className="w-3 h-3" />
                        ) : log.severity === 'warning' ? (
                          <AlertTriangle className="w-3 h-3" />
                        ) : (
                          <Info className="w-3 h-3" />
                        )}
                        {log.severity}
                      </span>
                    </td>
                    <td className="p-4">
                      <span className={`px-2 py-0.5 rounded border text-[9px] font-bold tracking-widest uppercase inline-flex items-center gap-1 ${getStatusColor(log.status)}`}>
                        {log.status === 'BLOCKED' ? (
                          <>
                            <span className="w-1.5 h-1.5 rounded-full bg-cyber-danger animate-pulse"></span>
                            BLOCKED
                          </>
                        ) : (
                          <>
                            <span className="w-1.5 h-1.5 rounded-full bg-cyber-success"></span>
                            PASSED
                          </>
                        )}
                      </span>
                    </td>
                    <td className="p-4 text-right">
                      <ChevronRight className="w-4 h-4 text-cyber-muted/50 inline-block" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Side Stack-Trace Inspector Panel */}
      {selectedLog && (
        <div className="w-96 glass-panel rounded-xl border border-cyber-border/40 p-5 flex flex-col shrink-0 animate-fadeIn">
          <div className="flex justify-between items-start mb-4 border-b border-cyber-border/30 pb-3">
            <div>
              <div className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-cyber-primary" />
                <h3 className="font-display font-bold text-sm tracking-wider text-slate-100 uppercase">
                  Event Analysis
                </h3>
              </div>
              <span className="text-[9px] font-mono text-cyber-muted uppercase block mt-0.5">
                ID: {selectedLog.id}
              </span>
            </div>
            <button 
              onClick={() => setSelectedLog(null)}
              className="text-[10px] font-mono border border-cyber-border/40 hover:border-cyber-primary/60 px-2 py-1 rounded text-cyber-muted hover:text-cyber-primary transition-all uppercase"
            >
              Close
            </button>
          </div>

          <div className="flex-1 overflow-y-auto space-y-4 font-mono text-xs">
            {/* Basic parameters */}
            <div>
              <div className="text-[10px] text-cyber-muted uppercase tracking-widest mb-1">Origin Package</div>
              <div className="p-2.5 bg-cyber-bg border border-cyber-border/30 rounded text-slate-200 font-bold select-all break-all">
                {selectedLog.sourcePackage}
              </div>
            </div>

            <div>
              <div className="text-[10px] text-cyber-muted uppercase tracking-widest mb-1">Target URL / Detail</div>
              <div className="p-2.5 bg-cyber-bg border border-cyber-border/30 rounded text-slate-200 select-all break-all leading-relaxed">
                {selectedLog.details}
              </div>
            </div>

            <div>
              <div className="text-[10px] text-cyber-muted uppercase tracking-widest mb-1">Trigger Domain Path</div>
              <div className="p-2.5 bg-cyber-bg border border-cyber-border/30 rounded text-slate-300 select-all break-all">
                {selectedLog.callerUrl}
              </div>
            </div>

            {/* Stack trace CLI terminal box */}
            <div>
              <div className="text-[10px] text-cyber-muted uppercase tracking-widest mb-1">Execution Call-Stack</div>
              <pre className="cli-terminal p-3 rounded text-[10px] leading-relaxed overflow-x-auto max-h-56 text-cyan-300/90 whitespace-pre">
                {selectedLog.stack || 'No Stack telemetry supplied by caller.'}
              </pre>
            </div>

            {/* Mitigation recommendation */}
            <div className={`p-3 rounded-lg border ${
              selectedLog.status === 'BLOCKED' 
                ? 'bg-cyber-danger/5 border-cyber-danger/20 text-cyber-danger' 
                : 'bg-cyber-primary/5 border-cyber-primary/20 text-cyber-primary'
            }`}>
              <div className="font-bold uppercase tracking-wider text-[10px] mb-1">Shield Mitigations</div>
              <p className="text-[11px] leading-relaxed opacity-90">
                {selectedLog.status === 'BLOCKED' 
                  ? 'Zero-Trust network interception blocked payload transfer. Malicious code was stopped in browser sandboxing scope. Check this script for exfiltration loops.' 
                  : 'Access permitted. Telemetry log recorded for supply chain audit logs. No standard policy violations detected.'}
              </p>
            </div>

            {/* Heuristic analysis panel */}
            <div className="pt-2 border-t border-cyber-border/30">
              {!aiAnalysis && !isAnalyzing ? (
                <button
                  onClick={() => {
                    setIsAnalyzing(true);
                    fetch('/api/analyze-threat', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ logId: selectedLog.id })
                    })
                      .then(res => res.json())
                      .then(data => {
                        setAiAnalysis(data);
                        setIsAnalyzing(false);
                      })
                      .catch(err => {
                        console.error(err);
                        setIsAnalyzing(false);
                      });
                  }}
                  className="w-full py-2.5 rounded-lg font-mono text-[10px] font-bold tracking-widest uppercase transition-all duration-300 border flex items-center justify-center gap-2 bg-slate-800/50 border-slate-700 text-slate-300 hover:bg-slate-800 hover:text-white"
                >
                  <Cpu className="w-4 h-4 text-cyber-purple" />
                  Run heuristic analysis
                </button>
              ) : isAnalyzing ? (
                <div className="flex flex-col items-center justify-center p-4 border border-cyber-purple/30 bg-cyber-purple/5 rounded-lg">
                  <Sparkles className="w-6 h-6 text-cyber-purple animate-spin mb-2" />
                  <span className="font-mono text-[10px] text-cyber-purple uppercase font-bold tracking-widest animate-pulse">Analyzing...</span>
                </div>
              ) : (
                <div className="p-4 rounded-lg border border-cyber-purple/40 bg-cyber-panel relative overflow-hidden">
                  <div className="absolute top-0 left-0 w-1 h-full bg-cyber-purple"></div>
                  <div className="flex items-center gap-2 mb-3">
                    <Cpu className="w-4 h-4 text-cyber-purple" />
                    <span className="font-display font-bold text-xs uppercase tracking-widest text-slate-200">Heuristic Threat Analysis</span>
                  </div>
                  <div className="space-y-3 font-sans text-xs">
                    <div>
                      <span className="text-[10px] font-mono text-slate-500 uppercase block mb-0.5">Summary</span>
                      <p className="text-slate-300 leading-relaxed">{aiAnalysis.summary}</p>
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <span className="text-[10px] font-mono text-slate-500 uppercase block mb-0.5">Risk Level</span>
                        <span className={`font-bold ${aiAnalysis.risk === 'Critical' ? 'text-cyber-danger' : 'text-cyber-warning'}`}>{aiAnalysis.risk}</span>
                      </div>
                      <div>
                        <span className="text-[10px] font-mono text-slate-500 uppercase block mb-0.5">Potential Impact</span>
                        <span className="text-slate-300">{aiAnalysis.impact}</span>
                      </div>
                    </div>
                    <div>
                      <span className="text-[10px] font-mono text-slate-500 uppercase block mb-0.5">Reasoning</span>
                      <p className="text-slate-300 leading-relaxed">{aiAnalysis.reason}</p>
                    </div>
                    <div className="p-2 bg-cyber-bg border border-cyber-border/30 rounded mt-2">
                      <span className="text-[10px] font-mono text-cyber-primary font-bold uppercase block mb-0.5">Recommended Action</span>
                      <p className="text-slate-300">{aiAnalysis.recommended}</p>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Replay Attack Button */}
            <div className="pt-2">
              <button
                onClick={() => setReplayLog(selectedLog)}
                className="w-full py-2.5 rounded-lg font-mono text-[10px] font-bold tracking-widest uppercase transition-all duration-300 border flex items-center justify-center gap-2 bg-cyber-primary/10 border-cyber-primary text-cyber-primary hover:bg-cyber-primary hover:text-white shadow-glow-primary/20"
              >
                <Play className="w-4 h-4" />
                Replay Attack Sequence
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Attack Replay Overlay Modal */}
      {replayLog && (
        <ReplayPlayer 
          log={replayLog} 
          onClose={() => setReplayLog(null)} 
        />
      )}
    </div>
  );
}
