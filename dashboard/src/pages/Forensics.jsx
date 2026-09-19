import React, { useEffect, useState } from 'react';
import { Search, Download, ShieldAlert, Clock, Code, FileText, Share2, SearchX, ExternalLink, FileSearch } from 'lucide-react';
import { usePhishGuard } from '../App';
import ReportExport from '../components/ReportExport';

export default function Forensics() {
  const { nonce } = usePhishGuard();
  const [incidents, setIncidents] = useState([]);
  const [activeId, setActiveId] = useState(null);
  const [q, setQ] = useState('');

  useEffect(() => {
    fetch('/api/incidents').then(r => r.json()).then(d => {
      const list = Array.isArray(d) ? d : [];
      setIncidents(list);
      if (list.length && !list.find(i => i.id === activeId)) setActiveId(list[0].id);
    }).catch(() => {});
  }, [nonce]);

  const filtered = q
    ? incidents.filter(i => `${i.id} ${i.package} ${i.title} ${i.identifier || ''}`.toLowerCase().includes(q.toLowerCase()))
    : incidents;
  const report = incidents.find(i => i.id === activeId);

  return (
    <div className="flex flex-col h-[calc(100vh-6rem)] gap-4">
      {/* toolbar */}
      <div className="glass-panel rounded-xl border border-cyber-border/40 px-5 py-3 flex items-center justify-between gap-4 shrink-0">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="p-2 rounded-lg bg-cyber-primary/10 border border-cyber-primary/20 shrink-0">
            <FileSearch className="w-4 h-4 text-cyber-primary" />
          </div>
          <div className="min-w-0">
            <h2 className="font-sans font-bold text-sm text-slate-100">Forensics Lab</h2>
            <p className="text-[11px] text-slate-400 truncate">
              {incidents.length} incident{incidents.length === 1 ? '' : 's'} · supply-chain findings and blocked runtime events
            </p>
          </div>
        </div>
        <ReportExport />
      </div>

      <div className="flex flex-1 gap-6 min-h-0">
      <div className="w-80 glass-panel rounded-xl border border-cyber-border/40 flex flex-col shrink-0 overflow-hidden">
        <div className="p-4 border-b border-cyber-border/30 bg-cyber-panel/50">
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search incidents…"
              className="w-full bg-cyber-bg/50 border border-cyber-border/40 rounded-lg pl-9 pr-4 py-2 text-xs font-mono text-slate-200 outline-none focus:border-cyber-primary/50" />
          </div>
        </div>
        <div className="flex-1 overflow-y-auto">
          {filtered.length === 0 && (
            <div className="p-6 text-center text-slate-500 font-mono text-xs">
              No critical/high findings or blocked runtime events yet.
            </div>
          )}
          {filtered.map(inc => (
            <button key={inc.id} onClick={() => setActiveId(inc.id)}
              className={`w-full text-left p-4 border-b border-cyber-border/20 hover:bg-slate-800/50 ${activeId === inc.id ? 'bg-slate-800 border-l-2 border-l-cyber-primary' : 'border-l-2 border-l-transparent'}`}>
              <div className="flex justify-between items-center mb-1">
                <span className="font-mono text-xs font-bold text-slate-200">{inc.id}</span>
                <span className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded ${inc.severity === 'critical' ? 'bg-cyber-danger/20 text-cyber-danger' : 'bg-cyber-warning/20 text-cyber-warning'}`}>
                  {(inc.severity || '').toUpperCase()}
                </span>
              </div>
              <div className="text-[10px] text-slate-400 mb-1 truncate">{inc.title}</div>
              <div className="text-[9px] font-mono text-slate-500 flex items-center gap-1">
                <Clock className="w-3 h-3" /> {inc.at ? new Date(inc.at).toLocaleString() : '—'} · {inc.kind}
              </div>
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 glass-panel rounded-xl border border-cyber-border/40 p-6 flex flex-col overflow-y-auto">
        {report ? (
          <>
            <div className="flex justify-between items-start mb-6 shrink-0">
              <div className="flex items-center gap-3">
                <div className="p-3 bg-cyber-danger/10 rounded-xl border border-cyber-danger/20"><ShieldAlert className="w-6 h-6 text-cyber-danger" /></div>
                <div>
                  <h2 className="font-display font-bold text-xl tracking-wide text-slate-100 uppercase">Incident Forensic Report</h2>
                  <div className="flex items-center gap-2 text-[11px] font-mono text-slate-400 mt-1">
                    <span className="text-cyber-primary">{report.id}</span><span>•</span>
                    <span>{report.at ? new Date(report.at).toLocaleString() : '—'}</span>
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button onClick={() => window.print()} className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-cyber-primary/30 bg-cyber-primary/10 hover:bg-cyber-primary/20 text-xs font-mono text-cyber-primary">
                  <Download className="w-3.5 h-3.5" /> Print / PDF
                </button>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4 mb-6 shrink-0">
              <Field label="Vector" value={report.vector} />
              <Field label="Package / Source" value={report.package} mono tone="warning" />
              <Field label="Severity" value={(report.severity || '').toUpperCase()} tone={report.severity === 'critical' ? 'danger' : 'warning'} />
              <Field label="Advisory" value={report.identifier || '—'} mono />
              <Field label="Reachability" value={report.direct ? 'Direct dependency' : report.kind === 'runtime' ? 'Runtime (browser)' : 'Transitive dependency'} />
              <Field label="Mitigation" value={report.mitigation} tone="success" />
            </div>

            <div className="mb-6">
              <h3 className="flex items-center gap-2 text-xs font-mono font-bold text-slate-300 uppercase tracking-widest mb-3 border-b border-cyber-border/30 pb-2">
                <FileText className="w-4 h-4 text-cyber-primary" /> Summary
              </h3>
              <p className="text-sm leading-relaxed text-slate-400">{report.detail}</p>
              {report.identifier && (
                <a href={`https://osv.dev/vulnerability/${report.identifier}`} target="_blank" rel="noreferrer"
                  className="text-cyber-primary text-xs inline-flex items-center gap-1 mt-2">Open advisory <ExternalLink className="w-3 h-3" /></a>
              )}
            </div>

            {report.stack && (
              <div className="flex-1 min-h-0 flex flex-col">
                <h3 className="flex items-center gap-2 text-xs font-mono font-bold text-slate-300 uppercase tracking-widest mb-3 border-b border-cyber-border/30 pb-2 shrink-0">
                  <Code className="w-4 h-4 text-cyber-purple" /> Captured Call Stack
                </h3>
                <div className="flex-1 bg-[#22252B] border border-slate-700/50 rounded-lg p-4 overflow-y-auto">
                  <pre className="font-mono text-[11px] leading-relaxed text-slate-300 whitespace-pre-wrap">{report.stack}</pre>
                </div>
              </div>
            )}
          </>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center text-slate-500">
            <SearchX className="w-12 h-12 mb-4 opacity-50" />
            <p className="font-mono text-sm">No incident selected.</p>
          </div>
        )}
      </div>
      </div>
    </div>
  );
}

function Field({ label, value, mono, tone }) {
  const col = tone === 'danger' ? 'text-cyber-danger' : tone === 'warning' ? 'text-cyber-warning' : tone === 'success' ? 'text-cyber-success' : 'text-slate-200';
  return (
    <div className="p-4 rounded-lg bg-cyber-bg border border-cyber-border/30">
      <div className="text-[10px] font-mono text-slate-500 uppercase mb-1">{label}</div>
      <div className={`font-bold text-sm ${mono ? 'font-mono' : ''} ${col} break-words`}>{value || '—'}</div>
    </div>
  );
}
