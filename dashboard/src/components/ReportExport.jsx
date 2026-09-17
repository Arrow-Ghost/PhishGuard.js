import React, { useEffect, useState } from 'react';
import { Download, ChevronDown, FileText, FileJson, Table, Globe, Check, Loader2 } from 'lucide-react';

const WINDOWS = [
  { key: '24h', label: 'Last 24 hours' },
  { key: '48h', label: 'Last 48 hours' },
  { key: '7d', label: 'Last 7 days' },
  { key: '14d', label: 'Last 14 days' },
  { key: '30d', label: 'Last 30 days' },
  { key: '90d', label: 'Last 90 days' },
  { key: 'all', label: 'All recorded history' },
];

const FORMATS = [
  { key: 'html', label: 'HTML report', hint: 'printable, opens in a browser', icon: Globe },
  { key: 'md', label: 'Markdown', hint: 'for tickets / wikis', icon: FileText },
  { key: 'csv', label: 'CSV', hint: 'for spreadsheets / SIEM', icon: Table },
  { key: 'json', label: 'JSON bundle', hint: 'full machine-readable dump', icon: FileJson },
];

/**
 * Timed forensic report export: pick a duration, pick a format, download.
 * The hub assembles scans, findings, runtime telemetry and posture snapshots
 * for the window and streams the file back with a Content-Disposition header.
 */
export default function ReportExport() {
  const [open, setOpen] = useState(false);
  const [win, setWin] = useState('7d');
  const [busy, setBusy] = useState(null);
  const [preview, setPreview] = useState(null);

  useEffect(() => {
    if (!open) return;
    const close = () => setOpen(false);
    window.addEventListener('click', close);
    return () => window.removeEventListener('click', close);
  }, [open]);

  // show what the chosen window actually contains before downloading
  useEffect(() => {
    if (!open) return;
    setPreview(null);
    fetch(`/api/forensics/report?window=${win}&format=json`)
      .then(r => r.json())
      .then(d => setPreview(d.summary || null))
      .catch(() => {});
  }, [open, win]);

  const download = async (fmt) => {
    setBusy(fmt);
    try {
      const url = `/api/forensics/report?window=${encodeURIComponent(win)}&format=${fmt}&download=1`;
      const res = await fetch(url);
      if (!res.ok) throw new Error(`export failed (${res.status})`);
      const blob = await res.blob();
      const cd = res.headers.get('content-disposition') || '';
      const m = cd.match(/filename="?([^"]+)"?/);
      const name = m ? m[1] : `phishguard-report-${win}.${fmt === 'md' ? 'md' : fmt}`;
      const href = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = href;
      a.download = name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(href), 4000);
      setOpen(false);
    } catch (err) {
      console.error('[phishguard] report export failed', err);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="relative shrink-0" onClick={e => e.stopPropagation()}>
      <button onClick={() => setOpen(o => !o)}
        className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-cyber-primary/30 bg-cyber-primary/10 hover:bg-cyber-primary/20 text-xs font-mono text-cyber-primary transition-colors">
        <Download className="w-3.5 h-3.5" />
        Download report
        <span className="px-1.5 py-0.5 rounded bg-cyber-primary/20 text-[9px] font-bold">{win}</span>
        <ChevronDown className={`w-3 h-3 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-2 w-[320px] rounded-xl border border-cyber-border/60 bg-cyber-panel shadow-2xl shadow-black/60 z-50 overflow-hidden">
          {/* duration */}
          <div className="px-4 pt-3 pb-2">
            <div className="text-[9px] font-mono uppercase tracking-widest text-slate-500 mb-2">Reporting period</div>
            <div className="grid grid-cols-2 gap-1">
              {WINDOWS.map(w => (
                <button key={w.key} onClick={() => setWin(w.key)}
                  className={`flex items-center gap-1.5 px-2 py-1.5 rounded text-[10px] font-mono text-left transition-colors ${
                    win === w.key
                      ? 'bg-cyber-primary/15 text-cyber-primary border border-cyber-primary/40'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'}`}>
                  <Check className={`w-3 h-3 shrink-0 ${win === w.key ? 'opacity-100' : 'opacity-0'}`} />
                  {w.label}
                </button>
              ))}
            </div>
          </div>

          {/* what's in it */}
          <div className="px-4 py-2 border-y border-cyber-border/40 bg-cyber-bg/40">
            {preview ? (
              <div className="grid grid-cols-3 gap-2">
                {[['Scans', preview.scansInWindow], ['Findings', preview.findingsInLatestScan],
                  ['Runtime', preview.runtimeEvents], ['Blocked', preview.blockedEvents],
                  ['Exploited', preview.knownExploited], ['Quarantined', preview.quarantined]].map(([l, v]) => (
                  <div key={l}>
                    <div className="font-mono text-sm font-bold text-slate-200 tabular-nums">{v}</div>
                    <div className="text-[8px] font-mono uppercase tracking-wider text-slate-500">{l}</div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-[10px] font-mono text-slate-500 py-2">Reading window…</div>
            )}
          </div>

          {/* formats */}
          <div className="px-2 py-2">
            <div className="px-2 text-[9px] font-mono uppercase tracking-widest text-slate-500 mb-1">Download as</div>
            {FORMATS.map(f => {
              const Icon = f.icon;
              return (
                <button key={f.key} onClick={() => download(f.key)} disabled={!!busy}
                  className="w-full flex items-center gap-2.5 px-2 py-2 rounded text-left hover:bg-slate-800/70 disabled:opacity-50 transition-colors">
                  {busy === f.key
                    ? <Loader2 className="w-3.5 h-3.5 text-cyber-primary animate-spin shrink-0" />
                    : <Icon className="w-3.5 h-3.5 text-slate-400 shrink-0" />}
                  <div className="min-w-0">
                    <div className="text-[11px] text-slate-200">{f.label}</div>
                    <div className="text-[9px] font-mono text-slate-500 truncate">{f.hint}</div>
                  </div>
                  <Download className="w-3 h-3 text-slate-600 ml-auto shrink-0" />
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
