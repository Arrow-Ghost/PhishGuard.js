import React, { useEffect, useMemo, useState } from 'react';
import {
  History, GitBranch, GitMerge, ShieldAlert, ShieldCheck, PackageCheck,
  Search, ExternalLink, ArrowUpCircle, Archive, Loader2, AlertTriangle,
} from 'lucide-react';
import { usePhishGuard } from '../App';

const KIND = {
  created:    { icon: GitBranch,    color: '#A4ACB8', label: 'First release' },
  advisory:   { icon: ShieldAlert,  color: '#E58585', label: 'Advisory' },
  patched:    { icon: ShieldCheck,  color: '#7FD1A8', label: 'Patched' },
  installed:  { icon: PackageCheck, color: '#A9C3DE', label: 'Your version' },
  deprecated: { icon: Archive,      color: '#E2B36B', label: 'Deprecated' },
  latest:     { icon: GitMerge,     color: '#86B4E6', label: 'Latest' },
};

const SEV_COLOR = { critical: '#E58585', high: '#E59A6A', moderate: '#E2B36B', low: '#86B4E6' };

function fmt(d) {
  if (!d) return '—';
  const t = new Date(d);
  return Number.isFinite(t.getTime()) ? t.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : '—';
}

/**
 * Real dependency history for any package installed in this repo:
 * npm publish timeline joined with every OSV advisory ever filed against it.
 */
export default function DependencyEvolutionTimeline() {
  const pg = usePhishGuard();
  const nonce = pg ? pg.nonce : 0;
  const [index, setIndex] = useState([]);
  const [selected, setSelected] = useState(null);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);
  const [q, setQ] = useState('');
  const [open, setOpen] = useState(false);

  // package list from the actual scan
  useEffect(() => {
    fetch('/api/packages/timeline-index')
      .then(r => r.json())
      .then(d => {
        const list = (d && d.packages) || [];
        setIndex(list);
        setSelected(s => s || (list[0] && list[0].name) || null);
      })
      .catch(() => setIndex([]));
  }, [nonce]);

  // timeline for the chosen package
  useEffect(() => {
    if (!selected) return;
    setLoading(true);
    setErr(null);
    const path = selected.startsWith('@')
      ? `/api/packages/${selected.split('/').map(encodeURIComponent).join('/')}/timeline`
      : `/api/packages/${encodeURIComponent(selected)}/timeline`;
    fetch(path)
      .then(r => r.json())
      .then(d => {
        if (d && d.error) setErr(d.error);
        setData(d && !d.error ? d : null);
        setLoading(false);
      })
      .catch(e => { setErr(String(e.message || e)); setLoading(false); });
  }, [selected, nonce]);

  const filtered = useMemo(() => {
    if (!q.trim()) return index.slice(0, 300);
    const t = q.toLowerCase();
    return index.filter(p => p.name.toLowerCase().includes(t)).slice(0, 300);
  }, [index, q]);

  useEffect(() => {
    if (!open) return;
    const close = () => setOpen(false);
    window.addEventListener('click', close);
    return () => window.removeEventListener('click', close);
  }, [open]);

  const current = index.find(p => p.name === selected);
  const events = (data && data.events) || [];

  return (
    <div className="glass-panel rounded-xl border border-cyber-border/40 p-5 flex flex-col h-full min-h-[350px] overflow-hidden">
      <div className="flex justify-between items-start gap-3 mb-4 border-b border-cyber-border/30 pb-3 shrink-0">
        <div className="flex items-center gap-2 min-w-0">
          <History className="w-5 h-5 text-cyber-primary shrink-0" />
          <div className="min-w-0">
            <h3 className="font-sans font-bold text-sm tracking-wide text-slate-100">Dependency Evolution Timeline</h3>
            <span className="text-[10px] text-slate-400">
              {index.length ? `npm release history + OSV advisories · ${index.length} packages installed` : 'Run a scan to load packages'}
            </span>
          </div>
        </div>

        {/* searchable package picker over every installed dependency */}
        <div className="relative shrink-0" onClick={e => e.stopPropagation()}>
          <button onClick={() => setOpen(o => !o)}
            className="flex items-center gap-2 bg-cyber-bg/50 border border-cyber-border/40 rounded px-3 py-1.5 text-xs font-mono text-slate-300 hover:border-cyber-primary/50 max-w-[220px]">
            <span className="truncate">{selected || 'select package'}</span>
            {current && current.category !== 'safe' && (
              <span className="w-1.5 h-1.5 rounded-full shrink-0"
                style={{ background: current.category === 'critical' ? '#E58585' : '#E2B36B' }} />
            )}
          </button>

          {open && (
            <div className="absolute right-0 top-full mt-1.5 w-[280px] rounded-lg border border-cyber-border/60 bg-cyber-panel shadow-2xl shadow-black/60 z-50 overflow-hidden">
              <div className="p-2 border-b border-cyber-border/40">
                <div className="relative">
                  <Search className="w-3 h-3 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
                  <input autoFocus value={q} onChange={e => setQ(e.target.value)}
                    placeholder="Filter packages…"
                    className="w-full bg-cyber-bg/60 border border-cyber-border/40 rounded pl-7 pr-2 py-1.5 text-[11px] font-mono text-slate-200 outline-none focus:border-cyber-primary/50" />
                </div>
              </div>
              <div className="max-h-[260px] overflow-y-auto custom-scrollbar">
                {filtered.map(p => (
                  <button key={p.name}
                    onClick={() => { setSelected(p.name); setOpen(false); setQ(''); }}
                    className={`w-full flex items-center gap-2 px-3 py-1.5 text-left hover:bg-slate-800/70 transition-colors ${
                      selected === p.name ? 'bg-cyber-primary/10' : ''}`}>
                    <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{
                      background: p.category === 'critical' ? '#E58585' : p.category === 'warning' ? '#E2B36B' : '#7FD1A8',
                    }} />
                    <span className="font-mono text-[11px] text-slate-200 truncate">{p.name}</span>
                    <span className="font-mono text-[9px] text-slate-500 ml-auto shrink-0">{p.version}</span>
                    {p.direct && <span className="font-mono text-[8px] text-cyber-primary shrink-0">D</span>}
                  </button>
                ))}
                {filtered.length === 0 && (
                  <div className="px-3 py-4 text-center font-mono text-[10px] text-slate-500">No package matches.</div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* summary strip */}
      {data && data.available && (
        <div className="flex items-center gap-3 mb-3 shrink-0 flex-wrap">
          <Chip label="installed" value={data.installedVersion || '—'} tone={data.stats.advisoriesAffectingInstalled ? 'danger' : 'success'} />
          <Chip label="latest" value={data.latest || '—'} />
          {data.versionsBehind != null && data.versionsBehind > 0 && (
            <Chip label="behind" value={`${data.versionsBehind} releases`} tone="warning" />
          )}
          <Chip label="advisories" value={`${data.stats.advisoriesAffectingInstalled} / ${data.stats.advisoriesTotal}`}
            tone={data.stats.advisoriesAffectingInstalled ? 'danger' : 'success'} />
          {data.deprecated && <Chip label="status" value="deprecated" tone="warning" />}
          {data.upgrade && (
            <span className="flex items-center gap-1.5 px-2 py-1 rounded border border-cyber-success/40 bg-cyber-success/10 text-cyber-success font-mono text-[10px] ml-auto">
              <ArrowUpCircle className="w-3 h-3" />
              upgrade to {data.upgrade.to} — clears {data.upgrade.clears}/{data.upgrade.of}
            </span>
          )}
        </div>
      )}

      {/* timeline */}
      <div className="flex-1 relative min-h-0 overflow-x-auto overflow-y-hidden custom-scrollbar">
        {loading && (
          <div className="h-full flex items-center justify-center gap-2 text-slate-500 font-mono text-xs">
            <Loader2 className="w-4 h-4 animate-spin" /> Loading {selected} history…
          </div>
        )}

        {!loading && err && (
          <div className="h-full flex flex-col items-center justify-center text-center px-6">
            <AlertTriangle className="w-7 h-7 text-cyber-warning mb-2" />
            <span className="font-mono text-[11px] text-cyber-warning">{err}</span>
          </div>
        )}

        {!loading && !err && data && !data.available && (
          <div className="h-full flex flex-col items-center justify-center text-center px-6">
            <AlertTriangle className="w-7 h-7 text-slate-600 mb-2" />
            <span className="font-mono text-[11px] text-slate-500">{data.reason}</span>
          </div>
        )}

        {!loading && !err && events.length > 0 && (
          <div className="h-full flex items-center min-w-max px-6 relative">
            <div className="absolute left-6 right-6 top-1/2 h-0.5 bg-cyber-border/40 rounded-full -translate-y-1/2" />
            <div className="flex gap-10 relative z-10">
              {events.map((e, idx) => {
                const k = KIND[e.kind] || KIND.created;
                const Icon = k.icon;
                const col = e.kind === 'advisory' ? (SEV_COLOR[e.severity] || k.color) : k.color;
                const above = idx % 2 === 0;
                const Card = (
                  <div className="w-[150px] rounded-lg border bg-cyber-bg/90 backdrop-blur-sm p-2 shadow-xl"
                    style={{ borderColor: `${col}55` }}>
                    <div className="flex items-center gap-1 mb-1">
                      <span className="font-mono text-[8px] uppercase tracking-wider" style={{ color: col }}>{k.label}</span>
                      {e.affectsInstalled && (
                        <span className="ml-auto font-mono text-[7px] px-1 rounded bg-cyber-danger text-white font-bold">HITS YOU</span>
                      )}
                    </div>
                    <div className="text-[10px] font-bold text-slate-100 leading-tight mb-0.5 break-words">{e.title}</div>
                    {e.detail && <div className="text-[9px] text-slate-400 leading-snug line-clamp-3">{e.detail}</div>}
                    <div className="flex items-center justify-between mt-1.5 pt-1 border-t border-cyber-border/30">
                      <span className="font-mono text-[8px] text-slate-500">{fmt(e.date)}</span>
                      {e.version && <span className="font-mono text-[8px] text-cyber-primary">v{e.version}</span>}
                    </div>
                    {e.url && (
                      <a href={e.url} target="_blank" rel="noreferrer"
                        className="flex items-center gap-1 mt-1 font-mono text-[8px] text-cyber-primary hover:underline">
                        advisory <ExternalLink className="w-2 h-2" />
                      </a>
                    )}
                  </div>
                );
                return (
                  <div key={`${e.kind}-${idx}`} className="relative flex flex-col items-center justify-center w-[150px]">
                    <div className="absolute bottom-[calc(50%+18px)]">{above ? Card : null}</div>
                    <div className="w-7 h-7 rounded-full border-2 flex items-center justify-center bg-cyber-panel z-10 transition-transform hover:scale-125"
                      style={{ borderColor: col, boxShadow: `0 0 10px ${col}55` }}>
                      <Icon className="w-3.5 h-3.5" style={{ color: col }} />
                    </div>
                    <div className="absolute top-[calc(50%+18px)]">{!above ? Card : null}</div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {!loading && !err && data && data.available && events.length === 0 && (
          <div className="h-full flex flex-col items-center justify-center text-center px-6">
            <PackageCheck className="w-7 h-7 text-cyber-success/50 mb-2" />
            <span className="font-mono text-[11px] text-slate-500">
              No dated events for {selected} — the registry returned no publish history.
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

function Chip({ label, value, tone }) {
  const cls = tone === 'danger' ? 'border-cyber-danger/40 bg-cyber-danger/10 text-cyber-danger'
    : tone === 'warning' ? 'border-cyber-warning/40 bg-cyber-warning/10 text-cyber-warning'
    : tone === 'success' ? 'border-cyber-success/40 bg-cyber-success/10 text-cyber-success'
    : 'border-cyber-border/40 bg-cyber-bg/60 text-slate-300';
  return (
    <span className={`px-2 py-1 rounded border font-mono text-[10px] ${cls}`}>
      <span className="opacity-60">{label}</span> {value}
    </span>
  );
}
