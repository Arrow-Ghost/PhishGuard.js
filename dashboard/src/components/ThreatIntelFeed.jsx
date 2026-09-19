import React, { useState, useEffect, useMemo } from 'react';
import { ShieldAlert, ExternalLink, Flame, ArrowUpRight, Wrench, CircleSlash, PackageCheck, ShieldCheck } from 'lucide-react';
import { usePhishGuard } from '../App';

const SEV = {
  critical: { chip: 'bg-cyber-danger/15 text-cyber-danger border-cyber-danger/40', bar: 'bg-cyber-danger' },
  high:     { chip: 'bg-orange-500/15 text-orange-400 border-orange-500/40',       bar: 'bg-orange-500' },
  moderate: { chip: 'bg-cyber-warning/15 text-cyber-warning border-cyber-warning/40', bar: 'bg-cyber-warning' },
  low:      { chip: 'bg-sky-500/15 text-sky-400 border-sky-500/40',                bar: 'bg-sky-500' },
};

const FILTERS = [
  { key: 'all', label: 'All' },
  { key: 'exploited', label: 'Exploited' },
  { key: 'direct', label: 'Direct' },
  { key: 'fixable', label: 'Fixable' },
];

export default function ThreatIntelFeed() {
  const pg = usePhishGuard();
  const nonce = pg ? pg.nonce : 0;
  const [data, setData] = useState({ items: [], summary: null });
  const [filter, setFilter] = useState('all');

  useEffect(() => {
    fetch('/api/threat-intel')
      .then(r => r.json())
      .then(d => setData(Array.isArray(d) ? { items: d, summary: null } : (d || { items: [], summary: null })))
      .catch(() => {});
  }, [nonce]);

  const items = useMemo(() => {
    const list = data.items || [];
    if (filter === 'exploited') return list.filter(i => i.knownExploited);
    if (filter === 'direct') return list.filter(i => i.direct);
    if (filter === 'fixable') return list.filter(i => i.actionable);
    return list;
  }, [data, filter]);

  const s = data.summary;

  return (
    <div className="glass-panel rounded-xl border border-cyber-border/40 p-5 flex flex-col h-[400px] overflow-hidden">
      <div className="flex justify-between items-start mb-2.5 shrink-0">
        <div className="flex items-center gap-2 min-w-0">
          <ShieldAlert className="w-5 h-5 text-cyber-primary shrink-0" />
          <div className="min-w-0">
            <h3 className="font-sans font-bold text-sm tracking-wide text-slate-100">Advisories Affecting This Repo</h3>
            <span className="text-[10px] text-slate-400">
              {s
                ? `${s.total} matched · ${s.fixable} fixable${s.remediated ? ` · ${s.remediated} remediated` : ''}`
                : 'OSV.dev · npm registry'}
            </span>
          </div>
        </div>
        {s && s.exploited > 0 && (
          <span className="flex items-center gap-1 px-2 py-0.5 rounded bg-cyber-danger/15 border border-cyber-danger/40 text-cyber-danger font-mono text-[9px] font-bold shrink-0">
            <Flame className="w-3 h-3" /> {s.exploited} KEV
          </span>
        )}
      </div>

      {/* filters */}
      <div className="flex gap-1 mb-2.5 shrink-0">
        {FILTERS.map(f => {
          const n = f.key === 'all' ? (s ? s.total : 0)
            : f.key === 'exploited' ? (s ? s.exploited : 0)
            : f.key === 'direct' ? (s ? s.direct : 0)
            : (s ? s.fixable : 0);
          return (
            <button key={f.key} onClick={() => setFilter(f.key)}
              className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase tracking-wider border transition-colors ${
                filter === f.key
                  ? 'bg-cyber-primary/15 border-cyber-primary/50 text-cyber-primary'
                  : 'border-cyber-border/40 text-slate-500 hover:text-slate-300'
              }`}>
              {f.label}{n ? ` ${n}` : ''}
            </button>
          );
        })}
      </div>

      <div className="flex-1 overflow-y-auto space-y-1.5 pr-1.5 custom-scrollbar min-h-0">
        {items.map(ev => {
          const sev = SEV[ev.severity] || SEV.low;
          const Row = ev.url ? 'a' : 'div';
          return (
            <Row
              key={ev.id}
              {...(ev.url ? { href: ev.url, target: '_blank', rel: 'noreferrer' } : {})}
              className={`group flex gap-2 p-2.5 rounded-lg border transition-all block ${
                ev.remediated
                  ? 'bg-cyber-success/[0.05] border-cyber-success/30 hover:border-cyber-success/50'
                  : 'bg-cyber-panel/40 border-cyber-border/30 hover:border-cyber-primary/40 hover:bg-cyber-panel/70'}`}
            >
              <span className={`w-0.5 rounded-full shrink-0 ${sev.bar}`} />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-1.5 mb-1 flex-wrap">
                  <span className={`px-1.5 py-0.5 rounded border font-mono text-[8px] font-bold uppercase ${sev.chip}`}>
                    {ev.severity}
                  </span>
                  <span className="font-mono text-[9px] font-bold text-slate-300 truncate">{ev.identifier}</span>
                  {ev.knownExploited && (
                    <span className="flex items-center gap-0.5 px-1 py-0.5 rounded bg-cyber-danger/20 text-cyber-danger font-mono text-[8px] font-bold">
                      <Flame className="w-2.5 h-2.5" /> KEV
                    </span>
                  )}
                  {ev.direct && (
                    <span className="px-1 py-0.5 rounded bg-cyber-primary/15 text-cyber-primary font-mono text-[8px] font-bold">DIRECT</span>
                  )}
                  {ev.remediated && (
                    <span className="flex items-center gap-0.5 px-1 py-0.5 rounded bg-cyber-success/20 text-cyber-success font-mono text-[8px] font-bold">
                      <ShieldCheck className="w-2.5 h-2.5" />
                      {ev.remediationPending ? 'FIX PENDING' : 'REMEDIATED'}
                    </span>
                  )}
                  {ev.url && <ExternalLink className="w-2.5 h-2.5 text-slate-600 group-hover:text-cyber-primary ml-auto shrink-0" />}
                </div>

                <div className="text-[11px] leading-snug text-slate-200 font-medium line-clamp-2 mb-1">{ev.title}</div>

                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-[9px] text-slate-400 truncate max-w-[45%]">
                    {ev.package}<span className="text-slate-600">@{ev.version}</span>
                  </span>
                  {ev.fixedVersion ? (
                    <span className="flex items-center gap-1 font-mono text-[9px] text-cyber-success">
                      <Wrench className="w-2.5 h-2.5" /> {ev.fixedVersion}
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 font-mono text-[9px] text-slate-500">
                      <CircleSlash className="w-2.5 h-2.5" /> no fix
                    </span>
                  )}
                  {(ev.cwes || []).slice(0, 2).map(c => (
                    <span key={c} className="font-mono text-[8px] px-1 py-0.5 rounded bg-slate-700/40 text-slate-400">{c}</span>
                  ))}
                </div>
              </div>
            </Row>
          );
        })}

        {items.length === 0 && (
          <div className="flex flex-col items-center justify-center h-full text-center px-4">
            <PackageCheck className="w-8 h-8 text-cyber-success/40 mb-2" />
            <span className="text-[11px] font-mono text-slate-400">
              {filter === 'all' ? 'No advisories affect installed packages' : `Nothing matches “${filter}”`}
            </span>
          </div>
        )}
      </div>

      {s && s.total > items.length && filter === 'all' && (
        <div className="shrink-0 pt-2 mt-1 border-t border-cyber-border/30 text-[9px] font-mono text-slate-500 flex items-center gap-1">
          <ArrowUpRight className="w-3 h-3" /> showing {items.length} of {s.total} — open Supply Chain Scanner for the full list
        </div>
      )}
    </div>
  );
}
