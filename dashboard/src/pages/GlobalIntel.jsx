import React, { useEffect, useMemo, useState } from 'react';
import {
  Globe2, Flame, Bug, PackageX, ExternalLink, Search, RefreshCw, AlertOctagon,
  ShieldAlert, Building2, CalendarClock, Link2, CheckCircle2, XCircle, Radio,
  ArrowDownWideNarrow, Check, ChevronRight,
} from 'lucide-react';
import { usePhishGuard } from '../App';

const KIND = {
  malware:   { label: 'MALICIOUS PACKAGE', icon: PackageX,   cls: 'bg-cyber-danger/15 text-cyber-danger border-cyber-danger/40' },
  exploited: { label: 'EXPLOITED IN WILD', icon: Flame,      cls: 'bg-orange-600/15 text-orange-400 border-orange-600/40' },
  advisory:  { label: 'ADVISORY',          icon: Bug,        cls: 'bg-cyber-primary/15 text-cyber-primary border-cyber-primary/40' },
};

const SEV = {
  critical: 'bg-cyber-danger/15 text-cyber-danger border-cyber-danger/40',
  high:     'bg-orange-500/15 text-orange-400 border-orange-500/40',
  moderate: 'bg-cyber-warning/15 text-cyber-warning border-cyber-warning/40',
  low:      'bg-sky-500/15 text-sky-400 border-sky-500/40',
};

const SORTS = [
  { key: 'recent',   label: 'Newest first',     hint: 'most recently published' },
  { key: 'severity', label: 'Severity',         hint: 'critical first' },
  { key: 'exposure', label: 'Your exposure',     hint: 'items in your tree first' },
  { key: 'malware',  label: 'Malware first',    hint: 'confirmed malicious packages' },
  { key: 'package',  label: 'Package name',     hint: 'A → Z' },
];

const SEV_RANK = { critical: 4, high: 3, moderate: 2, low: 1 };

const FILTERS = [
  { key: 'all', label: 'All intel' },
  { key: 'affecting', label: 'Affects this repo' },
  { key: 'malware', label: 'Malware campaigns' },
  { key: 'exploited', label: 'Actively exploited' },
  { key: 'critical', label: 'Critical' },
];

function ago(iso) {
  if (!iso) return '—';
  const ms = Date.now() - new Date(iso).getTime();
  if (!Number.isFinite(ms)) return '—';
  const h = Math.floor(ms / 3600000);
  if (h < 1) return `${Math.max(1, Math.floor(ms / 60000))}m ago`;
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return d < 30 ? `${d}d ago` : new Date(iso).toLocaleDateString();
}

/** The "source" that caused it: the package for npm intel, the vendor for KEV. */
function causedBy(item) {
  if (item.packages && item.packages.length) {
    return { kind: 'package', primary: item.packages[0].name, all: item.packages.map(p => p.name) };
  }
  if (item.vendor || item.product) {
    return { kind: 'vendor', primary: [item.vendor, item.product].filter(Boolean).join(' / '), all: [] };
  }
  return { kind: 'unknown', primary: 'unattributed', all: [] };
}

export default function GlobalIntel() {
  const pg = usePhishGuard();
  const nonce = pg ? pg.nonce : 0;
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');
  const [q, setQ] = useState('');
  const [selected, setSelected] = useState(null);
  const [err, setErr] = useState(null);
  const [sort, setSort] = useState('recent');
  const [sortOpen, setSortOpen] = useState(false);
  const [sourcesOpen, setSourcesOpen] = useState(false);

  const load = (force) => {
    setLoading(true);
    setErr(null);
    fetch(`/api/global-intel?limit=150${force ? '&ttlHours=0' : ''}`)
      .then(async r => {
        if (!r.ok) {
          throw new Error(r.status === 404
            ? 'The hub does not expose /api/global-intel. It is running an older build — restart `phishguard dashboard`.'
            : `Hub returned HTTP ${r.status}`);
        }
        const ct = r.headers.get('content-type') || '';
        if (!ct.includes('json')) throw new Error('Hub returned a non-JSON response for /api/global-intel.');
        return r.json();
      })
      .then(d => { setData(d); setLoading(false); })
      .catch(e => { setErr(e.message || String(e)); setLoading(false); });
  };

  useEffect(() => { load(false); }, [nonce]);

  const items = useMemo(() => {
    const list = (data && data.items) || [];
    let out = list;
    if (filter === 'affecting') out = out.filter(i => i.affectsRepo);
    else if (filter === 'malware') out = out.filter(i => i.kind === 'malware');
    else if (filter === 'exploited') out = out.filter(i => i.kind === 'exploited');
    else if (filter === 'critical') out = out.filter(i => i.severity === 'critical');
    if (q.trim()) {
      const t = q.toLowerCase();
      out = out.filter(i =>
        `${i.identifier} ${i.title} ${i.vendor || ''} ${i.product || ''} ${(i.packages || []).map(p => p.name).join(' ')}`
          .toLowerCase().includes(t));
    }

    const ts = i => new Date(i.published || 0).getTime() || 0;
    const pkgName = i => (i.packages && i.packages[0] ? i.packages[0].name : (i.vendor || i.product || i.identifier || ''));
    const sorted = [...out];
    if (sort === 'recent') {
      sorted.sort((a, b) => ts(b) - ts(a));
    } else if (sort === 'severity') {
      sorted.sort((a, b) => (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0) || ts(b) - ts(a));
    } else if (sort === 'exposure') {
      sorted.sort((a, b) => (b.affectsRepo - a.affectsRepo) || ts(b) - ts(a));
    } else if (sort === 'malware') {
      sorted.sort((a, b) => ((b.kind === 'malware') - (a.kind === 'malware')) || ts(b) - ts(a));
    } else if (sort === 'package') {
      sorted.sort((a, b) => pkgName(a).localeCompare(pkgName(b)) || ts(b) - ts(a));
    }
    return sorted;
  }, [data, filter, q, sort]);

  useEffect(() => {
    if (!sortOpen) return;
    const close = () => setSortOpen(false);
    window.addEventListener('click', close);
    return () => window.removeEventListener('click', close);
  }, [sortOpen]);

  const stats = (data && data.stats) || { total: 0, affectingRepo: 0, malware: 0, exploited: 0, critical: 0 };
  const allFeedsOk = data && data.sources ? data.sources.every(x => x.ok) : null;
  const active = selected && items.find(i => i.id === selected.id) ? selected : null;

  return (
    <div className="flex flex-col h-[calc(100vh-6rem)] gap-4">
      {/* header */}
      <div className="glass-panel rounded-xl border border-cyber-border/40 p-5 shrink-0">
        <div className="flex justify-between items-start gap-4 flex-wrap">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyber-primary/10 border border-cyber-primary/25">
              <Globe2 className="w-6 h-6 text-cyber-primary" />
            </div>
            <div>
              <h2 className="font-sans font-bold text-lg text-slate-100">Global Security Intel</h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Live supply-chain breaches worldwide, the package or vendor behind each one, and whether it reaches your tree.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button onClick={() => load(true)} disabled={loading}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-cyber-border/40 text-[11px] font-mono text-slate-300 hover:text-white hover:border-cyber-primary/60 disabled:opacity-50 transition-all">
              <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} /> Refresh feeds
            </button>
          </div>
        </div>

        {/* stat strip */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mt-5">
          <Stat label="Intel items" value={stats.total} icon={Radio} tone="primary" />
          <Stat label="Affects this repo" value={stats.affectingRepo} icon={AlertOctagon} tone={stats.affectingRepo ? 'danger' : 'success'} />
          <Stat label="Malware campaigns" value={stats.malware} icon={PackageX} tone="danger" />
          <Stat label="Exploited in wild" value={stats.exploited} icon={Flame} tone="warning" />
          <Stat label="Critical severity" value={stats.critical} icon={ShieldAlert} tone="warning" />
        </div>

        {/* feed status - collapsed until asked for */}
        <div className="mt-4 pt-3 border-t border-cyber-border/30">
          <button onClick={() => setSourcesOpen(o => !o)}
            className="flex items-center gap-1.5 text-[9px] font-mono uppercase tracking-widest text-slate-500 hover:text-slate-300 transition-colors">
            <ChevronRight className={`w-3 h-3 transition-transform ${sourcesOpen ? 'rotate-90' : ''}`} />
            Feed sources
            {allFeedsOk === false && <span className="text-cyber-warning normal-case tracking-normal">· degraded</span>}
          </button>
          {sourcesOpen && (
            <div className="flex items-center gap-3 flex-wrap mt-2.5">
              {(data && data.sources || []).map(s => (
                <a key={s.name} href={s.url} target="_blank" rel="noreferrer"
                  className="flex items-center gap-1.5 px-2 py-1 rounded border border-cyber-border/40 hover:border-cyber-primary/50 transition-colors">
                  {s.ok ? <CheckCircle2 className="w-3 h-3 text-cyber-success" /> : <XCircle className="w-3 h-3 text-cyber-danger" />}
                  <span className="font-mono text-[9px] text-slate-300">{s.name}</span>
                  <span className="font-mono text-[9px] text-slate-500">{s.count}</span>
                </a>
              ))}
              {data && data.note && <span className="text-[9px] font-mono text-cyber-warning">{data.note}</span>}
            </div>
          )}
        </div>
      </div>

      {/* body */}
      <div className="flex-1 flex gap-4 min-h-0">
        {/* list */}
        <div className="flex-1 glass-panel rounded-xl border border-cyber-border/40 flex flex-col min-w-0">
          <div className="p-4 border-b border-cyber-border/30 flex items-center gap-3 flex-wrap shrink-0">
            <div className="relative flex-1 min-w-[180px]">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input value={q} onChange={e => setQ(e.target.value)}
                placeholder="Search package, CVE, vendor…"
                className="w-full bg-cyber-bg/60 border border-cyber-border/40 rounded-lg pl-8 pr-3 py-1.5 text-[11px] font-mono text-slate-200 outline-none focus:border-cyber-primary/50" />
            </div>
            <div className="relative shrink-0" onClick={e => e.stopPropagation()}>
              <button onClick={() => setSortOpen(o => !o)}
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-cyber-border/40 text-[10px] font-mono text-slate-300 hover:text-white hover:border-cyber-primary/50 transition-colors">
                <ArrowDownWideNarrow className="w-3 h-3" />
                {(SORTS.find(x => x.key === sort) || SORTS[0]).label}
              </button>
              {sortOpen && (
                <div className="absolute right-0 top-full mt-1.5 w-[210px] rounded-lg border border-cyber-border/60 bg-cyber-panel shadow-2xl shadow-black/60 z-50 overflow-hidden">
                  <div className="px-3 py-2 border-b border-cyber-border/40 text-[9px] font-mono uppercase tracking-widest text-slate-500">
                    Sort intel by
                  </div>
                  {SORTS.map(o => (
                    <button key={o.key} onClick={() => { setSort(o.key); setSortOpen(false); }}
                      className={`w-full flex items-start gap-2 px-3 py-2 text-left hover:bg-slate-800/70 transition-colors ${
                        sort === o.key ? 'bg-cyber-primary/[0.08]' : ''}`}>
                      <Check className={`w-3 h-3 shrink-0 mt-0.5 ${sort === o.key ? 'text-cyber-primary opacity-100' : 'opacity-0'}`} />
                      <div className="min-w-0">
                        <div className={`text-[11px] ${sort === o.key ? 'text-cyber-primary' : 'text-slate-200'}`}>{o.label}</div>
                        <div className="text-[9px] font-mono text-slate-500 truncate">{o.hint}</div>
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </div>
            <div className="flex gap-1 flex-wrap">
              {FILTERS.map(f => (
                <button key={f.key} onClick={() => setFilter(f.key)}
                  className={`px-2.5 py-1 rounded text-[9px] font-mono font-bold uppercase tracking-wider border transition-colors ${
                    filter === f.key
                      ? 'bg-cyber-primary/15 border-cyber-primary/50 text-cyber-primary'
                      : 'border-cyber-border/40 text-slate-500 hover:text-slate-300'}`}>
                  {f.label}
                </button>
              ))}
            </div>
          </div>

          <div className="flex-1 overflow-y-auto custom-scrollbar divide-y divide-cyber-border/20">
            {loading && !data && (
              <div className="p-10 text-center font-mono text-xs text-slate-500 animate-pulse">
                Pulling GitHub Advisory DB, malware feed and CISA KEV…
              </div>
            )}
            {!loading && err && (
              <div className="p-10 text-center">
                <XCircle className="w-8 h-8 text-cyber-danger mx-auto mb-3" />
                <div className="font-mono text-xs text-cyber-danger mb-1">Could not load global intel</div>
                <div className="font-mono text-[11px] text-slate-500 max-w-md mx-auto leading-relaxed">{err}</div>
                <button onClick={() => load(true)}
                  className="mt-3 px-3 py-1.5 rounded-lg border border-cyber-border/50 text-[11px] font-mono text-slate-300 hover:text-white hover:border-cyber-primary/60">
                  Retry
                </button>
              </div>
            )}
            {!loading && !err && items.length === 0 && (
              <div className="p-10 text-center font-mono text-xs text-slate-500">
                {data && data.degraded
                  ? 'Feeds unreachable. Check network access, or disable offline mode in phishguard.config.json.'
                  : 'No intel items match this filter.'}
              </div>
            )}
            {items.map(item => {
              const k = KIND[item.kind] || KIND.advisory;
              const Icon = k.icon;
              const cause = causedBy(item);
              const isActive = active && active.id === item.id;
              return (
                <button key={item.id} onClick={() => setSelected(item)}
                  className={`w-full text-left p-3.5 hover:bg-slate-800/40 transition-colors ${
                    isActive ? 'bg-slate-800/60 border-l-2 border-l-cyber-primary' : 'border-l-2 border-l-transparent'} ${
                    item.affectsRepo ? 'bg-cyber-danger/[0.05]' : ''}`}>
                  <div className="flex items-center gap-1.5 mb-1.5 flex-wrap">
                    <span className={`flex items-center gap-1 px-1.5 py-0.5 rounded border font-mono text-[8px] font-bold ${k.cls}`}>
                      <Icon className="w-2.5 h-2.5" /> {k.label}
                    </span>
                    <span className={`px-1.5 py-0.5 rounded border font-mono text-[8px] font-bold uppercase ${SEV[item.severity] || SEV.low}`}>
                      {item.severity}
                    </span>
                    {item.ransomware && (
                      <span className="px-1.5 py-0.5 rounded bg-cyber-danger/20 text-cyber-danger font-mono text-[8px] font-bold">RANSOMWARE</span>
                    )}
                    {item.affectsRepo && (
                      <span className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-cyber-danger text-white font-mono text-[8px] font-bold">
                        <AlertOctagon className="w-2.5 h-2.5" /> IN YOUR TREE
                      </span>
                    )}
                    <span className="ml-auto font-mono text-[9px] text-slate-500 shrink-0">{ago(item.published)}</span>
                  </div>

                  <div className="text-xs font-medium text-slate-100 leading-snug mb-1.5 line-clamp-2">{item.title}</div>

                  <div className="flex items-center gap-3 flex-wrap">
                    <span className="flex items-center gap-1 font-mono text-[9px] text-slate-400">
                      {cause.kind === 'vendor' ? <Building2 className="w-3 h-3 text-slate-500" /> : <PackageX className="w-3 h-3 text-slate-500" />}
                      <span className="text-slate-300 font-bold">{cause.primary}</span>
                      {cause.all.length > 1 && <span className="text-slate-600">+{cause.all.length - 1}</span>}
                    </span>
                    <span className="font-mono text-[9px] text-slate-500">{item.identifier}</span>
                    <span className="font-mono text-[9px] text-slate-600">{item.source}</span>
                  </div>

                  {item.affectsRepo && item.repoMatch && (
                    <div className="mt-2 px-2 py-1.5 rounded bg-cyber-danger/10 border border-cyber-danger/30">
                      <span className="text-[9px] font-mono text-cyber-danger">{item.repoMatch.note}</span>
                    </div>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* detail */}
        <div className="w-[380px] glass-panel rounded-xl border border-cyber-border/40 flex flex-col shrink-0 overflow-hidden">
          {active ? (
            <>
              <div className="p-5 border-b border-cyber-border/30 shrink-0">
                <div className="flex items-center gap-1.5 mb-2 flex-wrap">
                  <span className={`px-1.5 py-0.5 rounded border font-mono text-[8px] font-bold ${(KIND[active.kind] || KIND.advisory).cls}`}>
                    {(KIND[active.kind] || KIND.advisory).label}
                  </span>
                  <span className={`px-1.5 py-0.5 rounded border font-mono text-[8px] font-bold uppercase ${SEV[active.severity] || SEV.low}`}>
                    {active.severity}
                  </span>
                  {active.cvss && <span className="font-mono text-[9px] text-slate-400">CVSS {active.cvss}</span>}
                </div>
                <h3 className="text-sm font-bold text-slate-100 leading-snug">{active.title}</h3>
                <div className="font-mono text-[10px] text-cyber-primary mt-1.5">{active.identifier}</div>
              </div>

              <div className="flex-1 overflow-y-auto custom-scrollbar p-5 space-y-4">
                <Section label="What caused it">
                  {active.packages && active.packages.length ? (
                    <div className="space-y-1.5">
                      {active.packages.slice(0, 8).map((p, i) => (
                        <div key={i} className="flex items-center gap-2 p-2 rounded bg-cyber-bg/60 border border-cyber-border/30">
                          <PackageX className="w-3 h-3 text-cyber-danger shrink-0" />
                          <span className="font-mono text-[10px] text-slate-200 truncate">{p.name}</span>
                          <span className="font-mono text-[9px] text-slate-500 ml-auto shrink-0">{p.vulnerableRange || 'all'}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="flex items-center gap-2 p-2 rounded bg-cyber-bg/60 border border-cyber-border/30">
                      <Building2 className="w-3 h-3 text-slate-400 shrink-0" />
                      <span className="font-mono text-[10px] text-slate-200">{causedBy(active).primary}</span>
                    </div>
                  )}
                </Section>

                {active.repoMatch && (
                  <Section label="Exposure in this repo" tone="danger">
                    <p className="text-[11px] leading-relaxed text-cyber-danger">{active.repoMatch.note}</p>
                    {(active.repoMatch.packages || []).map((p, i) => (
                      <div key={i} className="font-mono text-[9px] text-slate-400 mt-1">
                        {p.name}@{p.version} {p.direct ? '(direct)' : '(transitive)'} {p.inRange ? '— affected' : '— outside range'}
                      </div>
                    ))}
                  </Section>
                )}

                {active.description && (
                  <Section label="Details">
                    <p className="text-[11px] leading-relaxed text-slate-400 whitespace-pre-wrap">{active.description}</p>
                  </Section>
                )}

                <div className="grid grid-cols-2 gap-2">
                  <Meta icon={CalendarClock} label="Published" value={active.published ? new Date(active.published).toLocaleDateString() : '—'} />
                  <Meta icon={Radio} label="Source" value={active.source} />
                  {active.dueDate && <Meta icon={CalendarClock} label="KEV due date" value={active.dueDate} />}
                  {active.cwes && active.cwes.length > 0 && <Meta icon={Bug} label="CWE" value={active.cwes.join(', ')} />}
                </div>

                {active.references && active.references.length > 0 && (
                  <Section label="References">
                    <div className="space-y-1">
                      {active.references.slice(0, 5).map((r, i) => (
                        <a key={i} href={r} target="_blank" rel="noreferrer"
                          className="flex items-center gap-1.5 text-[10px] font-mono text-cyber-primary hover:underline truncate">
                          <Link2 className="w-3 h-3 shrink-0" /> <span className="truncate">{r}</span>
                        </a>
                      ))}
                    </div>
                  </Section>
                )}
              </div>

              <div className="p-4 border-t border-cyber-border/30 shrink-0 space-y-2">
                <a href={active.url} target="_blank" rel="noreferrer"
                  className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg bg-cyber-primary hover:bg-indigo-600 text-white font-sans text-xs font-bold transition-colors">
                  Open source page <ExternalLink className="w-3.5 h-3.5" />
                </a>
                {active.kevUrl && (
                  <a href={active.kevUrl} target="_blank" rel="noreferrer"
                    className="w-full flex items-center justify-center gap-2 py-2 rounded-lg border border-cyber-border/50 text-slate-300 hover:text-white hover:border-cyber-primary/50 font-mono text-[10px] transition-colors">
                    View CISA KEV catalog <ExternalLink className="w-3 h-3" />
                  </a>
                )}
              </div>
            </>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center text-center px-6">
              <Globe2 className="w-10 h-10 text-slate-700 mb-3" />
              <p className="font-mono text-xs text-slate-500 leading-relaxed">
                Select an intel item to see the package or vendor behind it, your exposure, and a link to the source.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value, icon: Icon, tone }) {
  const col = tone === 'danger' ? 'text-cyber-danger' : tone === 'warning' ? 'text-cyber-warning'
    : tone === 'success' ? 'text-cyber-success' : 'text-cyber-primary';
  return (
    <div className="p-3 rounded-lg bg-cyber-bg/50 border border-cyber-border/30">
      <div className="flex items-center gap-1.5 mb-1">
        <Icon className={`w-3 h-3 ${col}`} />
        <span className="text-[9px] font-mono uppercase tracking-wider text-slate-500 truncate">{label}</span>
      </div>
      <div className={`font-display font-bold text-xl ${col} tabular-nums`}>{value}</div>
    </div>
  );
}

function Section({ label, children, tone }) {
  return (
    <div>
      <div className={`text-[9px] font-mono uppercase tracking-widest mb-1.5 ${tone === 'danger' ? 'text-cyber-danger' : 'text-slate-500'}`}>{label}</div>
      {children}
    </div>
  );
}

function Meta({ icon: Icon, label, value }) {
  return (
    <div className="p-2 rounded bg-cyber-bg/50 border border-cyber-border/30">
      <div className="flex items-center gap-1 mb-0.5">
        <Icon className="w-2.5 h-2.5 text-slate-500" />
        <span className="text-[8px] font-mono uppercase tracking-wider text-slate-500">{label}</span>
      </div>
      <div className="font-mono text-[10px] text-slate-300 truncate" title={value}>{value}</div>
    </div>
  );
}
