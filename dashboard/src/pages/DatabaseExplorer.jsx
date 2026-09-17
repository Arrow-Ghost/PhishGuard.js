import React, { useState, useEffect, useCallback } from 'react';
import { Database, Table, Cpu, RefreshCw, Play, TerminalSquare, Search } from 'lucide-react';

export default function DatabaseExplorer() {
  const [stats, setStats] = useState(null);
  const [activeTab, setActiveTab] = useState(null);
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [sql, setSql] = useState('SELECT package_name, severity, identifier, title\nFROM scan_findings\nORDER BY CASE severity WHEN \'critical\' THEN 4 WHEN \'high\' THEN 3 WHEN \'moderate\' THEN 2 ELSE 1 END DESC\nLIMIT 50;');
  const [queryOut, setQueryOut] = useState(null);
  const [queryErr, setQueryErr] = useState('');

  const loadStats = useCallback(async () => {
    setLoading(true);
    try {
      const s = await (await fetch('/api/db-stats')).json();
      setStats(s);
      if (!activeTab && s.tables?.length) setActiveTab(s.tables.find(t => t.rows > 0)?.name || s.tables[0].name);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, [activeTab]);

  const loadTable = useCallback(async (name) => {
    if (!name) return;
    setLoading(true);
    try {
      const d = await (await fetch(`/api/db/table/${name}`)).json();
      setRows(Array.isArray(d) ? d : []);
    } catch { setRows([]); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { loadStats(); }, []);
  useEffect(() => { loadTable(activeTab); }, [activeTab, loadTable]);

  const runQuery = async () => {
    setQueryErr(''); setQueryOut(null);
    try {
      const res = await fetch('/api/db/query', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sql }),
      });
      const d = await res.json();
      if (!res.ok) throw new Error(d.error || 'query failed');
      setQueryOut(d);
    } catch (e) { setQueryErr(e.message); }
  };

  const filtered = search
    ? rows.filter(r => Object.values(r).some(v => String(v ?? '').toLowerCase().includes(search.toLowerCase())))
    : rows;
  const cols = rows.length ? Object.keys(rows[0]) : [];

  return (
    <div className="h-full flex flex-col gap-5 overflow-y-auto pr-1">
      <div className="bg-cyber-panel border border-cyber-border/40 rounded-xl p-5 flex flex-wrap items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-blue-500/10 text-cyan-400 rounded-xl border border-cyan-500/20"><Database className="w-7 h-7" /></div>
          <div>
            <h2 className="text-lg font-bold text-slate-100 tracking-wide">Relational Database Core</h2>
            <p className="text-xs font-mono text-slate-400 mt-1 flex flex-wrap items-center gap-x-4 gap-y-1">
              <span>{stats?.engine || 'SQLite'}</span><span>•</span>
              <span>journal: <strong className="text-emerald-400">{stats?.journalMode || '—'}</strong></span><span>•</span>
              <span className="truncate max-w-[380px]" title={stats?.dbFile}>{stats?.dbFile || ''}</span>
            </p>
          </div>
        </div>
        <button onClick={() => { loadStats(); loadTable(activeTab); }} disabled={loading}
          className="flex items-center gap-2 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 text-xs font-mono">
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Sync
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MiniStat label="Engine" value={stats?.engine?.split('(')[0] || 'SQLite'} icon={Cpu} />
        <MiniStat label="Total rows" value={stats ? stats.totalRecords : '—'} icon={Table} />
        <MiniStat label="Tables" value={stats ? stats.tables.length : '—'} icon={Database} />
        <MiniStat label="Journal" value={stats?.journalMode || '—'} icon={Cpu} />
      </div>

      {/* SQL console */}
      <div className="bg-cyber-panel border border-cyber-border/40 rounded-xl p-4">
        <div className="flex items-center gap-2 mb-2 text-slate-300 text-xs font-mono">
          <TerminalSquare className="w-4 h-4 text-cyan-400" /> Read-only SQL console
          <span className="text-slate-500">(SELECT / WITH / PRAGMA / EXPLAIN)</span>
        </div>
        <textarea value={sql} onChange={e => setSql(e.target.value)} rows={4}
          className="w-full bg-slate-950 border border-slate-700 text-slate-200 rounded-lg p-3 font-mono text-xs outline-none focus:border-cyan-500" />
        <div className="flex items-center gap-3 mt-2">
          <button onClick={runQuery} className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-mono font-bold">
            <Play className="w-3 h-3 fill-white" /> Run
          </button>
          {queryOut && <span className="text-[11px] font-mono text-slate-400">{queryOut.rowCount} rows · {queryOut.latencyMs}ms</span>}
          {queryErr && <span className="text-[11px] font-mono text-cyber-danger">{queryErr}</span>}
        </div>
        {queryOut && queryOut.rows.length > 0 && (
          <div className="mt-3 overflow-x-auto border border-slate-800 rounded-lg bg-slate-950 max-h-64">
            <table className="w-full text-left font-mono text-[11px]">
              <thead><tr className="border-b border-slate-800 text-slate-400 bg-slate-900/80">
                {queryOut.columns.map(cn => <th key={cn} className="py-2 px-3 uppercase tracking-wider">{cn}</th>)}
              </tr></thead>
              <tbody className="divide-y divide-slate-800/40 text-slate-300">
                {queryOut.rows.map((r, i) => (
                  <tr key={i}>{queryOut.columns.map(cn => <td key={cn} className="py-1.5 px-3 max-w-xs truncate">{String(r[cn] ?? '')}</td>)}</tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* table browser */}
      <div className="bg-cyber-panel border border-cyber-border/40 rounded-xl flex-1 flex flex-col min-h-[420px] overflow-hidden">
        <div className="border-b border-cyber-border/40 px-5 py-3 flex flex-wrap justify-between items-center gap-3 bg-slate-900/60">
          <div className="flex items-center gap-2 overflow-x-auto">
            {stats?.tables.map(t => (
              <button key={t.name} onClick={() => setActiveTab(t.name)}
                className={`px-3.5 py-1.5 rounded-lg text-xs font-mono flex items-center gap-2 whitespace-nowrap ${activeTab === t.name ? 'bg-cyan-600 text-white border border-cyan-400/30' : 'bg-slate-800/60 text-slate-400 hover:text-slate-200'}`}>
                <Table className="w-3.5 h-3.5" /> {t.name}
                <span className="px-1.5 rounded bg-black/50 text-[10px] text-cyan-300">{t.rows}</span>
              </button>
            ))}
          </div>
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Filter rows…"
              className="pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-700 text-slate-200 rounded-lg text-xs font-mono outline-none focus:border-cyan-500 w-56" />
          </div>
        </div>
        <div className="p-5 flex-1 overflow-auto">
          <div className="overflow-x-auto border border-slate-800 rounded-lg bg-slate-950">
            {filtered.length ? (
              <table className="w-full text-left font-mono text-xs">
                <thead><tr className="border-b border-slate-800 text-slate-300 bg-slate-900/80">
                  {cols.map(cn => <th key={cn} className="py-2.5 px-3 uppercase tracking-wider border-r border-slate-800/40">{cn}</th>)}
                </tr></thead>
                <tbody className="divide-y divide-slate-800/40 text-slate-300">
                  {filtered.map((r, i) => (
                    <tr key={i} className="hover:bg-slate-900/40">
                      {cols.map(cn => {
                        const v = r[cn];
                        return (
                          <td key={cn} className="py-2.5 px-3 border-r border-slate-800/20 max-w-xs truncate">
                            {cn === 'status' ? <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${v === 'BLOCKED' ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'}`}>{v}</span>
                              : cn === 'severity' ? <span className={`capitalize font-semibold ${v === 'critical' ? 'text-red-400' : v === 'high' ? 'text-orange-400' : v === 'moderate' || v === 'warning' ? 'text-amber-400' : 'text-slate-400'}`}>{v}</span>
                              : cn === 'id' ? <span className="text-cyan-400">{v}</span>
                              : String(v ?? '')}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="py-12 text-center text-slate-500 font-mono text-xs">{loading ? 'Querying…' : `No rows in ${activeTab || 'table'}.`}</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function MiniStat({ label, value, icon: Icon }) {
  return (
    <div className="bg-cyber-panel border border-cyber-border/40 rounded-xl p-4">
      <div className="flex justify-between items-center text-slate-400 text-xs font-mono">
        <span className="uppercase tracking-wider">{label}</span><Icon className="w-4 h-4 text-cyan-400" />
      </div>
      <p className="text-base font-bold text-slate-100 font-mono mt-1.5 truncate">{value}</p>
    </div>
  );
}
