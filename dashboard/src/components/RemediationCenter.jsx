import React, { useEffect, useMemo, useState } from 'react';
import {
  Wrench, ArrowRight, ShieldCheck, AlertTriangle, Loader2, Undo2, PackageCheck,
  ChevronLeft, Terminal, CircleSlash, Layers, Zap, History,
} from 'lucide-react';
import { usePhishGuard } from '../App';

/**
 * Remediation Center.
 *
 * The actionable half of PhishGuard: every advisory in the current scan that
 * has a published fix, ranked by how much risk the fix removes, with a
 * one-click apply that rewrites the project's real package.json (backed up,
 * and reversible from here).
 */

const SEV_DOT = { critical: '#f43f5e', high: '#fb923c', moderate: '#f59e0b', low: '#38bdf8' };

const STRATEGY = {
  upgrade:         { label: 'BUMP',     cls: 'bg-cyber-primary/15 text-cyber-primary border-cyber-primary/40', icon: ArrowRight },
  override:        { label: 'OVERRIDE', cls: 'bg-cyber-purple/15 text-cyber-purple border-cyber-purple/40',    icon: Layers },
  remove:          { label: 'REMOVE',   cls: 'bg-cyber-danger/15 text-cyber-danger border-cyber-danger/40',    icon: CircleSlash },
  'registry-only': { label: 'NO FIX',   cls: 'bg-slate-700/30 text-slate-400 border-slate-600/40',             icon: CircleSlash },
};

export default function RemediationCenter() {
  const pg = usePhishGuard();
  const nonce = pg ? pg.nonce : 0;
  const quarantineNonce = pg ? pg.quarantineNonce : 0;

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState(null);
  const [preview, setPreview] = useState(null);   // plan being reviewed
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [backups, setBackups] = useState([]);

  const load = () => {
    setLoading(true);
    fetch('/api/remediation/plan')
      .then(async r => {
        if (!r.ok) throw new Error(r.status === 404
          ? 'Hub is running an older build — restart `phishguard dashboard`.'
          : `HTTP ${r.status}`);
        return r.json();
      })
      .then(d => { setData(d); setErr(null); setLoading(false); })
      .catch(e => { setErr(e.message); setLoading(false); });
    fetch('/api/remediation/backups').then(r => r.json())
      .then(d => setBackups(d.backups || [])).catch(() => {});
  };

  useEffect(load, [nonce, quarantineNonce]);

  const items = useMemo(() => (data && data.items) || [], [data]);
  const stats = (data && data.stats) || {};

  const openPreview = (pkgName) => {
    setBusy(true);
    setResult(null);
    fetch('/api/remediation/preview', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: pkgName }),
    })
      .then(r => r.json())
      .then(p => { setPreview(p.error ? null : p); if (p.error) setErr(p.error); })
      .finally(() => setBusy(false));
  };

  const apply = () => {
    if (!preview) return;
    setBusy(true);
    fetch('/api/remediation/apply', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: preview.package }),
    })
      .then(r => r.json())
      .then(d => {
        setResult(d.error ? { error: d.error } : d);
        if (!d.error) load();
      })
      .finally(() => setBusy(false));
  };

  // Restore rewrites the whole manifest, so confirm when it would also revert
  // edits PhishGuard never made.
  const restore = () => {
    setBusy(true);
    fetch('/api/remediation/restore/preview')
      .then(r => r.json())
      .then(prev => {
        if (prev.error) throw new Error(prev.error);
        const collateral = prev.collateral || [];
        const msg = collateral.length
          ? `Restoring ${prev.backup} will also revert changes PhishGuard did not make:

  ${collateral.join(', ')}

Those edits will be lost. Continue?`
          : `Restore package.json from ${prev.backup}?`;
        if (!window.confirm(msg)) { setBusy(false); return null; }
        return fetch('/api/remediation/restore', {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
        }).then(r => r.json());
      })
      .then(d => {
        if (!d) return;
        setResult(d.error ? { error: d.error } : { restored: d });
        load();
      })
      .catch(e => setResult({ error: e.message }))
      .finally(() => setBusy(false));
  };

  const shell = (children) => (
    <div className="glass-panel rounded-xl border border-cyber-border/40 p-5 flex flex-col h-[400px] overflow-hidden">{children}</div>
  );

  /* --------------------------- preview / result --------------------------- */
  if (preview) {
    const st = STRATEGY[preview.strategy] || STRATEGY['registry-only'];
    return shell(
      <>
        <div className="flex items-center gap-2 mb-3 shrink-0">
          <button onClick={() => { setPreview(null); setResult(null); }}
            className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-100">
            <ChevronLeft className="w-4 h-4" />
          </button>
          <Wrench className="w-4 h-4 text-cyber-primary shrink-0" />
          <div className="min-w-0">
            <h3 className="font-sans font-bold text-sm text-slate-100 truncate">{preview.package}</h3>
            <span className="text-[10px] text-slate-400">
              {preview.installedVersion} · {preview.direct ? `direct (${preview.field})` : 'transitive'}
            </span>
          </div>
          <span className={`ml-auto px-1.5 py-0.5 rounded border font-mono text-[8px] font-bold ${st.cls}`}>{st.label}</span>
        </div>

        <div className="flex-1 overflow-y-auto custom-scrollbar space-y-3 min-h-0 pr-1">
          <div className="p-2.5 rounded-lg bg-cyber-bg/50 border border-cyber-border/30">
            <div className="text-[9px] font-mono uppercase tracking-widest text-slate-500 mb-1">Plan</div>
            <p className="text-[11px] text-slate-200 leading-relaxed">{preview.summary}</p>
          </div>

          {preview.changes.length > 0 && (
            <div>
              <div className="text-[9px] font-mono uppercase tracking-widest text-slate-500 mb-1.5">
                package.json diff
              </div>
              <div className="rounded-lg border border-cyber-border/30 bg-[#0d1117] p-2.5 font-mono text-[10px] space-y-0.5">
                {preview.changes.map((c, i) => (
                  <React.Fragment key={i}>
                    {c.from != null && (
                      <div className="text-cyber-danger">- "{c.pointer}": {JSON.stringify(c.from)}</div>
                    )}
                    {c.to != null && (
                      <div className="text-cyber-success">+ "{c.pointer}": {JSON.stringify(c.to)}</div>
                    )}
                    {c.to == null && c.op === 'delete' && (
                      <div className="text-slate-500">  (entry removed)</div>
                    )}
                  </React.Fragment>
                ))}
              </div>
            </div>
          )}

          {preview.warnings.map((w, i) => (
            <div key={i} className="flex items-start gap-1.5 p-2 rounded bg-cyber-warning/[0.06] border border-cyber-warning/25">
              <AlertTriangle className="w-3 h-3 text-cyber-warning shrink-0 mt-0.5" />
              <span className="text-[10px] text-cyber-warning leading-snug">{w}</span>
            </div>
          ))}

          {result && result.error && (
            <div className="p-2 rounded bg-cyber-danger/10 border border-cyber-danger/30 text-[10px] font-mono text-cyber-danger">
              {result.error}
            </div>
          )}
          {result && result.success && (
            <div className="p-2.5 rounded bg-cyber-success/[0.07] border border-cyber-success/30 space-y-1">
              <div className="flex items-center gap-1.5 text-cyber-success text-[11px] font-bold">
                <PackageCheck className="w-3.5 h-3.5" />
                {result.result.applied ? 'package.json updated' : 'Recorded in the quarantine registry'}
              </div>
              {result.result.backup && (
                <div className="text-[9px] font-mono text-slate-400">backup: {result.result.backup}</div>
              )}
              {result.result.needsInstall && (
                <div className="flex items-center gap-1.5 font-mono text-[10px] text-slate-200 bg-[#0d1117] rounded px-2 py-1 mt-1">
                  <Terminal className="w-3 h-3 text-cyber-primary" /> {result.result.needsInstall}
                </div>
              )}
            </div>
          )}
        </div>

        <div className="shrink-0 mt-3 pt-3 border-t border-cyber-border/30 flex items-center gap-2">
          {!result?.success ? (
            <>
              <button onClick={apply} disabled={busy}
                className={`flex-1 flex items-center justify-center gap-1.5 py-2 rounded-lg font-sans text-xs font-bold transition-colors disabled:opacity-50 ${
                  preview.editsManifest
                    ? 'bg-cyber-danger/15 border border-cyber-danger/50 text-cyber-danger hover:bg-cyber-danger hover:text-white'
                    : 'bg-cyber-primary/15 border border-cyber-primary/50 text-cyber-primary hover:bg-cyber-primary hover:text-white'}`}>
                {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
                {preview.editsManifest ? 'Apply to package.json' : 'Record quarantine'}
              </button>
              <button onClick={() => setPreview(null)}
                className="px-3 py-2 rounded-lg border border-cyber-border/50 text-slate-400 hover:text-slate-100 text-xs">
                Cancel
              </button>
            </>
          ) : (
            <button onClick={() => { setPreview(null); setResult(null); }}
              className="flex-1 py-2 rounded-lg border border-cyber-border/50 text-slate-300 hover:text-white text-xs font-bold">
              Done
            </button>
          )}
        </div>
      </>
    );
  }

  /* ------------------------------ list view ------------------------------- */
  if (loading && !data) {
    return shell(<><Head /><div className="flex-1 flex items-center justify-center gap-2 text-slate-500 font-mono text-[11px]"><Loader2 className="w-4 h-4 animate-spin" /> Building remediation plan…</div></>);
  }
  if (err) {
    return shell(<><Head /><div className="flex-1 flex flex-col items-center justify-center text-center px-6"><AlertTriangle className="w-6 h-6 text-cyber-warning mb-2" /><span className="font-mono text-[11px] text-slate-400">{err}</span></div></>);
  }

  return shell(
    <>
      <Head stats={stats} onRestore={backups.length ? restore : null} busy={busy} backups={backups.length} />

      <div className="grid grid-cols-3 gap-2 mb-3 shrink-0">
        <Metric label="Fixable now" value={stats.actionable || 0} tone="success" sub={`${stats.total || 0} affected`} />
        <Metric label="Advisories cleared" value={stats.advisoriesFixable || 0} tone="primary" sub={`of ${stats.advisoriesTotal || 0}`} />
        <Metric label="No fix yet" value={stats.blocked || 0} tone={stats.blocked ? 'warning' : 'success'} sub="upstream" />
      </div>

      <div className="flex-1 overflow-y-auto custom-scrollbar space-y-1 pr-1 min-h-0">
        {items.map(it => {
          const st = STRATEGY[it.strategy] || STRATEGY['registry-only'];
          return (
            <button key={it.package} onClick={() => it.actionable && openPreview(it.package)}
              disabled={!it.actionable}
              className={`w-full text-left p-2.5 rounded-lg border transition-colors ${
                it.actionable
                  ? 'border-cyber-border/30 bg-cyber-bg/40 hover:border-cyber-primary/50 hover:bg-cyber-bg/70'
                  : 'border-cyber-border/20 bg-cyber-bg/20 opacity-60 cursor-default'}`}>
              <div className="flex items-center gap-1.5 mb-1">
                <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: SEV_DOT[it.worstSeverity] || '#64748b' }} />
                <span className="font-mono text-[11px] font-bold text-slate-100 truncate">{it.package}</span>
                {it.direct && <span className="px-1 rounded bg-cyber-primary/15 text-cyber-primary font-mono text-[8px] font-bold shrink-0">DIRECT</span>}
                <span className={`ml-auto px-1.5 py-0.5 rounded border font-mono text-[8px] font-bold shrink-0 ${st.cls}`}>{st.label}</span>
              </div>
              <div className="flex items-center gap-1.5 font-mono text-[10px]">
                <span className="text-slate-500">{it.installedVersion}</span>
                {it.target && (
                  <>
                    <ArrowRight className="w-3 h-3 text-slate-600 shrink-0" />
                    <span className="text-cyber-success font-bold">{it.target}</span>
                  </>
                )}
                <span className="ml-auto text-slate-500 shrink-0">
                  {it.actionable ? `clears ${it.clears}/${it.advisories}` : `${it.advisories} advisor${it.advisories === 1 ? 'y' : 'ies'}, no fix`}
                </span>
              </div>
            </button>
          );
        })}
        {items.length === 0 && (
          <div className="h-full flex flex-col items-center justify-center text-center">
            <ShieldCheck className="w-8 h-8 text-cyber-success/50 mb-2" />
            <span className="font-mono text-[11px] text-slate-400">No package in this tree has a known advisory.</span>
          </div>
        )}
      </div>

      {result && (
        <div className="shrink-0 mt-2 pt-2 border-t border-cyber-border/30 text-[10px] font-mono">
          {result.error
            ? <span className="text-cyber-danger">{result.error}</span>
            : result.restored
              ? <span className="text-cyber-success">Restored from {result.restored.restoredFrom} — run npm install</span>
              : null}
        </div>
      )}
    </>
  );
}

function Head({ stats, onRestore, busy, backups }) {
  return (
    <div className="flex justify-between items-start gap-3 mb-3 shrink-0">
      <div className="flex items-center gap-2 min-w-0">
        <Wrench className="w-5 h-5 text-cyber-primary shrink-0" />
        <div className="min-w-0">
          <h3 className="font-sans font-bold text-sm tracking-wide text-slate-100">Remediation Center</h3>
          <span className="text-[10px] text-slate-400">
            {stats && stats.total != null
              ? 'Applies real fixes to this repo’s package.json'
              : 'Actionable fixes from the latest scan'}
          </span>
        </div>
      </div>
      {onRestore && (
        <button onClick={onRestore} disabled={busy} title={`${backups} backup(s) available`}
          className="flex items-center gap-1 px-2 py-1 rounded border border-cyber-border/40 text-[10px] font-mono text-slate-400 hover:text-slate-100 hover:border-cyber-primary/50 disabled:opacity-50 shrink-0">
          <Undo2 className="w-3 h-3" /> Restore
        </button>
      )}
    </div>
  );
}

function Metric({ label, value, sub, tone }) {
  const col = tone === 'danger' ? 'text-cyber-danger'
    : tone === 'warning' ? 'text-cyber-warning'
    : tone === 'success' ? 'text-cyber-success' : 'text-cyber-primary';
  return (
    <div className="p-2.5 rounded-lg bg-cyber-bg/50 border border-cyber-border/30">
      <div className="text-[8px] font-mono uppercase tracking-wider text-slate-500 truncate">{label}</div>
      <div className={`font-display font-bold text-xl leading-none mt-0.5 ${col} tabular-nums`}>{value}</div>
      <div className="text-[8px] font-mono text-slate-600 mt-0.5 truncate">{sub}</div>
    </div>
  );
}
