import React, { useEffect, useState } from 'react';
import {
  PackageSearch, ShieldCheck, CheckCircle, FileCode, Flame, AlertTriangle,
  Play, RotateCcw, Sparkles, GitBranch, ExternalLink,
} from 'lucide-react';
import TrustClassification from '../components/TrustClassification';
import DependencyEvolutionTimeline from '../components/DependencyEvolutionTimeline';
import { usePhishGuard } from '../App';

const badge = (cat) => cat === 'critical'
  ? 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/30'
  : cat === 'warning'
  ? 'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/30'
  : 'text-cyber-success bg-cyber-success/10 border-cyber-success/30';

export default function SupplyChain() {
  const { runScan, scanning, scanProgress, nonce } = usePhishGuard();
  const [report, setReport] = useState(null);
  const [mode, setMode] = useState('repo'); // 'repo' | 'paste'
  const [pasteInput, setPasteInput] = useState('');
  const [pasteResult, setPasteResult] = useState(null);
  const [pasteBusy, setPasteBusy] = useState(false);
  const [error, setError] = useState('');
  const [showAll, setShowAll] = useState(false);

  useEffect(() => {
    fetch('/api/scan/latest').then(r => r.json()).then(d => setReport(d && !d.error ? d : null)).catch(() => {});
  }, [nonce]);

  const rescan = async () => {
    setError('');
    const r = await runScan();
    if (r && r.error) setError(r.error);
    else setReport(r);
  };

  const runPaste = async () => {
    setPasteBusy(true); setError(''); setPasteResult(null);
    try {
      const res = await fetch('/api/scan', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ packageJson: pasteInput }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'scan failed');
      setPasteResult(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setPasteBusy(false);
    }
  };

  const active = mode === 'repo' ? report : null;
  const risky = active ? active.packages.filter(p => p.category !== 'safe') : [];
  const shownRisky = showAll ? risky : risky.slice(0, 30);

  return (
    <div className="flex flex-col gap-6 h-[calc(100vh-6rem)] overflow-y-auto pr-2">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 min-h-[460px]">
        {/* left: control */}
        <div className="glass-panel rounded-xl border border-cyber-border/40 p-5 flex flex-col">
          <div className="flex justify-between items-start mb-4 select-none">
            <div className="flex items-center gap-2.5">
              <div className="p-2 bg-cyber-primary/10 rounded-lg text-cyber-primary"><FileCode className="w-4.5 h-4.5" /></div>
              <div>
                <h2 className="font-sans font-bold text-base text-slate-100">Supply-Chain Scanner</h2>
                <p className="text-[11px] text-slate-400">OSV.dev advisories · real semver matching · npm deprecations · typosquat heuristics</p>
              </div>
            </div>
            <div className="flex bg-cyber-bg/50 border border-cyber-border/40 rounded p-1">
              {['repo', 'paste'].map(m => (
                <button key={m} onClick={() => setMode(m)}
                  className={`px-3 py-1 text-[9px] font-mono font-bold tracking-widest rounded uppercase ${mode === m ? 'bg-slate-700 text-white' : 'text-slate-400'}`}>
                  {m === 'repo' ? 'This repo' : 'Paste'}
                </button>
              ))}
            </div>
          </div>

          {mode === 'repo' ? (
            <div className="flex-1 flex flex-col">
              <p className="text-xs text-slate-300 leading-relaxed mb-4">
                Scans the resolved dependency tree of the repository this dashboard is watching
                {report ? <> (<span className="font-mono text-slate-200">{report.project.name}</span>, {report.lockfile.source})</> : ''}.
              </p>
              <button onClick={rescan} disabled={scanning}
                className="px-4 py-2 rounded bg-cyber-primary hover:bg-indigo-700 text-white font-sans text-xs font-bold transition-all flex items-center gap-1.5 self-start disabled:opacity-50">
                <Play className="w-3 h-3 fill-white" />
                {scanning ? (scanProgress ? `${scanProgress.phase}… ${scanProgress.done || ''}${scanProgress.total ? '/' + scanProgress.total : ''}` : 'Scanning…') : 'Scan repository now'}
              </button>

              {report && (
                <div className="mt-6 grid grid-cols-2 gap-3 font-mono text-xs">
                  <Stat label="Packages" value={report.counts.total} />
                  <Stat label="Direct" value={report.counts.direct} />
                  <Stat label="Vulnerable" value={report.counts.vulnerable} tone={report.counts.vulnerable ? 'danger' : 'ok'} />
                  <Stat label="Critical + High" value={report.counts.critical + report.counts.high} tone={(report.counts.critical + report.counts.high) ? 'danger' : 'ok'} />
                  <Stat label="Deprecated" value={report.counts.deprecated} tone={report.counts.deprecated ? 'warn' : 'ok'} />
                  <Stat label="Typosquat" value={report.counts.typosquat} tone={report.counts.typosquat ? 'danger' : 'ok'} />
                  <Stat label="Install scripts" value={report.counts.lifecycleScripts} tone={report.counts.lifecycleScripts ? 'warn' : 'ok'} />
                </div>
              )}
            </div>
          ) : (
            <div className="flex-1 flex flex-col">
              <div className="flex justify-end gap-2 mb-2">
                <button onClick={() => { setPasteInput(''); setPasteResult(null); }} className="p-1.5 rounded border border-cyber-border/40 text-slate-400 hover:text-slate-100"><RotateCcw className="w-3.5 h-3.5" /></button>
                <button onClick={runPaste} disabled={pasteBusy || !pasteInput.trim()}
                  className="px-4 py-1.5 rounded bg-cyber-primary hover:bg-indigo-700 text-white text-xs font-bold flex items-center gap-1.5 disabled:opacity-50">
                  <Play className="w-3 h-3 fill-white" />{pasteBusy ? 'Auditing…' : 'Audit manifest'}
                </button>
              </div>
              <textarea value={pasteInput} onChange={e => setPasteInput(e.target.value)}
                placeholder='{ "dependencies": { "lodash": "4.17.15" } }'
                className="flex-1 bg-[#22252B] text-slate-200 p-4 rounded-lg border border-cyber-border/30 outline-none resize-none font-mono text-xs" />
            </div>
          )}
        </div>

        {/* right: results */}
        <div className="glass-panel rounded-xl border border-cyber-border/40 p-5 flex flex-col min-h-[460px]">
          {error ? (
            <div className="flex-1 flex flex-col items-center justify-center text-cyber-danger p-6 text-center">
              <AlertTriangle className="w-12 h-12 mb-3" />
              <span className="font-mono text-sm uppercase font-bold">Scan error</span>
              <span className="text-[10px] font-mono mt-2 max-w-sm">{error}</span>
            </div>
          ) : mode === 'repo' && scanning && !active ? (
            <Spinner label={scanProgress ? `${scanProgress.phase}…` : 'Resolving dependencies…'} />
          ) : mode === 'repo' && active ? (
            <RepoResult report={active} risky={risky} shownRisky={shownRisky} showAll={showAll} setShowAll={setShowAll} />
          ) : mode === 'paste' && pasteBusy ? (
            <Spinner label="Querying OSV.dev…" />
          ) : mode === 'paste' && pasteResult ? (
            <PasteResult data={pasteResult} />
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center text-cyber-muted p-6 text-center select-none">
              <PackageSearch className="w-12 h-12 text-cyber-muted/30 mb-3" />
              <span className="font-mono text-sm uppercase font-bold">Awaiting scan</span>
            </div>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 min-h-[350px]">
        <TrustClassification />
        <DependencyEvolutionTimeline />
      </div>
    </div>
  );
}

function Stat({ label, value, tone }) {
  const col = tone === 'danger' ? 'text-cyber-danger' : tone === 'warn' ? 'text-cyber-warning' : tone === 'ok' ? 'text-cyber-success' : 'text-slate-200';
  return (
    <div className="p-3 rounded bg-cyber-bg/50 border border-cyber-border/20">
      <div className="text-[9px] text-slate-500 uppercase tracking-widest">{label}</div>
      <div className={`text-lg font-black ${col}`}>{value}</div>
    </div>
  );
}

function Spinner({ label }) {
  return (
    <div className="flex-1 flex flex-col items-center justify-center text-cyber-muted space-y-3">
      <Sparkles className="w-10 h-10 text-cyber-primary animate-spin" />
      <span className="font-mono text-[11px] uppercase tracking-widest text-cyber-primary">{label}</span>
    </div>
  );
}

function FindingRow({ f }) {
  return (
    <div className="text-[10px] font-mono p-2 bg-cyber-panel/60 border border-cyber-border/30 rounded text-slate-300 flex gap-2 items-start">
      {f.severity === 'critical' ? <Flame className="w-3.5 h-3.5 text-cyber-danger shrink-0 mt-0.5" />
        : <AlertTriangle className="w-3.5 h-3.5 text-cyber-warning shrink-0 mt-0.5" />}
      <div className="min-w-0">
        <span className="font-bold text-slate-100 block">
          {f.identifier ? <span className="text-cyber-primary">{f.identifier} </span> : null}{f.title}
        </span>
        <span className="text-cyber-muted mt-0.5 block leading-relaxed break-words">{f.description}</span>
        {f.fixedVersion && <span className="text-cyber-success block mt-0.5">→ fixed in {f.fixedVersion}</span>}
        {f.url && <a href={f.url} target="_blank" rel="noreferrer" className="text-cyber-primary inline-flex items-center gap-1 mt-0.5">ref <ExternalLink className="w-2.5 h-2.5" /></a>}
      </div>
    </div>
  );
}

function RepoResult({ report, risky, shownRisky, showAll, setShowAll }) {
  const scoreCol = report.score >= 80 ? 'text-cyber-success' : report.score >= 55 ? 'text-cyber-warning' : 'text-cyber-danger';
  return (
    <div className="flex-1 overflow-y-auto space-y-5 pr-1">
      <div className="flex justify-between items-center bg-cyber-bg/40 p-4 rounded-lg border border-cyber-border/30 select-none">
        <div>
          <span className="text-[10px] font-mono text-cyber-muted uppercase">Posture</span>
          <span className={`text-2xl font-display font-black block mt-1 ${scoreCol}`}>{report.score}/100</span>
          <span className="text-[9px] font-mono text-cyber-muted uppercase mt-0.5">
            grade {report.grade} · <span className="font-bold text-slate-100">{report.status}</span>
            {report.offline && <span className="text-cyber-warning"> · offline data</span>}
          </span>
        </div>
        <div className="flex gap-3 font-mono text-center">
          <Pill n={report.counts.critical + report.counts.malicious} l="Critical" c="danger" />
          <Pill n={report.counts.high} l="High" c="warn" />
          <Pill n={report.counts.moderate + report.counts.deprecated} l="Mod." c="warn" />
          <Pill n={report.counts.total} l="Scanned" c="primary" />
        </div>
      </div>

      <div className="space-y-3.5">
        <h3 className="font-display font-bold text-xs tracking-wider text-slate-200 uppercase">
          Risk vectors ({risky.length})
        </h3>
        {risky.length === 0 && (
          <div className="text-[11px] font-mono text-cyber-success flex items-center gap-2"><CheckCircle className="w-4 h-4" /> No advisories, deprecations or typosquats.</div>
        )}
        {shownRisky.map((p, i) => (
          <div key={i} className="p-3.5 rounded-lg bg-cyber-bg/50 border border-cyber-border/20 space-y-2">
            <div className="flex justify-between items-start">
              <div className="min-w-0">
                <span className="font-mono text-xs font-black text-slate-100">{p.name}</span>
                <span className="font-mono text-[10px] text-cyber-muted ml-2">{p.version || p.range}</span>
                <span className="font-mono text-[9px] text-slate-500 ml-2">{p.direct ? 'direct' : `depth ${p.depth}`}{p.dev ? ' · dev' : ''}</span>
              </div>
              <span className={`px-2 py-0.5 rounded border text-[9px] font-bold uppercase ${badge(p.category)}`}>{p.category} · {p.riskScore}</span>
            </div>
            <div className="space-y-1.5">{p.findings.map((f, j) => <FindingRow key={j} f={f} />)}</div>
          </div>
        ))}
        {risky.length > shownRisky.length && (
          <button onClick={() => setShowAll(true)} className="text-[10px] font-mono text-cyber-primary">show {risky.length - shownRisky.length} more…</button>
        )}
      </div>
    </div>
  );
}

function PasteResult({ data }) {
  return (
    <div className="flex-1 overflow-y-auto space-y-4 pr-1">
      <div className="flex gap-3 font-mono text-center">
        <Pill n={data.criticalCount} l="Critical" c="danger" />
        <Pill n={data.warningCount} l="Warnings" c="warn" />
        <Pill n={data.scannedCount} l="Scanned" c="primary" />
        <Pill n={data.score} l="Avg risk" c="warn" />
      </div>
      {data.dependencies.map((d, i) => (
        <div key={i} className="p-3.5 rounded-lg bg-cyber-bg/50 border border-cyber-border/20 space-y-2">
          <div className="flex justify-between">
            <span className="font-mono text-xs font-black text-slate-100">{d.name} <span className="text-cyber-muted font-normal">{d.version}</span></span>
            <span className={`px-2 py-0.5 rounded border text-[9px] font-bold uppercase ${badge(d.category)}`}>{d.category} · {d.riskScore}</span>
          </div>
          {d.findings.length
            ? d.findings.map((f, j) => <FindingRow key={j} f={{ ...f, severity: f.severity || 'moderate' }} />)
            : <div className="text-[10px] font-mono text-cyber-success/80 flex items-center gap-1.5"><CheckCircle className="w-3.5 h-3.5" /> No findings.</div>}
        </div>
      ))}
    </div>
  );
}

function Pill({ n, l, c }) {
  const cls = c === 'danger' ? 'bg-cyber-danger/10 border-cyber-danger/25 text-cyber-danger'
    : c === 'warn' ? 'bg-cyber-warning/10 border-cyber-warning/25 text-cyber-warning'
    : 'bg-cyber-primary/10 border-cyber-primary/25 text-cyber-primary';
  return (
    <div className={`px-3 py-1.5 rounded border ${cls}`}>
      <div className="font-black text-sm">{n}</div>
      <div className="text-[8px] uppercase tracking-wider font-bold">{l}</div>
    </div>
  );
}
