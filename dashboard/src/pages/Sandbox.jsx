import React, { useEffect, useMemo, useState, useRef } from 'react';
import {
  Terminal as TermIcon, ShieldAlert, Code, Network, Database, Flame, PackageX,
  Crosshair, Target, Layers, ExternalLink, Wrench, CircleSlash, Search, Zap,
  ChevronRight, Activity, Eye, Bug, Server,
} from 'lucide-react';
import { usePhishGuard } from '../App';
import AttackTree from '../components/AttackTree';

const SEV = {
  critical: { chip: 'bg-cyber-danger/15 text-cyber-danger border-cyber-danger/40', dot: '#FF453A', ring: 'border-cyber-danger/40 hover:border-cyber-danger' },
  high:     { chip: 'bg-orange-500/15 text-orange-400 border-orange-500/40',       dot: '#FF9F0A', ring: 'border-orange-500/40 hover:border-orange-500' },
  moderate: { chip: 'bg-cyber-warning/15 text-cyber-warning border-cyber-warning/40', dot: '#FF9F0A', ring: 'border-cyber-warning/40 hover:border-cyber-warning' },
  low:      { chip: 'bg-sky-500/15 text-sky-400 border-sky-500/40',                dot: '#0A84FF', ring: 'border-sky-500/40 hover:border-sky-500' },
  warning:  { chip: 'bg-cyber-warning/15 text-cyber-warning border-cyber-warning/40', dot: '#FF9F0A', ring: 'border-cyber-warning/40 hover:border-cyber-warning' },
};

const KIND_ICON = { vulnerability: Bug, malicious: PackageX, typosquat: Target, deprecated: Layers, 'lifecycle-script': Wrench };

const CIA = {
  high:   { label: 'HIGH',   cls: 'text-cyber-danger',  w: '100%', color: '#FF453A' },
  medium: { label: 'MEDIUM', cls: 'text-cyber-warning', w: '60%',  color: '#FF9F0A' },
  low:    { label: 'LOW',    cls: 'text-sky-400',       w: '30%',  color: '#0A84FF' },
  none:   { label: 'NONE',   cls: 'text-slate-600',     w: '4%',   color: '#8E8E93' },
};

const PHASE_COLOR = {
  delivery: '#0A84FF', reconnaissance: '#0A84FF', execution: '#FF9F0A',
  exploitation: '#FF453A', collection: '#FF9F0A', exfiltration: '#FF453A',
  impact: '#FF453A', mitigation: '#30D158',
};

export default function Sandbox() {
  const pg = usePhishGuard();
  const nonce = pg ? pg.nonce : 0;
  const [data, setData] = useState(null);
  const [selected, setSelected] = useState(null);
  const [q, setQ] = useState('');
  const [sevFilter, setSevFilter] = useState('all');
  const [lines, setLines] = useState(() => [
    { id: 'boot-1', phase: 'SYSTEM', text: 'Runtime agent online — fetch / XMLHttpRequest / sendBeacon / DOM hooks installed.' },
    { id: 'boot-2', phase: 'SYSTEM', text: 'Streaming enforcement events from every connected agent over the hub WebSocket.' },
  ]);
  const termRef = useRef(null);
  const seenLogIds = useRef(new Set());
  const traceTimer = useRef(null);          // in-flight console playback
  const [streaming, setStreaming] = useState(false);
  const seededRef = useRef(false);
  const lineSeq = useRef(0);

  const [err, setErr] = useState(null);

  useEffect(() => {
    setErr(null);
    fetch('/api/sandbox/scenarios')
      .then(async r => {
        if (!r.ok) {
          throw new Error(r.status === 404
            ? 'The hub does not expose /api/sandbox/scenarios. It is running an older build — restart `phishguard dashboard`.'
            : `Hub returned HTTP ${r.status}`);
        }
        const ct = r.headers.get('content-type') || '';
        if (!ct.includes('json')) throw new Error('Hub returned a non-JSON response.');
        return r.json();
      })
      .then(d => {
        // Deliberately no auto-select: nothing simulates until the user clicks
        // an alert, so loading the page never starts a playback on its own.
        setData(d);
      })
      .catch(e => setErr(e.message || String(e)));
  }, [nonce]);

  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
  }, [lines]);

  // Policy evaluation is a substring scan - it genuinely lands under a
  // microsecond, so print a floor rather than a misleading "0ms".
  const fmtLatency = (ms) => {
    if (!Number.isFinite(ms)) return '—';
    if (ms < 0.001) return '<0.001ms';
    if (ms < 1) return `${ms.toFixed(3)}ms`;
    return `${ms.toFixed(2)}ms`;
  };

  const pushLines = (entries) => {
    const stamped = entries.map(e => ({
      ...e,
      id: `l-${Date.now()}-${lineSeq.current++}`,
      t: e.t || new Date(),
    }));
    setLines(prev => [...prev.slice(-400), ...stamped]);
  };

  /**
   * Turn one real telemetry event into the enforcement sequence the agent
   * actually performed. Every line below corresponds to a step that genuinely
   * happened: policy evaluation, the enforcement call, stack capture, the
   * SQLite write, and the fan-out to connected dashboards.
   */
  const enforcementChain = (log) => {
    const blocked = log.status === 'BLOCKED';
    const flagged = log.status === 'FLAGGED';
    const target = log.callerUrl && log.callerUrl !== 'unknown' ? log.callerUrl : (log.details || '');
    const t = new Date(log.timestamp);
    const out = [];

    out.push({ phase: 'DETECT', tone: 'detect', t,
      text: `${log.action} — ${String(target).slice(0, 96)}` });

    out.push({ phase: 'POLICY', tone: 'policy', t,
      text: log.rule
        ? `matched ${log.rule}`
        : blocked ? 'matched an active deny rule' : 'evaluated against the active policy set — no deny rule matched' });

    if (blocked) {
      out.push({ phase: 'ENFORCE', tone: 'block', t,
        text: `${log.enforcement || 'request denied at the hook before it could execute'}${
          log.latencyMs != null ? `  [decision ${fmtLatency(log.latencyMs)}]` : ''}` });
    } else if (flagged) {
      out.push({ phase: 'FLAG', tone: 'flag', t,
        text: log.enforcement || 'permitted, recorded for review' });
    } else {
      out.push({ phase: 'ALLOW', tone: 'allow', t, text: 'permitted — no policy violation' });
    }

    out.push({ phase: 'CAPTURE', tone: 'meta', t,
      text: `origin ${log.sourcePackage}${log.stackFrames ? ` · ${log.stackFrames} stack frames recorded` : ''}` });

    out.push({ phase: 'PERSIST', tone: 'meta', t,
      text: `security_logs ← ${log.id} (sqlite, WAL)` });

    out.push({ phase: blocked ? 'CONTAINED' : 'LOGGED', tone: blocked ? 'contained' : 'meta', t,
      text: blocked
        ? 'threat neutralised — payload never left the browser; NEW_LOG broadcast to connected dashboards'
        : 'NEW_LOG broadcast to connected dashboards' });

    return out;
  };

  /**
   * A CLI trace for one specific scanned finding: how that exact attack would
   * run, and what PhishGuard's automated response to it is. Everything is
   * derived from that finding's own advisory, CWE, dependency route and
   * impact model - two different alerts never produce the same trace.
   */
  const attackTrace = (sc) => {
    const im = sc.impact || {};
    const route = (sc.tree && sc.tree.route) || [sc.package];
    const chain = (im.chain || []).filter(n => n.phase !== 'mitigation');
    const out = [];
    const L = (phase, tone, text) => out.push({ phase, tone, text });

    L('$', 'attack', `phishguard simulate --scenario ${sc.id} --package ${sc.package}@${sc.version}`);
    L('', 'meta', `advisory   ${sc.identifier || sc.kind}   severity=${sc.severity}${sc.cwes && sc.cwes.length ? `   ${sc.cwes.join(' ')}` : ''}`);
    L('', 'meta', `vector     ${im.vector || sc.kind}`);
    L('', 'meta', `reach      ${route.join(' -> ')}   (${sc.direct ? 'direct dependency' : `transitive, depth ${sc.depth ?? '?'}`})`);
    if (im.knownExploited) L('', 'escaped', 'flag       listed on CISA KEV - exploitation confirmed in the wild');

    // --- how the attack actually runs, step by step for THIS finding ---
    chain.forEach((n, i) => {
      L('atk', 'attack', `${i + 1}/${chain.length}  ${n.label}: ${n.detail}`);
    });
    (im.systemEffects || []).slice(0, 3).forEach(e => L('atk', 'escaped', `       -> ${e}`));
    L('atk', 'escaped',
      `       cia  confidentiality=${im.confidentiality} integrity=${im.integrity} availability=${im.availability}  likelihood=${im.likelihood}`);

    // --- what PhishGuard does about it, automatically ---
    L('pg', 'detect', `DETECT     ${sc.package}@${sc.version} matched ${sc.identifier || 'a known advisory'} during the dependency scan`);
    L('pg', 'policy', `ASSESS     ${im.blastRadius || 'reachability assessed from the dependency graph'}`);

    if (sc.fixedVersion && sc.direct) {
      L('pg', 'policy', `STRATEGY   direct dependency with a published fix -> raise the range in package.json`);
      L('pg', 'block', `REMEDY     ${sc.field || 'dependencies'}.${sc.package}: "^${sc.fixedVersion}"`);
      L('pg', 'contained', `ACTION     apply from the Remediation Center, or run:`);
      L('pg', 'meta', `           npm pkg set dependencies.${sc.package}="^${sc.fixedVersion}" && npm install`);
    } else if (sc.fixedVersion && !sc.direct) {
      L('pg', 'policy', `STRATEGY   transitive package - it cannot be uninstalled, so pin it with an npm override`);
      L('pg', 'block', `REMEDY     overrides.${sc.package}: "^${sc.fixedVersion}"`);
      L('pg', 'contained', `ACTION     apply from the Remediation Center, or run:`);
      L('pg', 'meta', `           npm pkg set overrides.${sc.package}="^${sc.fixedVersion}" && npm install`);
    } else {
      L('pg', 'policy', `STRATEGY   no fixed version published upstream - no safe manifest edit exists`);
      L('pg', 'flag', `REMEDY     ${im.remediation || 'constrain input at the call site or replace the package'}`);
      L('pg', 'flag', `ACTION     recorded in the quarantine registry; re-flagged on every future scan`);
    }

    // runtime control - honest about what the agent can and cannot stop
    if (im.surface === 'browser') {
      L('pg', 'contained', `RUNTIME    the browser agent also guards this class live: DOM injection and outbound`);
      L('pg', 'meta', `           exfiltration from this package are blocked at the hook.`);
    } else {
      L('pg', 'flag', `RUNTIME    server-side vector - the browser agent cannot intercept this. The manifest`);
      L('pg', 'meta', `           fix is the control; runtime telemetry only covers browser-scope behaviour.`);
    }

    L('pg', 'contained', `VERIFY     next scan confirms ${sc.identifier || 'this advisory'} no longer matches${
      sc.fixedVersion ? ` once ${sc.package} >= ${sc.fixedVersion}` : ''}`);
    return out;
  };

  /**
   * Play a trace into the console one line at a time, so you watch the attack
   * and the response unfold instead of getting a wall of text. This only ever
   * runs from an explicit click - loading the page starts nothing.
   */
  const stopTrace = () => {
    if (traceTimer.current) { clearTimeout(traceTimer.current); traceTimer.current = null; }
    setStreaming(false);
  };

  const playTrace = (entries, { stepMs = 280 } = {}) => {
    stopTrace();
    setStreaming(true);
    let i = 0;
    const tick = () => {
      if (i >= entries.length) { traceTimer.current = null; setStreaming(false); return; }
      const line = entries[i++];
      pushLines([line]);
      // attack steps linger a little longer than the response lines
      const delay = line.phase === 'atk' ? stepMs * 1.3 : stepMs;
      traceTimer.current = setTimeout(tick, delay);
    };
    tick();
  };

  // never leave a playback running when the page unmounts
  useEffect(() => () => {
    if (traceTimer.current) clearTimeout(traceTimer.current);
  }, []);

  // Every agent event that reaches the hub shows up here, whether it was fired
  // from this page or from the host application the agent is installed in.
  useEffect(() => {
    const logs = (pg && pg.logs) || [];
    if (!logs.length) return;

    if (!seededRef.current) {
      seededRef.current = true;
      for (const l of logs) seenLogIds.current.add(l.id);
      const recent = logs.slice(0, 3).reverse();
      if (recent.length) {
        pushLines([
          { phase: 'SYSTEM', tone: 'meta',
            text: `Replaying the ${recent.length} most recent enforcement event(s) from this repo's history.` },
          ...recent.flatMap(enforcementChain),
        ]);
      }
      return;
    }

    const fresh = logs.filter(l => !seenLogIds.current.has(l.id));
    if (!fresh.length) return;
    for (const l of fresh) seenLogIds.current.add(l.id);
    pushLines(fresh.slice().reverse().flatMap(enforcementChain));
  }, [pg && pg.logs]);

  const contained = lines.filter(l => l.phase === 'CONTAINED').length;

  const scenarios = useMemo(() => {
    let list = (data && data.scenarios) || [];
    if (sevFilter !== 'all') list = list.filter(s => s.severity === sevFilter);
    if (q.trim()) {
      const t = q.toLowerCase();
      list = list.filter(s => `${s.package} ${s.title} ${s.identifier || ''} ${s.impact.vector}`.toLowerCase().includes(t));
    }
    return list;
  }, [data, sevFilter, q]);

  /* ----------------------- live hook-verification demos ---------------------- */
  // These fire a real attack against the live runtime. The agent's own hooks
  // decide the outcome and report it to the hub; the console below then prints
  // the enforcement chain that actually ran - nothing here fakes the verdict.
  const runDemo = (demo) => {
    setSelected(null);
    playTrace([
      { phase: '$', tone: 'attack', text: `phishguard simulate --hook ${demo.kind} --target ${demo.target}` },
      { phase: 'ATTACK', tone: 'attack', text: demo.blurb || `simulating: ${demo.label}` },
      { phase: 'FIRE', tone: 'attack', text: `dispatching against the live runtime…` },
    ], { stepMs: 320 });

    if (demo.kind === 'network') {
      fetch(demo.target, { method: 'POST', body: JSON.stringify({ sandbox: true }) })
        .then(() => pushLines([{ phase: 'ESCAPED', tone: 'escaped',
          text: 'request completed — this destination is not on the active deny policy' }]))
        .catch(() => { /* the agent rejected it; the enforcement chain arrives over the WebSocket */ });
    } else if (demo.kind === 'dom') {
      try {
        const el = document.createElement('script');
        el.src = demo.target;
        document.body.appendChild(el);
        // If appendChild did not throw, the MutationObserver path handles it and
        // the hub reports the outcome. No guess is printed here.
      } catch { /* appendChild guard threw - the agent already reported it */ }
    } else if (demo.kind === 'storage') {
      try {
        window.localStorage.setItem('pg_cached_tz', '{"tz":"America/New_York"}');
        pushLines([{ phase: 'OBSERVE', tone: 'flag',
          text: 'localStorage write executed — storage access is recorded, not blocked by default policy' }]);
      } catch (e) {
        pushLines([{ phase: 'ERROR', tone: 'escaped', text: e.message }]);
      }
    } else if (demo.kind.startsWith('node-')) {
      // The Node runtime agent lives in a server process, not this page - fire
      // the demo in a disposable, dependency-attributed Node child process on
      // the hub side. The real enforcement chain (or lack of one) arrives over
      // the WebSocket the same way any other agent telemetry does.
      const vector = demo.kind.slice('node-'.length);
      fetch('/api/sandbox/node-demo', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ vector }),
      })
        .then(res => res.json())
        .then(() => pushLines([{ phase: 'DISPATCHED', tone: 'attack',
          text: 'fired in a sandboxed Node process attributed to a dependency — enforcement chain arrives over the WebSocket' }]))
        .catch(e => pushLines([{ phase: 'ERROR', tone: 'escaped', text: e.message }]));
    }
  };

  const counts = (data && data.counts) || {};

  return (
    <div className="flex flex-col h-full gap-4 overflow-hidden">
      {/* ------------------------------- header ------------------------------- */}
      <div className="glass-panel rounded-xl border border-cyber-border/40 p-4 shrink-0">
        <div className="flex justify-between items-start gap-4 flex-wrap mb-3">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg text-cyber-primary bg-cyber-primary/10 border border-cyber-primary/20">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h2 className="font-sans font-bold text-base text-slate-100">Shield Sandbox</h2>
              <p className="text-[11px] text-slate-400">
                Every alert and warning found in <span className="text-cyber-primary font-mono">{(data && data.project) || 'this repo'}</span>.
                Select one to model how the attack would play out.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {[['critical', counts.critical], ['high', counts.high], ['moderate', counts.moderate], ['low', counts.low]].map(([k, n]) => (
              n ? <button key={k} onClick={() => setSevFilter(sevFilter === k ? 'all' : k)}
                className={`px-2 py-0.5 rounded border font-mono text-[9px] font-bold uppercase transition-all ${SEV[k].chip} ${sevFilter === k ? 'ring-1 ring-white/30' : 'opacity-70 hover:opacity-100'}`}>
                {n} {k}
              </button> : null
            ))}
            {counts.knownExploited > 0 && (
              <span className="flex items-center gap-1 px-2 py-0.5 rounded bg-cyber-danger text-white font-mono text-[9px] font-bold">
                <Flame className="w-2.5 h-2.5" /> {counts.knownExploited} EXPLOITED
              </span>
            )}
          </div>
        </div>

        {/* scenario strip */}
        <div className="flex items-center gap-2 mb-2">
          <div className="relative flex-1 max-w-xs">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input value={q} onChange={e => setQ(e.target.value)} placeholder="Filter alerts…"
              className="w-full bg-cyber-bg/60 border border-cyber-border/40 rounded-lg pl-8 pr-3 py-1.5 text-[11px] font-mono text-slate-200 outline-none focus:border-cyber-primary/50" />
          </div>
          {sevFilter !== 'all' && (
            <button onClick={() => setSevFilter('all')} className="text-[10px] font-mono text-slate-400 hover:text-slate-200">clear filter</button>
          )}
          <span className="ml-auto text-[10px] font-mono text-slate-500">{scenarios.length} shown</span>
        </div>

        <div className="flex gap-2.5 overflow-x-auto pb-2 custom-scrollbar">
          {scenarios.map(s => {
            const sev = SEV[s.severity] || SEV.low;
            const Icon = KIND_ICON[s.kind] || Bug;
            const active = selected && selected.id === s.id;
            return (
              <button key={s.id}
                onClick={() => { setSelected(s); playTrace(attackTrace(s)); }}
                className={`shrink-0 w-[210px] text-left p-3 rounded-lg border bg-cyber-bg/40 transition-all ${
                  active ? 'border-cyber-primary bg-cyber-primary/[0.07] ring-1 ring-cyber-primary/30' : sev.ring}`}>
                <div className="flex items-center gap-1.5 mb-1.5">
                  <Icon className="w-3.5 h-3.5 shrink-0" style={{ color: sev.dot }} />
                  <span className="font-mono text-[11px] font-bold text-slate-100 truncate">{s.package}</span>
                  {s.impact.knownExploited && <Flame className="w-3 h-3 text-cyber-danger shrink-0 ml-auto" />}
                </div>
                <div className="text-[10px] text-slate-400 leading-snug line-clamp-2 mb-1.5">{s.impact.vector}</div>
                <div className="flex items-center gap-1.5">
                  <span className={`px-1.5 py-0.5 rounded border font-mono text-[8px] font-bold uppercase ${sev.chip}`}>{s.severity}</span>
                  {s.direct && <span className="px-1 py-0.5 rounded bg-cyber-primary/15 text-cyber-primary font-mono text-[8px] font-bold">DIRECT</span>}
                </div>
              </button>
            );
          })}

          {scenarios.length === 0 && (
            <div className="w-full py-5 text-center font-mono text-[11px]">
              {err ? (
                <span className="text-cyber-danger">
                  Could not load alerts — {err}
                </span>
              ) : data ? (
                <span className="text-slate-500">No alerts match this filter — your tree is clean here.</span>
              ) : (
                <span className="text-slate-500">Loading scan findings…</span>
              )}
            </div>
          )}
        </div>

        {/* live hook demos */}
        <div className="flex items-center gap-2 pt-3 mt-1 border-t border-cyber-border/30 flex-wrap">
          <span className="flex items-center gap-1.5 text-[9px] font-mono uppercase tracking-widest text-slate-500 shrink-0">
            <Zap className="w-3 h-3" /> Live hook tests
          </span>
          {(data && data.demos || []).map(d => (
            <button key={d.id} onClick={() => runDemo(d)} title={d.blurb}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md border font-mono text-[10px] transition-all ${
                d.severity === 'critical'
                  ? 'border-cyber-danger/40 text-cyber-danger hover:bg-cyber-danger/10'
                  : 'border-cyber-warning/40 text-cyber-warning hover:bg-cyber-warning/10'}`}>
              {d.kind === 'network' ? <Network className="w-3 h-3" />
                : d.kind === 'dom' ? <Code className="w-3 h-3" />
                : d.kind === 'node-network' ? <Server className="w-3 h-3" />
                : d.kind === 'node-process' ? <TermIcon className="w-3 h-3" />
                : d.kind === 'node-fs' ? <Database className="w-3 h-3" />
                : <Database className="w-3 h-3" />}
              {d.label}
            </button>
          ))}
        </div>
      </div>

      {/* ------------------------------- body -------------------------------- */}
      <div className="flex-1 flex gap-4 min-h-0">
        {selected ? (
          <>
            {/* impact analysis */}
            <div className="flex-1 glass-panel rounded-xl border border-cyber-border/40 flex flex-col min-w-0 overflow-hidden">
              <ImpactHeader s={selected} />
              <div className="flex-1 overflow-y-auto custom-scrollbar p-4 space-y-3">
                {selected.tree
                  ? <AttackTree tree={selected.tree} severity={selected.severity} />
                  : <KillChain chain={selected.impact.chain} />}

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                  <Panel icon={Crosshair} title="Attacker objective">
                    <p className="text-[11px] leading-relaxed text-slate-300">{selected.impact.attackerGoal}</p>
                    <div className="flex items-center gap-2 mt-2.5 flex-wrap">
                      <Tag label="Vector" value={selected.impact.vector} />
                      <Tag label="Surface" value={selected.impact.surface} />
                      <Tag label="Likelihood" value={selected.impact.likelihood}
                        tone={/wild|likely/i.test(selected.impact.likelihood) ? 'danger' : 'muted'} />
                    </div>
                  </Panel>

                  <Panel icon={Target} title="Impact on the system">
                    <div className="space-y-2">
                      {[['Confidentiality', selected.impact.confidentiality],
                        ['Integrity', selected.impact.integrity],
                        ['Availability', selected.impact.availability]].map(([label, v]) => {
                        const c = CIA[v] || CIA.none;
                        return (
                          <div key={label}>
                            <div className="flex justify-between items-center mb-0.5">
                              <span className="text-[10px] text-slate-400">{label}</span>
                              <span className={`font-mono text-[9px] font-bold ${c.cls}`}>{c.label}</span>
                            </div>
                            <div className="h-1.5 rounded-full bg-cyber-bg border border-cyber-border/30 overflow-hidden">
                              <div className="h-full rounded-full transition-all duration-700"
                                style={{ width: c.w, background: c.color, boxShadow: `0 0 6px ${c.color}55` }} />
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </Panel>
                </div>

                <Panel icon={Activity} title="What actually happens">
                  <ul className="space-y-1.5">
                    {selected.impact.systemEffects.map((e, i) => (
                      <li key={i} className="flex items-start gap-2 text-[11px] text-slate-300 leading-relaxed">
                        <ChevronRight className="w-3 h-3 text-cyber-danger shrink-0 mt-0.5" />{e}
                      </li>
                    ))}
                  </ul>
                </Panel>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                  <Panel icon={Layers} title="Blast radius">
                    <p className="text-[11px] leading-relaxed text-slate-300">{selected.impact.blastRadius}</p>
                  </Panel>
                  <Panel icon={Eye} title="Exploit preconditions">
                    <ul className="space-y-1">
                      {selected.impact.exploitConditions.map((c, i) => (
                        <li key={i} className="flex items-start gap-1.5 text-[10px] text-slate-400 leading-relaxed">
                          <span className="w-1 h-1 rounded-full bg-slate-600 mt-1.5 shrink-0" />{c}
                        </li>
                      ))}
                    </ul>
                  </Panel>
                </div>

                <Panel icon={Wrench} title="Remediation" tone="success">
                  <p className="text-[11px] leading-relaxed text-cyber-success">{selected.impact.remediation}</p>
                  {selected.url && (
                    <a href={selected.url} target="_blank" rel="noreferrer"
                      className="inline-flex items-center gap-1 mt-2 text-[10px] font-mono text-cyber-primary hover:underline">
                      Read the advisory <ExternalLink className="w-3 h-3" />
                    </a>
                  )}
                </Panel>

                {selected.description && (
                  <Panel icon={Bug} title="Advisory text">
                    <p className="text-[10px] leading-relaxed text-slate-400 whitespace-pre-wrap max-h-40 overflow-y-auto custom-scrollbar">
                      {selected.description}
                    </p>
                  </Panel>
                )}
              </div>
            </div>

            {/* console */}
            <Console lines={lines} termRef={termRef} contained={contained} onClear={() => setLines([])} />
          </>
        ) : (
          <>
            <div className="flex-1 glass-panel rounded-xl border border-cyber-border/40 flex flex-col items-center justify-center text-center px-8">
              <Crosshair className="w-10 h-10 text-slate-700 mb-3" />
              <p className="font-mono text-xs text-slate-500 leading-relaxed max-w-sm">
                Select an alert above to model the attack path, the CIA impact and the blast radius —
                or fire a live hook test to verify the runtime agent.
              </p>
            </div>
            <Console lines={lines} termRef={termRef} contained={contained} onClear={() => setLines([])} />
          </>
        )}
      </div>
    </div>
  );
}

/* ------------------------------- sub-views -------------------------------- */

function ImpactHeader({ s }) {
  const sev = SEV[s.severity] || SEV.low;
  const Icon = KIND_ICON[s.kind] || Bug;
  return (
    <div className="p-4 border-b border-cyber-border/30 shrink-0 bg-cyber-panel/40">
      <div className="flex items-start gap-3">
        <div className="p-2 rounded-lg shrink-0" style={{ background: `${sev.dot}1a`, border: `1px solid ${sev.dot}55` }}>
          <Icon className="w-4 h-4" style={{ color: sev.dot }} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5 mb-1 flex-wrap">
            <span className={`px-1.5 py-0.5 rounded border font-mono text-[8px] font-bold uppercase ${sev.chip}`}>{s.severity}</span>
            <span className="font-mono text-[10px] text-cyber-primary">{s.identifier || s.kind}</span>
            {s.impact.knownExploited && (
              <span className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-cyber-danger text-white font-mono text-[8px] font-bold">
                <Flame className="w-2.5 h-2.5" /> EXPLOITED IN WILD
              </span>
            )}
            {s.direct
              ? <span className="px-1.5 py-0.5 rounded bg-cyber-primary/15 text-cyber-primary font-mono text-[8px] font-bold">DIRECT DEP</span>
              : <span className="px-1.5 py-0.5 rounded bg-slate-700/40 text-slate-400 font-mono text-[8px] font-bold">TRANSITIVE</span>}
          </div>
          <h3 className="text-sm font-bold text-slate-100 leading-snug">{s.title}</h3>
          <div className="flex items-center gap-2 mt-1 flex-wrap">
            <span className="font-mono text-[10px] text-slate-400">{s.package}<span className="text-slate-600">@{s.version}</span></span>
            {s.fixedVersion
              ? <span className="flex items-center gap-1 font-mono text-[10px] text-cyber-success"><Wrench className="w-3 h-3" /> fix {s.fixedVersion}</span>
              : <span className="flex items-center gap-1 font-mono text-[10px] text-slate-500"><CircleSlash className="w-3 h-3" /> no fix</span>}
            {(s.cwes || []).slice(0, 3).map(c => (
              <span key={c} className="font-mono text-[8px] px-1 py-0.5 rounded bg-slate-700/40 text-slate-400">{c}</span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function KillChain({ chain }) {
  return (
    <div className="rounded-lg border border-cyber-border/30 bg-cyber-bg/40 p-4">
      <div className="flex items-center gap-1.5 mb-4">
        <Crosshair className="w-3.5 h-3.5 text-cyber-primary" />
        <span className="text-[10px] font-mono uppercase tracking-widest text-slate-400">Attack path</span>
      </div>
      <div className="flex items-stretch gap-0 overflow-x-auto custom-scrollbar pb-1">
        {chain.map((node, i) => {
          const col = PHASE_COLOR[node.phase] || '#8E8E93';
          const last = i === chain.length - 1;
          return (
            <React.Fragment key={node.id}>
              <div className="flex flex-col items-center shrink-0" style={{ width: 132 }}>
                <div className="w-9 h-9 rounded-full flex items-center justify-center border-2 mb-2"
                  style={{ borderColor: col, background: `${col}18`, boxShadow: `0 0 12px ${col}33` }}>
                  <span className="font-mono text-[11px] font-bold" style={{ color: col }}>{i + 1}</span>
                </div>
                <div className="text-[10px] font-bold text-slate-200 text-center leading-tight mb-0.5">{node.label}</div>
                <div className="text-[9px] text-slate-500 text-center leading-snug px-1">{node.detail}</div>
                <div className="mt-1.5 font-mono text-[7px] uppercase tracking-wider px-1.5 py-0.5 rounded"
                  style={{ color: col, background: `${col}14` }}>{node.phase}</div>
              </div>
              {!last && (
                <div className="flex items-start pt-4 shrink-0" style={{ width: 22 }}>
                  <div className="h-0.5 w-full rounded"
                    style={{ background: `linear-gradient(90deg, ${col}, ${PHASE_COLOR[chain[i + 1].phase] || '#8E8E93'})` }} />
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}

function Panel({ icon: Icon, title, children, tone }) {
  return (
    <div className={`rounded-lg border p-3 ${tone === 'success' ? 'border-cyber-success/25 bg-cyber-success/[0.04]' : 'border-cyber-border/30 bg-cyber-bg/40'}`}>
      <div className="flex items-center gap-1.5 mb-2">
        <Icon className={`w-3.5 h-3.5 ${tone === 'success' ? 'text-cyber-success' : 'text-cyber-primary'}`} />
        <span className="text-[10px] font-mono uppercase tracking-widest text-slate-400">{title}</span>
      </div>
      {children}
    </div>
  );
}

function Tag({ label, value, tone }) {
  return (
    <span className={`px-2 py-0.5 rounded border font-mono text-[9px] ${
      tone === 'danger' ? 'border-cyber-danger/40 bg-cyber-danger/10 text-cyber-danger' : 'border-cyber-border/40 bg-cyber-bg/60 text-slate-300'}`}>
      <span className="text-slate-500">{label}:</span> {value}
    </span>
  );
}

const TONE = {
  attack:    { label: 'text-fuchsia-400', bar: '#BF5AF2' },
  detect:    { label: 'text-sky-400',     bar: '#0A84FF' },
  policy:    { label: 'text-indigo-400',  bar: '#0A84FF' },
  block:     { label: 'text-cyber-danger', bar: '#FF453A' },
  flag:      { label: 'text-cyber-warning', bar: '#FF9F0A' },
  allow:     { label: 'text-slate-400',   bar: '#8E8E93' },
  contained: { label: 'text-cyber-success', bar: '#30D158' },
  escaped:   { label: 'text-cyber-danger', bar: '#FF453A' },
  meta:      { label: 'text-slate-500',   bar: '#636366' },
};

function Console({ lines, termRef, onClear, contained }) {
  const time = (t) => {
    const d = t instanceof Date ? t : new Date(t || Date.now());
    return Number.isFinite(d.getTime())
      ? d.toLocaleTimeString([], { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0')
      : '--:--:--';
  };
  return (
    <div className="w-[400px] glass-panel rounded-xl border border-cyber-border/40 p-4 flex flex-col shrink-0 min-h-0">
      <div className="flex items-center gap-2 mb-3 shrink-0">
        <TermIcon className="w-4 h-4 text-slate-400" />
        <div className="min-w-0">
          <h3 className="font-sans font-bold text-xs text-slate-100">Enforcement Console</h3>
          <span className="text-[10px] text-slate-400 block">What PhishGuard did, step by step</span>
        </div>
        {contained > 0 && (
          <span className="ml-auto px-1.5 py-0.5 rounded bg-cyber-success/15 border border-cyber-success/40 text-cyber-success font-mono text-[9px] font-bold shrink-0">
            {contained} CONTAINED
          </span>
        )}
        <button onClick={onClear}
          className="text-[9px] font-mono border border-slate-700 hover:border-slate-500 px-2 py-0.5 rounded text-slate-400 hover:text-slate-200 uppercase font-bold shrink-0">
          Clear
        </button>
      </div>

      <div ref={termRef}
        className="flex-1 cli-terminal p-3 rounded-lg overflow-y-auto font-mono text-[10px] leading-relaxed custom-scrollbar min-h-0 space-y-0.5">
        {lines.map((l) => {
          const tone = TONE[l.tone] || TONE.meta;
          return (
            <div key={l.id} className="flex gap-2 items-start">
              <span className="text-slate-700 shrink-0 tabular-nums">{time(l.t)}</span>
              <span className={`shrink-0 font-bold w-[68px] ${tone.label}`}>{l.phase}</span>
              <span className="w-0.5 shrink-0 self-stretch rounded" style={{ background: tone.bar, opacity: 0.5 }} />
              <span className="text-slate-300 break-all min-w-0">{l.text}</span>
            </div>
          );
        })}
        {lines.length === 0 && (
          <div className="text-slate-600 py-4 text-center">Console cleared — fire a hook test or wait for agent traffic.</div>
        )}
      </div>

      <div className="shrink-0 mt-2 pt-2 border-t border-cyber-border/30 text-[9px] font-mono text-slate-500 leading-relaxed">
        Live for every agent connected to this hub — including the one installed in your app.
      </div>
    </div>
  );
}
