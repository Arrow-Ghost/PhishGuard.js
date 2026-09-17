import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Play, Pause, RotateCcw, SkipForward, Crosshair, FolderGit2, Package,
  Bug, Zap, ShieldCheck, Gauge,
} from 'lucide-react';

/**
 * Animated attack-tree simulation.
 *
 * Renders the real propagation path — your repo, down the actual dependency
 * route, into the vulnerable package, through the exploit, fanning out into
 * consequence branches, and terminating at PhishGuard's mitigation.
 *
 * The tree lights up one depth level at a time so you can watch the attack
 * advance and see exactly where it gets cut off.
 */

const KIND = {
  repo:       { color: '#818cf8', icon: FolderGit2,  ring: 22 },
  dependency: { color: '#38bdf8', icon: Package,     ring: 18 },
  sink:       { color: '#f43f5e', icon: Bug,         ring: 21 },
  exploit:    { color: '#f43f5e', icon: Zap,         ring: 22 },
  impact:     { color: '#fb923c', icon: Crosshair,   ring: 17 },
  mitigation: { color: '#10b981', icon: ShieldCheck, ring: 23 },
};

const SEV_COLOR = { critical: '#f43f5e', high: '#fb923c', moderate: '#f59e0b', low: '#38bdf8' };
const SPEEDS = [0.5, 1, 2];

export default function AttackTree({ tree, severity }) {
  const [step, setStep] = useState(0);
  const [playing, setPlaying] = useState(true);
  const [speed, setSpeed] = useState(1);
  const [hover, setHover] = useState(null);
  const timer = useRef(null);

  const maxDepth = tree ? tree.maxDepth : 0;

  // restart whenever the selected finding changes
  useEffect(() => {
    setStep(0);
    setPlaying(true);
  }, [tree]);

  useEffect(() => {
    clearTimeout(timer.current);
    if (!playing || step >= maxDepth) {
      if (step >= maxDepth) setPlaying(false);
      return;
    }
    timer.current = setTimeout(() => setStep(s => Math.min(maxDepth, s + 1)), 950 / speed);
    return () => clearTimeout(timer.current);
  }, [playing, step, maxDepth, speed]);

  /* ------------------------------- layout -------------------------------- */
  const layout = useMemo(() => {
    if (!tree || !tree.nodes.length) return null;
    const byDepth = new Map();
    for (const n of tree.nodes) {
      if (!byDepth.has(n.depth)) byDepth.set(n.depth, []);
      byDepth.get(n.depth).push(n);
    }
    const depths = [...byDepth.keys()].sort((a, b) => a - b);
    const colW = 156;
    const rowH = 62;
    const widest = Math.max(...depths.map(d => byDepth.get(d).length));
    const height = Math.max(168, widest * rowH + 52);
    const width = 70 + depths.length * colW;

    const pos = new Map();
    for (const d of depths) {
      const list = byDepth.get(d);
      list.forEach((n, i) => {
        pos.set(n.id, {
          x: 56 + d * colW,
          y: height / 2 + (i - (list.length - 1) / 2) * rowH,
        });
      });
    }

    const edges = [];
    for (const n of tree.nodes) {
      const parents = Array.isArray(n.parent) ? n.parent : n.parent ? [n.parent] : [];
      for (const p of parents) {
        if (!pos.has(p) || !pos.has(n.id)) continue;
        edges.push({ from: p, to: n.id, depth: n.depth, kind: n.kind });
      }
    }
    return { nodes: tree.nodes, pos, edges, width, height, depths };
  }, [tree]);

  if (!tree || !layout) return null;

  const reached = (n) => n.depth <= step;
  const edgeLive = (e) => e.depth <= step;
  const done = step >= maxDepth;

  const phaseLabel = (() => {
    const atStep = tree.nodes.filter(n => n.depth === step);
    if (!atStep.length) return '';
    const n = atStep[0];
    if (n.kind === 'repo') return 'Entry point';
    if (n.kind === 'dependency') return `Traversing dependency ${step} of ${tree.route.length}`;
    if (n.kind === 'sink') return 'Reached the vulnerable package';
    if (n.kind === 'exploit') return `Exploiting: ${tree.vector}`;
    if (n.kind === 'impact') return `${atStep.length} consequence branches`;
    if (n.kind === 'mitigation') return 'Blocked by PhishGuard';
    return '';
  })();

  return (
    <div className="rounded-lg border border-cyber-border/30 bg-cyber-bg/40 p-4">
      {/* header + transport */}
      <div className="flex items-center gap-2 mb-3 flex-wrap">
        <Crosshair className="w-3.5 h-3.5 text-cyber-primary shrink-0" />
        <span className="text-[10px] font-mono uppercase tracking-widest text-slate-400">Attack path simulation</span>

        <span className={`ml-1 px-1.5 py-0.5 rounded font-mono text-[9px] font-bold ${
          done ? 'bg-cyber-success/15 text-cyber-success' : 'bg-cyber-danger/15 text-cyber-danger'}`}>
          {done ? 'NEUTRALISED' : `STEP ${step}/${maxDepth}`}
        </span>
        {phaseLabel && <span className="text-[10px] text-slate-500 truncate">{phaseLabel}</span>}

        <div className="ml-auto flex items-center gap-1 shrink-0">
          <button onClick={() => { setStep(0); setPlaying(true); }} title="Replay"
            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-100 transition-colors">
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
          <button onClick={() => setPlaying(p => !p)} title={playing ? 'Pause' : 'Play'} disabled={done && !playing}
            className="p-1.5 rounded hover:bg-slate-800 text-slate-300 hover:text-white disabled:opacity-40 transition-colors">
            {playing ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
          </button>
          <button onClick={() => { setPlaying(false); setStep(s => Math.min(maxDepth, s + 1)); }} title="Step" disabled={done}
            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-100 disabled:opacity-40 transition-colors">
            <SkipForward className="w-3.5 h-3.5" />
          </button>
          <button onClick={() => setSpeed(s => SPEEDS[(SPEEDS.indexOf(s) + 1) % SPEEDS.length])} title="Playback speed"
            className="flex items-center gap-1 px-1.5 py-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-100 font-mono text-[10px] transition-colors">
            <Gauge className="w-3 h-3" />{speed}×
          </button>
        </div>
      </div>

      {/* progress rail */}
      <div className="h-0.5 rounded-full bg-cyber-border/40 mb-3 overflow-hidden">
        <div className="h-full rounded-full transition-all duration-500"
          style={{
            width: `${(step / Math.max(1, maxDepth)) * 100}%`,
            background: done ? '#10b981' : (SEV_COLOR[severity] || '#f43f5e'),
          }} />
      </div>

      <div className="overflow-x-auto custom-scrollbar">
        <svg width={layout.width} height={layout.height} className="block">
          <defs>
            <marker id="at-arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
              <path d="M0,0 L6,3 L0,6 Z" fill="#475569" />
            </marker>
          </defs>

          {/* edges */}
          {layout.edges.map((e, i) => {
            const a = layout.pos.get(e.from);
            const b = layout.pos.get(e.to);
            const live = edgeLive(e);
            const mid = (a.x + b.x) / 2;
            const d = `M ${a.x + 20} ${a.y} C ${mid} ${a.y}, ${mid} ${b.y}, ${b.x - 20} ${b.y}`;
            const col = e.kind === 'mitigation' ? '#10b981' : live ? (SEV_COLOR[severity] || '#f43f5e') : '#334155';
            return (
              <g key={i}>
                <path d={d} fill="none" stroke={live ? col : '#1e293b'} strokeWidth={live ? 2 : 1.2}
                  strokeDasharray={live ? 'none' : '3 4'} opacity={live ? 0.85 : 0.5}
                  style={{ transition: 'stroke 500ms, stroke-width 500ms, opacity 500ms' }}
                  markerEnd={live ? undefined : 'url(#at-arrow)'} />
                {live && e.depth === step && (
                  <circle r="3.5" fill={col}>
                    <animateMotion path={d} dur="1.1s" repeatCount="3" />
                  </circle>
                )}
              </g>
            );
          })}

          {/* nodes */}
          {layout.nodes.map(n => {
            const p = layout.pos.get(n.id);
            const k = KIND[n.kind] || KIND.dependency;
            const on = reached(n);
            const isNow = n.depth === step;
            const col = n.kind === 'mitigation' ? '#10b981'
              : n.kind === 'sink' || n.kind === 'exploit' ? (SEV_COLOR[severity] || k.color)
              : k.color;
            const r = k.ring;
            return (
              <g key={n.id}
                onMouseEnter={() => setHover(n)} onMouseLeave={() => setHover(null)}
                style={{ cursor: 'pointer' }}>
                {/* the pulse marks the step currently advancing - it stops once
                    the simulation reaches the mitigation node */}
                {on && isNow && !done && (
                  <circle cx={p.x} cy={p.y} r={r + 6} fill="none" stroke={col} strokeWidth="1.5" opacity="0.5">
                    <animate attributeName="r" values={`${r};${r + 12};${r}`} dur="1.4s" repeatCount="indefinite" />
                    <animate attributeName="opacity" values="0.6;0;0.6" dur="1.4s" repeatCount="indefinite" />
                  </circle>
                )}
                <circle cx={p.x} cy={p.y} r={r}
                  fill={on ? `${col}1f` : '#0d1117'}
                  stroke={on ? col : '#334155'}
                  strokeWidth={on ? 2.2 : 1.2}
                  style={{
                    transition: 'all 500ms',
                    filter: on ? `drop-shadow(0 0 8px ${col}66)` : 'none',
                  }} />
                <foreignObject x={p.x - 10} y={p.y - 10} width="20" height="20" style={{ pointerEvents: 'none' }}>
                  <div className="w-5 h-5 flex items-center justify-center">
                    <k.icon width={13} height={13} style={{ color: on ? col : '#475569', transition: 'color 500ms' }} />
                  </div>
                </foreignObject>

                {/* label */}
                <text x={p.x} y={p.y + r + 13} textAnchor="middle"
                  style={{
                    fontSize: 10, fontWeight: 700, fontFamily: 'ui-monospace, monospace',
                    fill: on ? '#e2e8f0' : '#475569', transition: 'fill 500ms',
                    paintOrder: 'stroke', stroke: '#0a0e17', strokeWidth: 3, strokeLinejoin: 'round',
                  }}>
                  {String(n.label).length > 20 ? String(n.label).slice(0, 18) + '…' : n.label}
                </text>
                {n.version && (
                  <text x={p.x} y={p.y + r + 24} textAnchor="middle"
                    style={{ fontSize: 8, fontFamily: 'ui-monospace, monospace', fill: on ? '#64748b' : '#334155' }}>
                    v{n.version}
                  </text>
                )}
              </g>
            );
          })}
        </svg>
      </div>

      {/* detail strip */}
      <div className="mt-2 pt-2 border-t border-cyber-border/30 min-h-[30px]">
        {hover ? (
          <div className="flex items-start gap-2">
            <span className="px-1.5 py-0.5 rounded font-mono text-[8px] uppercase tracking-wider shrink-0 mt-0.5"
              style={{
                color: (KIND[hover.kind] || KIND.dependency).color,
                background: `${(KIND[hover.kind] || KIND.dependency).color}18`,
              }}>
              {hover.phase}
            </span>
            <div className="min-w-0">
              <div className="text-[11px] font-bold text-slate-200">{hover.label}</div>
              <div className="text-[10px] text-slate-400 leading-snug">{hover.detail}</div>
            </div>
          </div>
        ) : (
          <div className="text-[10px] text-slate-500 font-mono">
            {tree.route.length > 1
              ? `Route: ${tree.route.join(' → ')} · hover any node for detail`
              : 'Direct dependency · hover any node for detail'}
          </div>
        )}
      </div>
    </div>
  );
}
