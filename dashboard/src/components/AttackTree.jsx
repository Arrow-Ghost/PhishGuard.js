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
  repo:       { color: '#0A84FF', icon: FolderGit2,  ring: 26 },
  dependency: { color: '#0A84FF', icon: Package,     ring: 24 },
  sink:       { color: '#FF453A', icon: Bug,         ring: 26 },
  exploit:    { color: '#FF453A', icon: Zap,         ring: 26 },
  impact:     { color: '#FF9F0A', icon: Crosshair,   ring: 22 },
  mitigation: { color: '#30D158', icon: ShieldCheck, ring: 28 },
};

const SEV_COLOR = { critical: '#FF453A', high: '#FF9F0A', moderate: '#FF9F0A', low: '#0A84FF' };
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
    const colW = 150;
    const rowH = 84;
    const widest = Math.max(...depths.map(d => byDepth.get(d).length));
    const height = Math.max(210, widest * rowH + 84);
    const width = 100 + depths.length * colW + 60;

    const pos = new Map();
    for (const d of depths) {
      const list = byDepth.get(d);
      list.forEach((n, i) => {
        pos.set(n.id, {
          x: 100 + d * colW,
          y: 22 + height / 2 + (i - (list.length - 1) / 2) * rowH,
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
    const heads = depths.map(d => {
      const n = byDepth.get(d)[0];
      const label = { repo: 'ENTRY', dependency: 'DEPENDENCY', sink: 'VULNERABLE', exploit: 'EXPLOIT', impact: 'IMPACT', mitigation: 'PHISHGUARD' }[n.kind] || 'STEP';
      return { d, x: 100 + d * colW, label };
    });
    return { nodes: tree.nodes, pos, edges, width, height: height + 22, depths, heads };
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
        <span className="text-[11px] font-mono uppercase tracking-widest text-slate-300">Attack path simulation</span>

        <span className={`ml-1 px-1.5 py-0.5 rounded font-mono text-[10px] font-bold ${
          done ? 'bg-cyber-success/15 text-cyber-success' : 'bg-cyber-danger/15 text-cyber-danger'}`}>
          {done ? 'NEUTRALISED' : `STEP ${step}/${maxDepth}`}
        </span>
        {phaseLabel && <span className="text-[12px] text-slate-200 truncate">{phaseLabel}</span>}

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
            background: done ? '#30D158' : (SEV_COLOR[severity] || '#FF453A'),
          }} />
      </div>

      <div className="overflow-x-auto custom-scrollbar">
        <svg viewBox={`0 0 ${layout.width} ${layout.height}`} width="100%" style={{ maxHeight: layout.height }} preserveAspectRatio="xMidYMid meet" className="block mx-auto">
          <defs>
            <marker id="at-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
              <path d="M0,0 L7,3.5 L0,7 Z" fill="#8E8E93" />
            </marker>
          </defs>

          {/* phase headers */}
          {layout.heads.map(h => {
            const active = h.d === step;
            const passed = h.d < step;
            return (
              <g key={h.d}>
                <text x={h.x} y={13} textAnchor="middle"
                  style={{
                    fontSize: 11.5, fontWeight: 700, letterSpacing: '0.12em', fontFamily: 'ui-monospace, monospace',
                    fill: active ? '#FFFFFF' : passed ? '#D1D1D6' : '#8E8E93', transition: 'fill 400ms',
                  }}>
                  {h.label}
                </text>
                <line x1={h.x - 26} x2={h.x + 26} y1={20} y2={20}
                  stroke={active ? '#FFFFFF' : '#636366'} strokeWidth={active ? 2 : 1}
                  strokeOpacity={active ? 0.9 : 0.6} style={{ transition: 'all 400ms' }} />
              </g>
            );
          })}

          {/* edges */}
          {layout.edges.map((e, i) => {
            const a = layout.pos.get(e.from);
            const b = layout.pos.get(e.to);
            const live = edgeLive(e);
            const advancing = live && e.depth === step && !done;
            const mid = (a.x + b.x) / 2;
            const fromKind = layout.nodes.find(n => n.id === e.from);
            const r0 = (KIND[fromKind ? fromKind.kind : 'dependency'] || KIND.dependency).ring;
            const r1 = (KIND[e.kind] || KIND.dependency).ring;
            const d = `M ${a.x + r0 + 2} ${a.y} C ${mid} ${a.y}, ${mid} ${b.y}, ${b.x - r1 - 4} ${b.y}`;
            const col = e.kind === 'mitigation' ? '#30D158' : live ? (SEV_COLOR[severity] || '#FF453A') : '#6E7783';
            return (
              <g key={i}>
                <path d={d} fill="none" stroke={col} strokeWidth={live ? 2.4 : 1.4}
                  strokeDasharray={live ? 'none' : '4 5'} strokeOpacity={live ? 0.95 : 0.55}
                  style={{ transition: 'stroke 400ms, stroke-width 400ms, stroke-opacity 400ms' }}
                  markerEnd={live ? undefined : 'url(#at-arrow)'} />
                {advancing && (
                  <>
                    <path d={d} fill="none" stroke="#FFFFFF" strokeWidth="2.4" strokeLinecap="round"
                      strokeDasharray="6 14" strokeOpacity="0.9">
                      <animate attributeName="stroke-dashoffset" from="20" to="0" dur="0.7s" repeatCount="indefinite" />
                    </path>
                    <circle r="4.5" fill="#FFFFFF" stroke={col} strokeWidth="2">
                      <animateMotion path={d} dur="0.95s" repeatCount="indefinite" />
                    </circle>
                  </>
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
            const col = n.kind === 'mitigation' ? '#30D158'
              : n.kind === 'sink' || n.kind === 'exploit' ? (SEV_COLOR[severity] || k.color)
              : k.color;
            const r = k.ring;
            const label = String(n.label).length > 17 ? String(n.label).slice(0, 15) + '…' : String(n.label);
            return (
              <g key={n.id} onMouseEnter={() => setHover(n)} onMouseLeave={() => setHover(null)} style={{ cursor: 'pointer' }}>
                {on && isNow && !done && (
                  <circle cx={p.x} cy={p.y} r={r} fill="none" stroke={col} strokeWidth="2">
                    <animate attributeName="r" values={`${r};${r + 12}`} dur="1.3s" repeatCount="indefinite" />
                    <animate attributeName="stroke-opacity" values="0.7;0" dur="1.3s" repeatCount="indefinite" />
                  </circle>
                )}
                {/* solid dark base keeps the icon readable over the glass */}
                <circle cx={p.x} cy={p.y} r={r} fill="#1A1D22" />
                <circle cx={p.x} cy={p.y} r={r}
                  fill={on ? col : 'none'} fillOpacity={on ? 0.18 : 0}
                  stroke={on ? col : '#6E7783'} strokeWidth={on ? 2.6 : 1.6}
                  strokeDasharray={on ? 'none' : '3 3'}
                  style={{ transition: 'all 400ms' }} />
                <foreignObject x={p.x - 12} y={p.y - 12} width="24" height="24" style={{ pointerEvents: 'none' }}>
                  <div className="w-6 h-6 flex items-center justify-center">
                    <k.icon width={17} height={17} strokeWidth={2} style={{ color: on ? '#FFFFFF' : '#8E8E93', transition: 'color 400ms' }} />
                  </div>
                </foreignObject>

                <text x={p.x} y={p.y + r + 19} textAnchor="middle"
                  style={{
                    fontSize: 14.5, fontWeight: 700, fontFamily: 'ui-monospace, monospace',
                    fill: on ? '#FFFFFF' : '#AEAEB2', transition: 'fill 400ms',
                    paintOrder: 'stroke', stroke: '#1A1D22', strokeWidth: 4, strokeLinejoin: 'round',
                  }}>
                  {label}
                </text>
                {n.version && (
                  <text x={p.x} y={p.y + r + 35} textAnchor="middle"
                    style={{
                      fontSize: 12, fontFamily: 'ui-monospace, monospace', fill: on ? '#D1D1D6' : '#8E8E93',
                      paintOrder: 'stroke', stroke: '#1A1D22', strokeWidth: 3, strokeLinejoin: 'round',
                    }}>
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
              <div className="text-[13px] font-bold text-white">{hover.label}</div>
              <div className="text-[12px] text-slate-300 leading-snug">{hover.detail}</div>
            </div>
          </div>
        ) : (
          <div className="text-[11px] text-slate-400 font-mono">
            {tree.route.length > 1
              ? `Route: ${tree.route.join(' → ')} · hover any node for detail`
              : 'Direct dependency · hover any node for detail'}
          </div>
        )}
      </div>
    </div>
  );
}
