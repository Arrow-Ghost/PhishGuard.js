import React, { useMemo, useState, useEffect, useRef } from 'react';
import { Radar } from 'lucide-react';

/**
 * 5-axis intrusion radar.
 *
 * Position is meaningful, not decorative:
 *   angle    = threat vector class (one of five sectors)
 *   distance = severity (critical sits on the outer ring)
 *
 * Blips come from real runtime telemetry and the latest scan's findings.
 */

const AXES = [
  { key: 'network', label: 'NETWORK EXFIL', angle: -90 },
  { key: 'dom', label: 'DOM INJECT', angle: -18 },
  { key: 'storage', label: 'CREDENTIALS', angle: 54 },
  { key: 'supply', label: 'SUPPLY CHAIN', angle: 126 },
  { key: 'cve', label: 'KNOWN CVE', angle: 198 },
];

const SEV_RADIUS = { critical: 0.92, high: 0.72, moderate: 0.52, warning: 0.52, low: 0.34, info: 0.28 };
const SEV_COLOR = { critical: '#f43f5e', high: '#fb923c', moderate: '#f59e0b', warning: '#f59e0b', low: '#38bdf8', info: '#10b981' };

function classifyLog(log) {
  const a = `${log.action || ''} ${log.details || ''}`.toLowerCase();
  if (/dom|script|inject/.test(a)) return 'dom';
  if (/storage|cookie|localstorage/.test(a)) return 'storage';
  if (/network|fetch|xhr|beacon|request/.test(a)) return 'network';
  return 'network';
}

function classifyFinding(f) {
  if (f.type === 'malicious' || f.type === 'typosquat') return 'supply';
  if (f.type === 'deprecated') return 'supply';
  return 'cve';
}

/**
 * @param logs        runtime telemetry (only recent events are plotted)
 * @param advisories  the live advisory set from /api/threat-intel - the exact
 *                    same list the "Advisories Affecting This Repo" panel shows,
 *                    so the two can never disagree
 */
export default function AttackRadar({ logs = [], advisories = [] }) {
  const [sweep, setSweep] = useState(0);
  const [hover, setHover] = useState(null);
  const raf = useRef(null);

  useEffect(() => {
    let last = performance.now();
    const tick = (now) => {
      const dt = now - last;
      last = now;
      setSweep(s => (s + dt * 0.06) % 360);      // ~6s per revolution
      raf.current = requestAnimationFrame(tick);
    };
    raf.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf.current);
  }, []);

  // Remediated advisories are no longer live exposure - they must not keep
  // painting contacts on the radar.
  const live = useMemo(
    () => (advisories || []).filter(a => !a.remediated),
    [advisories]
  );

  // Only runtime events from the last hour count as "active" contacts;
  // older telemetry belongs in the log, not on a live radar.
  const recentLogs = useMemo(() => {
    const cutoff = Date.now() - 3600000;
    return (logs || []).filter(l => {
      const t = new Date(l.timestamp).getTime();
      return Number.isFinite(t) && t >= cutoff;
    });
  }, [logs]);

  const blips = useMemo(() => {
    const out = [];
    const pushed = new Set();

    const place = (key, severity, label, meta, seed) => {
      const axis = AXES.find(a => a.key === key) || AXES[0];
      // deterministic jitter inside the 72° sector so repeat items don't stack
      const h = [...String(seed)].reduce((a, c) => (a * 31 + c.charCodeAt(0)) >>> 0, 7);
      const spread = ((h % 1000) / 1000 - 0.5) * 52;       // ±26°
      const wob = ((h >> 10) % 100) / 100 * 0.1 - 0.05;
      const rad = ((axis.angle + spread) * Math.PI) / 180;
      const dist = Math.max(0.18, Math.min(0.95, (SEV_RADIUS[severity] ?? 0.4) + wob));
      out.push({
        id: `${key}-${seed}`,
        x: 50 + Math.cos(rad) * dist * 46,
        y: 50 + Math.sin(rad) * dist * 46,
        angle: (axis.angle + spread + 360) % 360,
        severity, label, meta, axis: axis.label,
      });
    };

    for (const l of recentLogs.slice(0, 24)) {
      if (pushed.has(l.id)) continue;
      pushed.add(l.id);
      place(classifyLog(l), l.status === 'BLOCKED' ? 'critical' : (l.severity || 'info'),
        l.sourcePackage, l.action, l.id);
    }
    for (const f of live.slice(0, 40)) {
      const name = f.packageName || f.package;
      const seed = `${name}-${f.identifier || f.type}`;
      if (pushed.has(seed)) continue;
      pushed.add(seed);
      place(classifyFinding(f), f.severity || 'moderate', name, f.identifier || f.type, seed);
    }
    return out;
  }, [recentLogs, live]);

  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, other: 0 };
    for (const b of blips) {
      if (b.severity === 'critical') c.critical++;
      else if (b.severity === 'high') c.high++;
      else c.other++;
    }
    return c;
  }, [blips]);

  // A blip "pings" when the sweep line passes over it.
  const isLit = (angle) => {
    const d = (sweep - angle + 360) % 360;
    return d < 38;
  };
  const litStrength = (angle) => {
    const d = (sweep - angle + 360) % 360;
    return d < 38 ? 1 - d / 38 : 0;
  };

  return (
    <div className="glass-panel rounded-xl border border-cyber-border/40 p-5 flex flex-col h-[320px] overflow-hidden relative">
      <div className="flex justify-between items-start z-10 relative shrink-0">
        <div className="flex items-center gap-2">
          <Radar className="w-5 h-5 text-cyber-primary" />
          <div>
            <h3 className="font-sans font-bold text-sm tracking-wide text-slate-100">Intrusion Radar</h3>
            <span className="text-[10px] text-slate-400">
              {blips.length
                ? `${live.length} advisor${live.length === 1 ? 'y' : 'ies'}${recentLogs.length ? ` · ${recentLogs.length} runtime` : ''} · bearing = vector, range = severity`
                : 'Repo clear — no live advisories or recent runtime events'}
            </span>
          </div>
        </div>
        <div className="flex items-center gap-1.5 font-mono text-[9px]">
          {counts.critical > 0 && <span className="px-1.5 py-0.5 rounded bg-cyber-danger/15 text-cyber-danger font-bold">{counts.critical} CRIT</span>}
          {counts.high > 0 && <span className="px-1.5 py-0.5 rounded bg-orange-500/15 text-orange-400 font-bold">{counts.high} HIGH</span>}
        </div>
      </div>

      <div className="flex-1 mt-1 relative flex items-center justify-center min-h-0">
        <svg viewBox="0 0 100 100" className="h-full max-h-[215px] aspect-square overflow-visible">
          <defs>
            <radialGradient id="radarGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#4f46e5" stopOpacity="0.14" />
              <stop offset="70%" stopColor="#4f46e5" stopOpacity="0.03" />
              <stop offset="100%" stopColor="#4f46e5" stopOpacity="0" />
            </radialGradient>
            <linearGradient id="sweepGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#4f46e5" stopOpacity="0.45" />
              <stop offset="100%" stopColor="#4f46e5" stopOpacity="0" />
            </linearGradient>
          </defs>

          <circle cx="50" cy="50" r="46" fill="url(#radarGlow)" />

          {/* range rings, labelled by severity band */}
          {[
            { r: 46, label: 'CRIT' },
            { r: 35, label: 'HIGH' },
            { r: 24, label: 'MOD' },
            { r: 13, label: 'LOW' },
          ].map(ring => (
            <g key={ring.r}>
              <circle cx="50" cy="50" r={ring.r} fill="none"
                stroke="#4f46e5" strokeOpacity={ring.r === 46 ? 0.3 : 0.13} strokeWidth="0.4" />
              <text x="50.8" y={50 - ring.r + 2.6} className="fill-slate-600"
                style={{ fontSize: 2.4, fontFamily: 'monospace', letterSpacing: '0.08em' }}>{ring.label}</text>
            </g>
          ))}

          {/* sector dividers + axis labels */}
          {AXES.map(axis => {
            const div = ((axis.angle + 36) * Math.PI) / 180;
            const lab = (axis.angle * Math.PI) / 180;
            const lx = 50 + Math.cos(lab) * 53;
            const ly = 50 + Math.sin(lab) * 53;
            const active = blips.some(b => b.axis === axis.label);
            return (
              <g key={axis.key}>
                <line x1="50" y1="50" x2={50 + Math.cos(div) * 46} y2={50 + Math.sin(div) * 46}
                  stroke="#4f46e5" strokeOpacity="0.14" strokeWidth="0.35" strokeDasharray="1 1.5" />
                <text x={lx} y={ly} textAnchor="middle" dominantBaseline="middle"
                  className={active ? 'fill-slate-400' : 'fill-slate-700'}
                  style={{ fontSize: 2.7, fontFamily: 'monospace', fontWeight: 700, letterSpacing: '0.06em' }}>
                  {axis.label}
                </text>
              </g>
            );
          })}

          {/* rotating sweep */}
          <g transform={`rotate(${sweep} 50 50)`}>
            <path d={`M 50 50 L 96 50 A 46 46 0 0 0 ${50 + 46 * Math.cos(-0.66)} ${50 + 46 * Math.sin(-0.66)} Z`}
              fill="url(#sweepGrad)" />
            <line x1="50" y1="50" x2="96" y2="50" stroke="#818cf8" strokeOpacity="0.75" strokeWidth="0.5" />
          </g>

          {/* centre */}
          <circle cx="50" cy="50" r="2.2" fill="none" stroke="#4f46e5" strokeOpacity="0.6" strokeWidth="0.5" />
          <circle cx="50" cy="50" r="0.8" fill="#818cf8" />

          {/* contacts */}
          {blips.map(b => {
            const lit = litStrength(b.angle);
            const col = SEV_COLOR[b.severity] || '#64748b';
            const isCrit = b.severity === 'critical';
            return (
              <g key={b.id}
                onMouseEnter={() => setHover(b)} onMouseLeave={() => setHover(null)}
                style={{ cursor: 'pointer' }}>
                {(isLit(b.angle) || isCrit) && (
                  <circle cx={b.x} cy={b.y} r={2 + lit * 4} fill="none" stroke={col}
                    strokeOpacity={isCrit ? 0.25 + lit * 0.5 : lit * 0.6} strokeWidth="0.4" />
                )}
                <circle cx={b.x} cy={b.y} r={isCrit ? 1.5 : 1.15} fill={col}
                  opacity={0.45 + lit * 0.55} />
                <circle cx={b.x} cy={b.y} r="3.2" fill="transparent" />
              </g>
            );
          })}
        </svg>

        {hover && (
          <div className="absolute bottom-0 left-0 right-0 mx-2 px-2.5 py-1.5 rounded-md bg-cyber-bg/95 border border-cyber-border/60 backdrop-blur pointer-events-none">
            <div className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: SEV_COLOR[hover.severity] }} />
              <span className="font-mono text-[10px] font-bold text-slate-100 truncate">{hover.label}</span>
              <span className="font-mono text-[9px] text-slate-500 ml-auto shrink-0">{hover.axis}</span>
            </div>
            <div className="font-mono text-[9px] text-slate-400 truncate mt-0.5">{hover.meta}</div>
          </div>
        )}
      </div>
    </div>
  );
}
