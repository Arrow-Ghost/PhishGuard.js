import React, { useMemo, useState, useEffect, useRef } from 'react';
import { Radar } from 'lucide-react';

/**
 * Intrusion radar.
 *
 * Position carries meaning, nothing here is decoration:
 *   bearing  = threat vector (six 60 degree sectors)
 *   range    = severity (critical on the outer ring, low near the centre)
 *
 * Contacts come from live advisories and from runtime agent telemetry.
 */

const AXES = [
  { key: 'network', label: 'NETWORK', angle: -90 },
  { key: 'dom', label: 'DOM', angle: -30 },
  { key: 'storage', label: 'CREDENTIALS', angle: 30 },
  { key: 'process', label: 'PROCESS', angle: 90 },
  { key: 'supply', label: 'SUPPLY CHAIN', angle: 150 },
  { key: 'cve', label: 'KNOWN CVE', angle: 210 },
];

const RINGS = [
  { r: 0.25, label: 'LOW' },
  { r: 0.5, label: 'MODERATE' },
  { r: 0.75, label: 'HIGH' },
  { r: 1, label: 'CRITICAL' },
];

const SEV_RADIUS = { critical: 0.9, high: 0.7, moderate: 0.5, warning: 0.5, low: 0.3, info: 0.24 };
const SEV_COLOR = { critical: '#FF453A', high: '#FF9F0A', moderate: '#FF9F0A', warning: '#FF9F0A', low: '#0A84FF', info: '#30D158' };
const SEV_LABEL = { critical: 'Critical', high: 'High', moderate: 'Moderate', warning: 'Moderate', low: 'Low', info: 'Info' };

const CX = 150, CY = 150, R = 104;           // viewBox is 300 x 300

const rad = (deg) => (deg * Math.PI) / 180;
const pt = (deg, dist) => [CX + Math.cos(rad(deg)) * R * dist, CY + Math.sin(rad(deg)) * R * dist];

function classifyLog(log) {
  const a = `${log.action || ''} ${log.details || ''}`.toLowerCase();
  if (/dom|script|inject/.test(a)) return 'dom';
  // credential and secret-file reads (Node fsShield) sit with storage/cookie theft:
  // both mean "your credentials just left the process".
  if (/storage|cookie|localstorage|sensitive path|fs\.readfile/.test(a)) return 'storage';
  // child_process activity (Node processShield)
  if (/^process |child_process|exec(sync)?|spawn(sync)?|fork/.test(a)) return 'process';
  if (/network|fetch|xhr|beacon|request|http\./.test(a)) return 'network';
  return 'network';
}

function classifyFinding(f) {
  if (f.type === 'malicious' || f.type === 'typosquat' || f.type === 'deprecated' || f.type === 'lifecycle-script') return 'supply';
  return 'cve';
}

export default function AttackRadar({ logs = [], advisories = [] }) {
  const [sweep, setSweep] = useState(0);
  const [hover, setHover] = useState(null);
  const raf = useRef(null);

  useEffect(() => {
    let last = performance.now();
    const tick = (now) => {
      const dt = now - last;
      last = now;
      setSweep(s => (s + dt * 0.05) % 360);        // one revolution every 7.2 s
      raf.current = requestAnimationFrame(tick);
    };
    raf.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf.current);
  }, []);

  // Remediated advisories are no longer live exposure.
  const live = useMemo(() => (advisories || []).filter(a => !a.remediated), [advisories]);

  const recentLogs = useMemo(() => {
    const cutoff = Date.now() - 3600000;
    return (logs || []).filter(l => {
      const t = new Date(l.timestamp).getTime();
      return Number.isFinite(t) && t >= cutoff;
    });
  }, [logs]);

  const contacts = useMemo(() => {
    const out = [];
    const seen = new Set();

    const place = (key, severity, label, meta, seed, source) => {
      const axis = AXES.find(a => a.key === key) || AXES[0];
      const h = [...String(seed)].reduce((a, c) => (a * 31 + c.charCodeAt(0)) >>> 0, 7);
      const spread = ((h % 1000) / 1000 - 0.5) * 42;          // stay inside the 60 degree sector
      const wob = (((h >> 10) % 100) / 100) * 0.1 - 0.05;
      const bearing = axis.angle + spread;
      const dist = Math.max(0.16, Math.min(0.95, (SEV_RADIUS[severity] ?? 0.4) + wob));
      const [x, y] = pt(bearing, dist);
      out.push({ id: `${key}-${seed}`, x, y, bearing: (bearing + 360) % 360, severity, label, meta, axis: axis.label, axisKey: key, source });
    };

    for (const l of recentLogs.slice(0, 24)) {
      if (seen.has(l.id)) continue;
      seen.add(l.id);
      place(classifyLog(l), l.status === 'BLOCKED' ? 'critical' : (l.severity || 'info'),
        l.sourcePackage, l.action, l.id, 'runtime');
    }
    for (const f of live.slice(0, 40)) {
      const name = f.packageName || f.package;
      const seed = `${name}-${f.identifier || f.type}`;
      if (seen.has(seed)) continue;
      seen.add(seed);
      place(classifyFinding(f), f.severity || 'moderate', name, f.identifier || f.type, seed, 'advisory');
    }
    return out;
  }, [recentLogs, live]);

  const perAxis = useMemo(() => {
    const m = {};
    for (const a of AXES) m[a.key] = 0;
    for (const c of contacts) m[c.axisKey]++;
    return m;
  }, [contacts]);

  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, other: 0 };
    for (const b of contacts) {
      if (b.severity === 'critical') c.critical++;
      else if (b.severity === 'high') c.high++;
      else c.other++;
    }
    return c;
  }, [contacts]);

  // How recently the sweep passed over a bearing (0..1), for the ping effect.
  const lit = (bearing) => {
    const d = (sweep - bearing + 360) % 360;
    return d < 60 ? 1 - d / 60 : 0;
  };

  // The sweep trail is drawn as stacked wedges of decreasing opacity, which
  // renders identically in every browser (no conic gradients needed).
  const TRAIL = 22;
  const trail = Array.from({ length: TRAIL }, (_, i) => {
    const a0 = -i * 2.6;
    const a1 = -(i + 1) * 2.6;
    const [x0, y0] = [CX + Math.cos(rad(a0)) * R, CY + Math.sin(rad(a0)) * R];
    const [x1, y1] = [CX + Math.cos(rad(a1)) * R, CY + Math.sin(rad(a1)) * R];
    return { d: `M ${CX} ${CY} L ${x0} ${y0} A ${R} ${R} 0 0 0 ${x1} ${y1} Z`, o: 0.3 * (1 - i / TRAIL) };
  });

  const ticks = Array.from({ length: 72 }, (_, i) => {
    const deg = i * 5;
    const major = deg % 30 === 0;
    const [x0, y0] = [CX + Math.cos(rad(deg)) * (R + 2), CY + Math.sin(rad(deg)) * (R + 2)];
    const [x1, y1] = [CX + Math.cos(rad(deg)) * (R + (major ? 8 : 5)), CY + Math.sin(rad(deg)) * (R + (major ? 8 : 5))];
    return { x0, y0, x1, y1, major };
  });

  return (
    <div className="glass-panel rounded-xl border border-cyber-border/40 p-5 flex flex-col h-[320px] overflow-hidden relative">
      <div className="flex justify-between items-start shrink-0 relative z-10">
        <div className="flex items-center gap-2">
          <Radar className="w-5 h-5 text-cyber-primary" />
          <div>
            <h3 className="font-sans font-bold text-sm tracking-wide text-slate-100">Intrusion Radar</h3>
            <span className="text-[10px] text-slate-400">
              {contacts.length
                ? `${contacts.length} contact${contacts.length === 1 ? '' : 's'} · bearing is the vector, range is severity`
                : 'Clear. No live advisories or recent runtime events.'}
            </span>
          </div>
        </div>
        <div className="flex items-center gap-1.5 font-mono text-[9px]">
          {counts.critical > 0 && <span className="px-1.5 py-0.5 rounded bg-cyber-danger/15 text-cyber-danger font-bold">{counts.critical} CRIT</span>}
          {counts.high > 0 && <span className="px-1.5 py-0.5 rounded bg-orange-500/15 text-orange-300 font-bold">{counts.high} HIGH</span>}
        </div>
      </div>

      <div className="flex-1 min-h-0 relative flex items-center justify-center">
        <svg viewBox="0 0 300 300" className="h-full max-h-[236px] aspect-square overflow-visible select-none">
          <defs>
            <radialGradient id="rd-face" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#1B1640" stopOpacity="0.55" />
              <stop offset="100%" stopColor="#14161A" stopOpacity="0.75" />
            </radialGradient>
            <clipPath id="rd-clip"><circle cx={CX} cy={CY} r={R} /></clipPath>
          </defs>

          {/* dial face */}
          <circle cx={CX} cy={CY} r={R} fill="url(#rd-face)" />
          <circle cx={CX} cy={CY} r={R + 1} fill="none" stroke="#F2F2F7" strokeOpacity="0.45" strokeWidth="1.2" />

          {/* alternating sector shading marks each threat vector */}
          {AXES.map((a, i) => {
            const a0 = a.angle - 30, a1 = a.angle + 30;
            const [x0, y0] = [CX + Math.cos(rad(a0)) * R, CY + Math.sin(rad(a0)) * R];
            const [x1, y1] = [CX + Math.cos(rad(a1)) * R, CY + Math.sin(rad(a1)) * R];
            return (
              <path key={a.key} d={`M ${CX} ${CY} L ${x0} ${y0} A ${R} ${R} 0 0 1 ${x1} ${y1} Z`}
                fill="#F2F2F7" fillOpacity={i % 2 === 0 ? 0.045 : 0.015} />
            );
          })}

          {/* range rings */}
          {RINGS.map(ring => (
            <circle key={ring.label} cx={CX} cy={CY} r={R * ring.r} fill="none"
              stroke="#F2F2F7" strokeOpacity={ring.r === 1 ? 0 : 0.2} strokeWidth="0.8" />
          ))}

          {/* sector dividers */}
          {AXES.map(a => {
            const [x, y] = pt(a.angle + 30, 1);
            return <line key={a.key} x1={CX} y1={CY} x2={x} y2={y} stroke="#F2F2F7" strokeOpacity="0.22" strokeWidth="0.8" />;
          })}

          {/* degree ticks */}
          {ticks.map((t, i) => (
            <line key={i} x1={t.x0} y1={t.y0} x2={t.x1} y2={t.y1} stroke="#F2F2F7"
              strokeOpacity={t.major ? 0.55 : 0.25} strokeWidth={t.major ? 1 : 0.7} />
          ))}

          {/* severity labels on the vertical axis */}
          {RINGS.map(ring => (
            <text key={ring.label} x={CX + 3} y={CY - R * ring.r + 9} fill="#F2F2F7" fillOpacity="0.5"
              style={{ fontSize: 5.6, fontFamily: 'ui-monospace, monospace', letterSpacing: '0.08em' }}>
              {ring.label}
            </text>
          ))}

          {/* sweep with trail */}
          <g transform={`rotate(${sweep} ${CX} ${CY})`} clipPath="url(#rd-clip)">
            {trail.map((w, i) => <path key={i} d={w.d} fill="#0A84FF" fillOpacity={w.o} />)}
            <line x1={CX} y1={CY} x2={CX + R} y2={CY} stroke="#F2F2F7" strokeOpacity="0.9" strokeWidth="1.3" />
          </g>

          {/* sector names, with live counts */}
          {AXES.map(a => {
            const [x, y] = pt(a.angle, 1.2);
            const n = perAxis[a.key];
            return (
              <g key={a.key}>
                <text x={x} y={y - 2} textAnchor="middle" dominantBaseline="middle"
                  fill={n ? '#F2F2F7' : '#D1D1D6'} fillOpacity={n ? 1 : 0.85}
                  style={{ fontSize: 7.4, fontWeight: 700, fontFamily: 'ui-monospace, monospace', letterSpacing: '0.06em' }}>
                  {a.label}
                </text>
                <text x={x} y={y + 7.5} textAnchor="middle" dominantBaseline="middle"
                  fill={n ? '#FFE3D4' : '#AEAEB2'} fillOpacity={n ? 1 : 0.8}
                  style={{ fontSize: 7, fontFamily: 'ui-monospace, monospace' }}>
                  {n} {n === 1 ? 'contact' : 'contacts'}
                </text>
              </g>
            );
          })}

          {/* contacts */}
          {contacts.map(c => {
            const l = lit(c.bearing);
            const col = SEV_COLOR[c.severity] || '#8E8E93';
            const isHover = hover && hover.id === c.id;
            return (
              <g key={c.id} onMouseEnter={() => setHover(c)} onMouseLeave={() => setHover(null)} style={{ cursor: 'pointer' }}>
                {(l > 0.05 || isHover) && (
                  <circle cx={c.x} cy={c.y} r={4 + (isHover ? 5 : l * 6)} fill="none" stroke={col}
                    strokeOpacity={isHover ? 0.9 : l * 0.7} strokeWidth="1" />
                )}
                <circle cx={c.x} cy={c.y} r={c.severity === 'critical' ? 3.6 : 3} fill={col}
                  fillOpacity={0.55 + l * 0.45} stroke="#14161A" strokeWidth="1" />
                <circle cx={c.x} cy={c.y} r="8" fill="transparent" />
              </g>
            );
          })}

          {/* centre readout */}
          <circle cx={CX} cy={CY} r="15" fill="#14161A" fillOpacity="0.85" stroke="#F2F2F7" strokeOpacity="0.4" strokeWidth="0.8" />
          <text x={CX} y={CY + 1} textAnchor="middle" dominantBaseline="middle" fill="#F2F2F7"
            style={{ fontSize: 13, fontWeight: 700, fontFamily: 'ui-monospace, monospace' }}>
            {contacts.length}
          </text>
        </svg>

        {/* hover readout */}
        {hover && (
          <div className="absolute bottom-0 left-0 right-0 px-3 py-2 rounded-lg bg-cyber-bg/95 border border-white/20 backdrop-blur pointer-events-none">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full shrink-0" style={{ background: SEV_COLOR[hover.severity] }} />
              <span className="font-mono text-[11px] font-bold text-slate-100 truncate">{hover.label}</span>
              <span className="font-mono text-[9px] text-slate-400 ml-auto shrink-0">
                {SEV_LABEL[hover.severity]} · {hover.axis}
              </span>
            </div>
            <div className="font-mono text-[10px] text-slate-300 truncate mt-0.5">
              {hover.source === 'runtime' ? 'Runtime · ' : 'Advisory · '}{hover.meta}
            </div>
          </div>
        )}
      </div>

      {/* legend */}
      <div className="shrink-0 flex items-center justify-center gap-4 pt-1 font-mono text-[9px] text-slate-300">
        {['critical', 'high', 'moderate', 'low'].map(s => (
          <span key={s} className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full" style={{ background: SEV_COLOR[s] }} />
            {SEV_LABEL[s]}
          </span>
        ))}
      </div>
    </div>
  );
}
