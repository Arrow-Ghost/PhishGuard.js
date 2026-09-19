import React, { useState, useEffect } from 'react';
import { ShieldCheck, ShieldAlert, Info, Crosshair, Boxes, Wrench, Activity, Bug } from 'lucide-react';
import { usePhishGuard } from '../App';

const TONE = {
  success: { text: 'text-cyber-success', stroke: '#7FD1A8', bg: 'bg-cyber-success/10', border: 'border-cyber-success/30' },
  warning: { text: 'text-cyber-warning', stroke: '#E2B36B', bg: 'bg-cyber-warning/10', border: 'border-cyber-warning/30' },
  danger:  { text: 'text-cyber-danger',  stroke: '#E58585', bg: 'bg-cyber-danger/10',  border: 'border-cyber-danger/30' },
  muted:   { text: 'text-slate-400',     stroke: '#A4ACB8', bg: 'bg-slate-700/10',     border: 'border-slate-600/30' },
};

const BAND_ICON = {
  vulnerability: Bug,
  exploitability: Crosshair,
  supplyChain: Boxes,
  maintenance: Wrench,
  runtime: Activity,
};

function bandTone(score) {
  if (score >= 85) return 'success';
  if (score >= 55) return 'warning';
  return 'danger';
}

/** Radial grade gauge: an arc proportional to the score with the letter inside. */
export function GradeGauge({ score, grade, tone, size = 128, stroke = 9 }) {
  const t = TONE[tone] || TONE.muted;
  const r = (size - stroke) / 2;
  const circ = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score ?? 0)) / 100;
  // leave a 90° gap at the bottom so the arc reads as a gauge
  const arc = circ * 0.75;
  const dash = arc * pct;

  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-[225deg]">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#3A3F48" strokeWidth={stroke}
          strokeDasharray={`${arc} ${circ}`} strokeLinecap="round" />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={t.stroke} strokeWidth={stroke}
          strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 900ms cubic-bezier(.2,.8,.2,1)', filter: `drop-shadow(0 0 6px ${t.stroke}55)` }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={`font-display font-black leading-none ${t.text}`} style={{ fontSize: size * 0.34 }}>
          {grade || '—'}
        </span>
        <span className="font-mono text-[10px] text-slate-400 mt-1 tabular-nums">
          {score == null ? '--' : score}<span className="text-slate-600">/100</span>
        </span>
      </div>
    </div>
  );
}

export default function ScoreWidget() {
  const pg = usePhishGuard();
  const nonce = pg ? pg.nonce : 0;
  const logs = pg ? pg.logs : [];
  const [data, setData] = useState(null);
  const [openBand, setOpenBand] = useState(null);

  useEffect(() => {
    fetch('/api/security-score')
      .then(r => r.json())
      .then(setData)
      .catch(() => {});
  }, [nonce, logs.length]);

  if (!data) {
    return <div className="animate-pulse bg-cyber-panel border border-cyber-border/40 rounded-xl h-[320px] w-full" />;
  }

  const tone = data.tone || 'muted';
  const t = TONE[tone] || TONE.muted;
  const bands = data.bands || [];

  return (
    <div className="glass-panel rounded-xl border border-cyber-border/40 p-5 flex flex-col h-[320px] overflow-hidden">
      <div className="flex items-center gap-2 shrink-0 mb-3">
        {tone === 'success'
          ? <ShieldCheck className="w-5 h-5 text-cyber-success" />
          : <ShieldAlert className={`w-5 h-5 ${t.text}`} />}
        <div className="min-w-0">
          <h3 className="font-sans font-bold text-sm tracking-wide text-slate-100">Global Security Score</h3>
          <span className="text-[10px] text-slate-400 block">Weighted across 5 bands</span>
        </div>
        {data.kevHits > 0 && (
          <span className="ml-auto px-2 py-0.5 rounded bg-cyber-danger/15 border border-cyber-danger/40 text-cyber-danger font-mono text-[9px] font-bold shrink-0">
            {data.kevHits} KEV
          </span>
        )}
      </div>

      <div className="flex gap-4 min-h-0 flex-1">
        {/* grade gauge */}
        <div className="flex flex-col items-center justify-start shrink-0 w-[104px]">
          <GradeGauge score={data.score} grade={data.grade} tone={tone} size={100} stroke={8} />
          <div className={`mt-2 px-2.5 py-1 rounded-md border ${t.bg} ${t.border} text-center w-full`}>
            <div className={`font-sans font-bold text-xs ${t.text}`}>{data.label || '—'}</div>
          </div>
          <p className="text-[9px] leading-snug text-slate-500 text-center mt-1.5 hidden 2xl:block">{data.blurb}</p>
        </div>

        {/* band breakdown */}
        <div className="flex-1 min-w-0 overflow-y-auto custom-scrollbar pr-1 space-y-1.5">
          {bands.map(b => {
            const bt = TONE[bandTone(b.score)];
            const Icon = BAND_ICON[b.key] || Info;
            const open = openBand === b.key;
            return (
              <div key={b.key}>
                <button
                  onClick={() => setOpenBand(open ? null : b.key)}
                  className="w-full text-left group"
                  title="Show the evidence behind this band"
                >
                  <div className="flex items-baseline gap-1.5 mb-1">
                    <Icon className={`w-3 h-3 shrink-0 self-center ${bt.text}`} />
                    <span className="text-[10px] font-medium text-slate-300 truncate group-hover:text-slate-100" title={`${b.label} — ${Math.round(b.weight * 100)}% of the score`}>
                      {b.label}
                    </span>
                    <span className={`ml-auto font-mono text-[10px] font-bold shrink-0 tabular-nums ${bt.text}`}>
                      {b.score}
                    </span>
                  </div>
                  <div className="h-1.5 rounded-full bg-cyber-bg overflow-hidden border border-cyber-border/30">
                    <div className="h-full rounded-full transition-all duration-700"
                      style={{ width: `${b.score}%`, background: bt.stroke, boxShadow: `0 0 6px ${bt.stroke}66` }} />
                  </div>
                </button>
                {open && (
                  <div className="mt-1.5 mb-2 pl-4 space-y-1 border-l border-cyber-border/40">
                    {b.evidence.map((e, i) => (
                      <div key={i} className="flex items-start gap-1.5">
                        <span className={`w-1 h-1 rounded-full mt-1.5 shrink-0 ${
                          e.tone === 'good' ? 'bg-cyber-success' : e.tone === 'warn' ? 'bg-cyber-warning' : 'bg-cyber-danger'}`} />
                        <span className="text-[9px] leading-snug text-slate-400">{e.text}</span>
                      </div>
                    ))}
                    <div className="text-[9px] font-mono text-slate-600 pt-0.5">
                      weight {Math.round(b.weight * 100)}% · contributes {b.contributes} of {b.maxContribution} pts
                    </div>
                  </div>
                )}
              </div>
            );
          })}
          {bands.length === 0 && (
            <div className="text-[11px] text-slate-500 font-mono py-6 text-center">Run a scan to compute bands.</div>
          )}
        </div>
      </div>

      {data.headline && (
        <div className="shrink-0 mt-2.5 pt-2.5 border-t border-cyber-border/30 flex items-center gap-1.5">
          <Info className="w-3 h-3 text-slate-500 shrink-0" />
          <span className="text-[10px] text-slate-400 truncate">{data.headline}</span>
        </div>
      )}
    </div>
  );
}
