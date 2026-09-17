import React, { useEffect, useState, useCallback } from 'react';
import { Timer, Check, ChevronDown } from 'lucide-react';

const LABELS = {
  15: 'Every 15 minutes',
  30: 'Every 30 minutes',
  60: 'Every hour',
  180: 'Every 3 hours',
  360: 'Every 6 hours',
  720: 'Every 12 hours',
  1440: 'Once a day',
};
const SHORT = { 15: '15m', 30: '30m', 60: '1h', 180: '3h', 360: '6h', 720: '12h', 1440: '24h' };

function countdown(iso) {
  if (!iso) return null;
  const ms = new Date(iso).getTime() - Date.now();
  if (!Number.isFinite(ms) || ms <= 0) return 'due now';
  const m = Math.floor(ms / 60000);
  const s = Math.floor((ms % 60000) / 1000);
  if (m >= 60) return `in ${Math.floor(m / 60)}h ${m % 60}m`;
  return m > 0 ? `in ${m}m ${s}s` : `in ${s}s`;
}

/**
 * Auto-scan toggle + cadence picker. The schedule lives on the hub (persisted
 * in the repo's own database), so it survives a page reload or a hub restart.
 */
export default function AutoScanControl() {
  const [state, setState] = useState(null);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [, tick] = useState(0);

  const load = useCallback(() => {
    fetch('/api/autoscan').then(r => r.json()).then(setState).catch(() => {});
  }, []);

  useEffect(() => { load(); }, [load]);

  // live countdown + drift correction
  useEffect(() => {
    const t = setInterval(() => tick(n => n + 1), 1000);
    const p = setInterval(load, 30000);
    return () => { clearInterval(t); clearInterval(p); };
  }, [load]);

  useEffect(() => {
    if (!open) return;
    const close = () => setOpen(false);
    window.addEventListener('click', close);
    return () => window.removeEventListener('click', close);
  }, [open]);

  const push = async (patch) => {
    setBusy(true);
    try {
      const res = await fetch('/api/autoscan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(patch),
      });
      const next = await res.json();
      if (!next.error) setState(next);
    } finally {
      setBusy(false);
    }
  };

  if (!state) return null;

  const intervals = state.intervals || [15, 30, 60, 180, 360, 720, 1440];
  const enabled = !!state.enabled;
  const next = countdown(state.nextRunAt);

  return (
    <div className="flex items-center gap-0 shrink-0" onClick={e => e.stopPropagation()}>
      {/* toggle */}
      <button
        onClick={() => push({ enabled: !enabled })}
        disabled={busy}
        title={enabled ? 'Disable scheduled scanning' : 'Scan this repo automatically on a schedule'}
        className={`flex items-center gap-2 pl-2.5 pr-3 py-1.5 rounded-l-lg border text-[11px] font-mono transition-all disabled:opacity-50 ${
          enabled
            ? 'bg-cyber-success/10 border-cyber-success/40 text-cyber-success'
            : 'bg-cyber-panel/60 border-cyber-border/40 text-slate-400 hover:text-slate-200 hover:border-slate-500'
        }`}
      >
        <span className={`relative inline-flex w-7 h-3.5 rounded-full transition-colors shrink-0 ${
          enabled ? 'bg-cyber-success/40' : 'bg-slate-700'}`}>
          <span className={`absolute top-0.5 w-2.5 h-2.5 rounded-full transition-all ${
            enabled ? 'left-[15px] bg-cyber-success' : 'left-0.5 bg-slate-400'}`} />
        </span>
        <Timer className={`w-3.5 h-3.5 ${enabled && state.running ? 'animate-spin' : ''}`} />
        <span className="font-medium">Auto-scan</span>
      </button>

      {/* interval dropdown */}
      <div className="relative">
        <button
          onClick={() => setOpen(o => !o)}
          disabled={busy}
          title="Scan frequency"
          className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-r-lg border border-l-0 text-[11px] font-mono transition-all disabled:opacity-50 ${
            enabled
              ? 'bg-cyber-success/[0.06] border-cyber-success/40 text-slate-200'
              : 'bg-cyber-panel/60 border-cyber-border/40 text-slate-400 hover:text-slate-200'
          }`}
        >
          <span className="font-bold tabular-nums">{SHORT[state.intervalMinutes] || `${state.intervalMinutes}m`}</span>
          <ChevronDown className={`w-3 h-3 transition-transform ${open ? 'rotate-180' : ''}`} />
        </button>

        {open && (
          <div className="absolute right-0 top-full mt-1.5 w-52 rounded-lg border border-cyber-border/60 bg-cyber-panel shadow-xl shadow-black/50 z-50 overflow-hidden">
            <div className="px-3 py-2 border-b border-cyber-border/40">
              <div className="text-[9px] font-mono uppercase tracking-widest text-slate-500">Scan frequency</div>
            </div>
            {intervals.map(m => (
              <button
                key={m}
                onClick={() => { push({ intervalMinutes: m, enabled: true }); setOpen(false); }}
                className={`w-full flex items-center gap-2 px-3 py-2 text-left text-[11px] transition-colors hover:bg-slate-800/70 ${
                  state.intervalMinutes === m ? 'text-cyber-primary bg-cyber-primary/[0.07]' : 'text-slate-300'
                }`}
              >
                <Check className={`w-3 h-3 shrink-0 ${state.intervalMinutes === m ? 'opacity-100' : 'opacity-0'}`} />
                <span>{LABELS[m] || `Every ${m} minutes`}</span>
              </button>
            ))}
            <div className="px-3 py-2 border-t border-cyber-border/40 text-[9px] font-mono text-slate-500 leading-relaxed">
              {enabled
                ? <>Next scan {next || '—'}<br />Scans never overlap.</>
                : 'Picking a frequency turns auto-scan on.'}
            </div>
          </div>
        )}
      </div>

      {enabled && next && (
        <span className="ml-2.5 font-mono text-[10px] text-slate-500 tabular-nums hidden xl:inline">
          {state.running ? 'scanning…' : `next ${next}`}
        </span>
      )}
    </div>
  );
}
