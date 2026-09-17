import React, { useEffect, useState } from 'react';
import {
  ShieldAlert, Loader2, AlertTriangle, PackageCheck, Terminal, X, Zap, FileJson, Undo2,
  EyeOff, ShieldQuestion, Check,
} from 'lucide-react';

/**
 * Quarantine wizard.
 *
 * This writes to the target repository's real package.json, so it never acts
 * on a click alone: it fetches the exact plan, shows the diff and every
 * warning, and only mutates after an explicit confirmation. The original file
 * is backed up first and can be restored from the Remediation Center.
 */

const STRATEGY_COPY = {
  upgrade: 'Raise the version range in package.json',
  override: 'Pin the version with an npm "overrides" entry',
  remove: 'Delete the dependency from package.json',
  'registry-only': 'Record in the quarantine registry (no safe manifest edit exists)',
};

export default function QuarantineWizard({ pkg, onComplete, onCancel }) {
  const [plan, setPlan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [applying, setApplying] = useState(false);
  const [result, setResult] = useState(null);
  // 'trust' = the confirmation step before accepting the risk
  const [mode, setMode] = useState('quarantine');
  const [trustReason, setTrustReason] = useState('');

  useEffect(() => {
    let cancelled = false;
    fetch('/api/remediation/preview', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: pkg.name }),
    })
      .then(async r => {
        const d = await r.json();
        if (!r.ok || d.error) throw new Error(d.error || `HTTP ${r.status}`);
        return d;
      })
      .then(d => { if (!cancelled) { setPlan(d); setLoading(false); } })
      .catch(e => { if (!cancelled) { setError(e.message); setLoading(false); } });
    return () => { cancelled = true; };
  }, [pkg.name]);

  const ignore = () => {
    setApplying(true);
    fetch('/api/ignore', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: pkg.name,
        version: plan ? plan.installedVersion : pkg.version,
        reason: trustReason.trim() || 'Marked as trusted from the threat map',
        acknowledged: true,          // the trust question below was answered
      }),
    })
      .then(async r => {
        const d = await r.json();
        if (!r.ok || d.error) throw new Error(d.error || `HTTP ${r.status}`);
        return d;
      })
      .then(d => setResult({ ignored: true, ...d }))
      .catch(e => setError(e.message))
      .finally(() => setApplying(false));
  };

  const apply = () => {
    setApplying(true);
    fetch('/api/remediation/apply', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: pkg.name, reason: `Quarantined from the threat map (risk ${pkg.riskScore})` }),
    })
      .then(async r => {
        const d = await r.json();
        if (!r.ok || d.error) throw new Error(d.error || `HTTP ${r.status}`);
        return d;
      })
      .then(d => setResult(d))
      .catch(e => setError(e.message))
      .finally(() => setApplying(false));
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="glass-panel w-full max-w-xl rounded-xl border border-cyber-danger/40 shadow-[0_0_60px_rgba(244,63,94,0.12)] overflow-hidden flex flex-col max-h-[85vh]">
        {/* header */}
        <div className="flex items-center gap-3 p-5 border-b border-cyber-border/40 shrink-0">
          <div className="p-2 rounded-lg bg-cyber-danger/10 border border-cyber-danger/30">
            <ShieldAlert className="w-5 h-5 text-cyber-danger" />
          </div>
          <div className="min-w-0">
            <h3 className="font-sans font-bold text-base text-slate-100 truncate">
              {mode === 'trust' ? 'Trust' : 'Quarantine'} {pkg.name}
            </h3>
            <p className="text-[11px] text-slate-400">
              {result
                ? 'Done'
                : mode === 'trust'
                  ? 'Accept the risk and stop scoring this package'
                  : 'PhishGuard will edit this repository’s package.json'}
            </p>
          </div>
          <button onClick={onCancel} className="ml-auto p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-100">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 overflow-y-auto custom-scrollbar space-y-4 min-h-0">
          {loading && (
            <div className="flex items-center gap-2 text-slate-400 font-mono text-xs py-6 justify-center">
              <Loader2 className="w-4 h-4 animate-spin" /> Building the remediation plan…
            </div>
          )}

          {error && (
            <div className="p-3 rounded-lg bg-cyber-danger/10 border border-cyber-danger/30">
              <div className="flex items-center gap-1.5 text-cyber-danger text-xs font-bold mb-1">
                <AlertTriangle className="w-3.5 h-3.5" /> Could not plan this change
              </div>
              <p className="text-[11px] font-mono text-slate-300">{error}</p>
            </div>
          )}

          {mode === 'trust' && !result && (
            <div className="space-y-4">
              <div className="flex items-start gap-3 p-3.5 rounded-lg bg-cyber-warning/[0.07] border border-cyber-warning/30">
                <ShieldQuestion className="w-5 h-5 text-cyber-warning shrink-0 mt-0.5" />
                <div>
                  <h4 className="font-sans font-bold text-sm text-slate-100 mb-1">
                    Do you trust {pkg.name}?
                  </h4>
                  <p className="text-[11px] text-slate-300 leading-relaxed">
                    Ignoring removes this package from your security score. Its advisories stay
                    visible in scans and reports for audit, but they stop counting against you —
                    and PhishGuard will no longer flag it as a threat.
                  </p>
                </div>
              </div>

              <div className="space-y-1.5">
                {[
                  `You have reviewed what ${pkg.name} does and where it came from.`,
                  'You accept the risk of the advisories it currently carries.',
                  'You will re-evaluate if a new advisory is published for it.',
                ].map((t, i) => (
                  <div key={i} className="flex items-start gap-2">
                    <Check className="w-3 h-3 text-cyber-success shrink-0 mt-0.5" />
                    <span className="text-[11px] text-slate-400 leading-relaxed">{t}</span>
                  </div>
                ))}
              </div>

              <div>
                <label className="text-[9px] font-mono uppercase tracking-widest text-slate-500 mb-1.5 block">
                  Why do you trust it? (recorded in the audit trail)
                </label>
                <input
                  value={trustReason}
                  onChange={e => setTrustReason(e.target.value)}
                  placeholder="e.g. internal fork, advisory not reachable from our code…"
                  className="w-full bg-cyber-bg/60 border border-cyber-border/40 rounded-lg px-3 py-2 text-[11px] font-mono text-slate-200 outline-none focus:border-cyber-warning/50"
                />
              </div>

              <p className="text-[10px] font-mono text-slate-500 leading-relaxed">
                This is reversible — revoke trust any time and its advisories count again.
              </p>
            </div>
          )}

          {plan && !result && mode === 'quarantine' && (
            <>
              <div className="grid grid-cols-2 gap-3">
                <Field label="Installed" value={`${plan.package}@${plan.installedVersion}`} mono />
                <Field label="Reachability" value={plan.direct ? `direct (${plan.field})` : 'transitive'} />
                <Field label="Strategy" value={STRATEGY_COPY[plan.strategy] || plan.strategy} />
                <Field label="Advisories cleared" value={`${plan.clears} of ${plan.totalAdvisories}`}
                  tone={plan.clears ? 'success' : 'warning'} />
              </div>

              <div>
                <div className="text-[9px] font-mono uppercase tracking-widest text-slate-500 mb-1.5 flex items-center gap-1.5">
                  <FileJson className="w-3 h-3" /> package.json changes
                </div>
                {plan.changes.length ? (
                  <div className="rounded-lg border border-cyber-border/40 bg-[#0d1117] p-3 font-mono text-[11px] space-y-0.5">
                    {plan.changes.map((c, i) => (
                      <React.Fragment key={i}>
                        {c.from != null && <div className="text-cyber-danger">- "{c.pointer}": {JSON.stringify(c.from)}</div>}
                        {c.to != null && <div className="text-cyber-success">+ "{c.pointer}": {JSON.stringify(c.to)}</div>}
                        {c.op === 'delete' && <div className="text-slate-500">  entry removed</div>}
                      </React.Fragment>
                    ))}
                  </div>
                ) : (
                  <div className="rounded-lg border border-cyber-border/40 bg-cyber-bg/60 p-3 text-[11px] text-slate-400 font-mono">
                    No manifest change — this will only be recorded in the quarantine registry.
                  </div>
                )}
              </div>

              {plan.warnings.map((w, i) => (
                <div key={i} className="flex items-start gap-2 p-2.5 rounded-lg bg-cyber-warning/[0.06] border border-cyber-warning/25">
                  <AlertTriangle className="w-3.5 h-3.5 text-cyber-warning shrink-0 mt-0.5" />
                  <span className="text-[11px] text-cyber-warning leading-relaxed">{w}</span>
                </div>
              ))}

              {plan.editsManifest && (
                <p className="text-[10px] font-mono text-slate-500 leading-relaxed">
                  The current package.json is copied to <span className="text-slate-300">.phishguard/backups/</span> before
                  anything is written, and can be rolled back from the Remediation Center.
                </p>
              )}
            </>
          )}

          {result && result.ignored && (
            <div className="space-y-3">
              <div className="flex items-center gap-2 text-cyber-warning">
                <EyeOff className="w-5 h-5" />
                <span className="font-sans font-bold text-sm">{pkg.name} is now trusted</span>
              </div>
              <p className="text-[11px] text-slate-300 leading-relaxed">
                Its advisories are excluded from the security score and it is no longer treated as a
                threat. It still appears in scans and exported reports so the decision stays auditable.
              </p>
              <p className="text-[10px] font-mono text-slate-500">
                Revoke from the Remediation Center to bring its findings back.
              </p>
            </div>
          )}

          {result && !result.ignored && (
            <div className="space-y-3">
              <div className="flex items-center gap-2 text-cyber-success">
                <PackageCheck className="w-5 h-5" />
                <span className="font-sans font-bold text-sm">
                  {result.result.applied ? 'package.json updated' : 'Recorded in the quarantine registry'}
                </span>
              </div>
              <p className="text-[11px] text-slate-300 leading-relaxed">{result.plan.summary}</p>
              {result.result.backup && (
                <div className="flex items-center gap-1.5 text-[10px] font-mono text-slate-400">
                  <Undo2 className="w-3 h-3" /> backup saved: {result.result.backup}
                </div>
              )}
              {result.result.needsInstall && (
                <div>
                  <div className="text-[9px] font-mono uppercase tracking-widest text-slate-500 mb-1.5">Finish the change</div>
                  <div className="flex items-center gap-2 font-mono text-[12px] text-slate-100 bg-[#0d1117] border border-cyber-border/40 rounded-lg px-3 py-2">
                    <Terminal className="w-3.5 h-3.5 text-cyber-primary shrink-0" />
                    {result.result.needsInstall}
                  </div>
                  <p className="text-[10px] text-slate-500 mt-1.5 font-mono">
                    PhishGuard does not run installs for you — review the diff, then run this yourself.
                  </p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* actions */}
        <div className="p-4 border-t border-cyber-border/40 flex items-center gap-2 shrink-0">
          {!result && mode === 'trust' ? (
            <>
              <button onClick={ignore} disabled={applying}
                className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg bg-cyber-warning/15 border border-cyber-warning/50 text-cyber-warning hover:bg-cyber-warning hover:text-black text-xs font-bold transition-colors disabled:opacity-40">
                {applying ? <Loader2 className="w-4 h-4 animate-spin" /> : <EyeOff className="w-4 h-4" />}
                Yes, I trust it — stop flagging
              </button>
              <button onClick={() => setMode('quarantine')}
                className="px-4 py-2.5 rounded-lg border border-cyber-border/50 text-slate-400 hover:text-slate-100 text-xs font-bold">
                Back
              </button>
            </>
          ) : !result ? (
            <>
              <button
                onClick={apply}
                disabled={!plan || applying}
                className={`flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg font-sans text-xs font-bold transition-colors disabled:opacity-40 ${
                  plan && plan.editsManifest
                    ? 'bg-cyber-danger/15 border border-cyber-danger/50 text-cyber-danger hover:bg-cyber-danger hover:text-white'
                    : 'bg-cyber-primary/15 border border-cyber-primary/50 text-cyber-primary hover:bg-cyber-primary hover:text-white'
                }`}
              >
                {applying ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                {plan && plan.editsManifest ? 'Confirm — write package.json' : 'Record quarantine'}
              </button>
              <button onClick={() => setMode('trust')} disabled={applying}
                title="Accept the risk and exclude this package from the score"
                className="flex items-center justify-center gap-1.5 px-4 py-2.5 rounded-lg border border-cyber-warning/40 text-cyber-warning hover:bg-cyber-warning/10 text-xs font-bold transition-colors disabled:opacity-40">
                <EyeOff className="w-3.5 h-3.5" /> Ignore
              </button>
              <button onClick={onCancel}
                className="px-4 py-2.5 rounded-lg border border-cyber-border/50 text-slate-400 hover:text-slate-100 text-xs font-bold">
                Cancel
              </button>
            </>
          ) : (
            <button onClick={() => onComplete(result)}
              className="flex-1 py-2.5 rounded-lg bg-cyber-success/15 border border-cyber-success/50 text-cyber-success hover:bg-cyber-success hover:text-white text-xs font-bold transition-colors">
              Close
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function Field({ label, value, mono, tone }) {
  const col = tone === 'success' ? 'text-cyber-success' : tone === 'warning' ? 'text-cyber-warning' : 'text-slate-200';
  return (
    <div className="p-2.5 rounded-lg bg-cyber-bg/60 border border-cyber-border/30">
      <div className="text-[9px] font-mono uppercase tracking-wider text-slate-500 mb-0.5">{label}</div>
      <div className={`text-[11px] font-bold ${mono ? 'font-mono' : ''} ${col} break-words`}>{value}</div>
    </div>
  );
}
