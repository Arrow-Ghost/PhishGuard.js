import React, { useEffect, useState } from 'react';
import {
  ShieldCheck, Flame, Layers, Activity, Lock, ShieldAlert, Server, PackageX, GitBranch,
} from 'lucide-react';
import MetricCard from '../components/MetricCard';
import ScoreWidget, { GradeGauge } from '../components/ScoreWidget';
import AutoScanControl from '../components/AutoScanControl';
import ThreatIntelFeed from '../components/ThreatIntelFeed';
import AttackRadar from '../components/AttackRadar';
import RemediationCenter from '../components/RemediationCenter';
import ThreatPredictionEngine from '../components/ThreatPredictionEngine';
import { usePhishGuard } from '../App';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar, Legend,
} from 'recharts';

export default function Dashboard() {
  const { logs, isConnected, scanSummary, nonce } = usePhishGuard();
  const [report, setReport] = useState(null);
  const [history, setHistory] = useState([]);

  const [live, setLive] = useState(null);
  const [advisories, setAdvisories] = useState([]);

  useEffect(() => {
    fetch('/api/scan/latest').then(r => r.json()).then(d => setReport(d && !d.error ? d : null)).catch(() => {});
    fetch('/api/scan/history').then(r => r.json()).then(d => setHistory(Array.isArray(d) ? d : [])).catch(() => {});
    fetch('/api/security-score').then(r => r.json()).then(d => setLive(d && !d.error ? d : null)).catch(() => {});
    // Same source as the "Advisories Affecting This Repo" panel, so the radar
    // can never disagree with the rest of the dashboard.
    fetch('/api/threat-intel')
      .then(r => r.json())
      .then(d => setAdvisories(Array.isArray(d) ? d : (d && d.items) || []))
      .catch(() => setAdvisories([]));
  }, [nonce, scanSummary]);

  const c = report ? report.counts : null;
  const blockedCount = logs.filter(l => l.status === 'BLOCKED').length;
  const warningsCount = logs.filter(l => l.severity === 'warning').length;

  const trendData = [...history].reverse().map(h => ({
    t: new Date(h.ran_at).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit' }),
    score: h.score,
    vulnerable: h.vulnerable_count,
    critical: h.critical_count + h.high_count,
  }));
  if (trendData.length === 1) trendData.unshift({ ...trendData[0], t: '' });

  const severityData = c ? [
    { name: 'Critical', value: c.critical + c.malicious },
    { name: 'High', value: c.high },
    { name: 'Moderate', value: c.moderate },
    { name: 'Low', value: c.low },
    { name: 'Deprecated', value: c.deprecated },
    { name: 'Typosquat', value: c.typosquat },
    { name: 'Install scripts', value: c.lifecycleScripts },
  ] : [];

  return (
    <div className="space-y-6 overflow-y-auto max-h-[calc(100vh-4rem)] pr-2">
      <div className="flex justify-between items-center border-b border-cyber-border/20 pb-4 select-none">
        <div>
          <h2 className="font-sans font-bold text-xl text-slate-100">Security Dashboard</h2>
          <span className="text-xs text-slate-400 block mt-0.5">
            {report
              ? `${report.project.name} — ${report.lockfile.source} — last scanned ${new Date(report.generatedAt).toLocaleString()}`
              : 'No scan yet. Use “Re-scan repo”.'}
          </span>
        </div>
        <div className="flex items-center gap-3 flex-wrap justify-end">
          {live && live.remediation && live.remediation.packages > 0 && (
            <div className="flex items-center gap-2 font-mono text-xs px-2.5 py-1.5 rounded-lg border border-cyber-success/40 bg-cyber-success/10">
              <ShieldCheck className="w-3.5 h-3.5 text-cyber-success" />
              <span className="text-cyber-success font-bold">
                {live.remediation.packages} remediated
              </span>
              {live.remediation.advisoriesPending > 0 && (
                <span className="text-slate-400">
                  · {live.remediation.advisoriesPending} pending npm install
                </span>
              )}
              {live.remediation.advisoriesFixed > 0 && (
                <span className="text-slate-400">
                  · {live.remediation.advisoriesFixed} cleared
                </span>
              )}
            </div>
          )}
          <AutoScanControl />
          <div className="flex items-center gap-2 font-mono text-xs px-2.5 py-1.5 rounded-lg border border-cyber-border/30 bg-cyber-panel/60">
            <Server className="w-3.5 h-3.5 text-cyber-primary" />
            <span className="text-slate-400">Status:</span>
            <span className={report ? (report.status === 'SECURE' ? 'text-cyber-success' : report.status === 'WARNING' ? 'text-cyber-warning' : 'text-cyber-danger') : 'text-slate-400'}>
              {report ? report.status : 'UNSCANNED'}
            </span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
        <MetricCard title="Packages Monitored" value={c ? c.total : '—'}
          subtext={c ? `${c.direct} direct · ${c.transitive} transitive` : 'run a scan'}
          icon={Layers} color="primary"
          sparklineData={history.length ? [...history].reverse().map(h => h.total_packages) : null} />
        <MetricCard title="Vulnerable Packages" value={c ? c.vulnerable : '—'}
          subtext={c
            ? (live && live.remediation && live.remediation.packages
                ? `${c.critical} critical · ${c.high} high · ${live.remediation.packages} remediated`
                : `${c.critical} critical · ${c.high} high`)
            : ''}
          icon={PackageX} color={c && (c.critical || c.high) ? 'danger' : 'success'}
          sparklineData={history.length ? [...history].reverse().map(h => h.vulnerable_count) : null} />
        <MetricCard title="Runtime Blocks" value={blockedCount}
          subtext="Agent-blocked requests this session"
          icon={Flame} color={blockedCount ? 'danger' : 'success'} />
        <PostureCard score={live ? live.score : (report ? report.score : null)}
          grade={live ? live.grade : (report ? report.grade : null)}
          label={live ? live.label : null} tone={live ? live.tone : 'muted'}
          headline={live ? live.headline : null}
          history={history} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <ScoreWidget />
        <AttackRadar logs={logs} advisories={advisories} />

        <div className="glass-panel rounded-xl border border-cyber-border/40 p-5 flex flex-col h-[320px]">
          <div className="flex items-center gap-2.5 mb-4 shrink-0">
            <GitBranch className="w-5 h-5 text-cyber-primary" />
            <div>
              <h3 className="font-sans font-bold text-sm tracking-wide text-slate-100">Posture Over Time</h3>
              <span className="text-[11px] text-slate-400 block mt-0.5">Score per scan (this repo)</span>
            </div>
          </div>
          <div className="flex-1 w-full text-xs font-mono">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="cScore" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#0A84FF" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#0A84FF" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#3A3A3C" strokeDasharray="3 3" opacity={0.2} />
                <XAxis dataKey="t" stroke="#8E8E93" tick={{ fontSize: 9 }} />
                <YAxis stroke="#8E8E93" domain={[0, 100]} />
                <Tooltip contentStyle={{ backgroundColor: '#2C2C2E', borderColor: '#3A3A3C', borderRadius: 6, color: '#F2F2F7', fontFamily: 'monospace' }} />
                <Area name="Score" type="monotone" dataKey="score" stroke="#0A84FF" fillOpacity={1} fill="url(#cScore)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="glass-panel rounded-xl border border-cyber-border/40 p-5 flex flex-col h-[320px]">
          <div className="flex items-center gap-2.5 mb-4 shrink-0">
            <Lock className="w-5 h-5 text-cyber-danger" />
            <div>
              <h3 className="font-sans font-bold text-sm tracking-wide text-slate-100">Findings by Type</h3>
              <span className="text-[11px] text-slate-400 block mt-0.5">Latest scan</span>
            </div>
          </div>
          <div className="flex-1 w-full text-xs font-mono">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                <CartesianGrid stroke="#3A3A3C" strokeDasharray="3 3" opacity={0.2} />
                <XAxis dataKey="name" stroke="#8E8E93" tick={{ fontSize: 9 }} />
                <YAxis stroke="#8E8E93" allowDecimals={false} />
                <Tooltip contentStyle={{ backgroundColor: '#2C2C2E', borderColor: '#3A3A3C', borderRadius: 6, color: '#F2F2F7', fontFamily: 'monospace' }} />
                <Bar dataKey="value" fill="#FF453A" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

      </div>

      {/* three equal-height panels so the row fills the width instead of
          leaving the intel feed stranded on its own line */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
        <ThreatIntelFeed />
        <RemediationCenter />
        <ThreatPredictionEngine />
      </div>

      <div className="glass-panel rounded-xl border border-cyber-border/40 p-5 flex flex-col">
        <h3 className="font-display font-bold text-sm tracking-wider text-slate-100 uppercase mb-4 border-b border-cyber-border/30 pb-2">
          Latest Runtime Telemetry
        </h3>
        <div className="space-y-2.5 max-h-56 overflow-y-auto">
          {logs.slice(0, 6).map((log) => {
            const isBlocked = log.status === 'BLOCKED';
            const isWarning = log.severity === 'warning';
            return (
              <div key={log.id} className={`p-3 rounded-lg border font-mono text-xs flex justify-between items-center ${
                isBlocked ? 'bg-cyber-danger/[0.04] border-cyber-danger/30'
                  : isWarning ? 'bg-cyber-warning/[0.04] border-cyber-warning/30'
                  : 'bg-cyber-bg/60 border-cyber-border/20'}`}>
                <div className="flex gap-3 items-center min-w-0">
                  <span className={`text-[10px] px-2 py-0.5 rounded border uppercase font-bold tracking-widest ${
                    isBlocked ? 'border-cyber-danger text-cyber-danger'
                      : isWarning ? 'border-cyber-warning text-cyber-warning'
                      : 'border-cyber-primary text-cyber-primary'}`}>{log.status}</span>
                  <div className="truncate min-w-0">
                    <span className="text-slate-100 font-bold mr-2">[{log.sourcePackage}]</span>
                    <span className="text-slate-300">{log.details}</span>
                  </div>
                </div>
                <span className="text-[10px] text-cyber-muted shrink-0 ml-4">{new Date(log.timestamp).toLocaleTimeString()}</span>
              </div>
            );
          })}
          {logs.length === 0 && (
            <div className="text-xs font-mono text-slate-500 py-6 text-center">
              No runtime telemetry yet. Import <code className="text-cyber-primary">phishguard/agent</code> in your app, or open the Shield Sandbox.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/* Grade-forward posture card: the letter is the headline, the score supports it. */
function PostureCard({ score, grade, label, tone, headline, history }) {
  const toneCls = {
    success: 'text-cyber-success border-cyber-success/25 bg-cyber-success/[0.05]',
    warning: 'text-cyber-warning border-cyber-warning/25 bg-cyber-warning/[0.05]',
    danger: 'text-cyber-danger border-cyber-danger/25 bg-cyber-danger/[0.05]',
    muted: 'text-slate-400 border-cyber-border/40 bg-cyber-panel/40',
  }[tone || 'muted'];

  const spark = history.length ? [...history].reverse().map(h => h.score) : [];
  const pts = spark.length > 1
    ? spark.map((v, i) => `${(i / (spark.length - 1)) * 100},${30 - (v / 100) * 26}`).join(' ')
    : null;

  return (
    <div className={`glass-panel rounded-xl border p-4 flex items-center gap-4 ${toneCls}`}>
      <GradeGauge score={score} grade={grade} tone={tone || 'muted'} size={74} stroke={6} />
      <div className="min-w-0 flex-1">
        <div className="text-[10px] font-mono uppercase tracking-widest text-slate-500">Posture Grade</div>
        <div className="font-sans font-bold text-base mt-0.5 leading-tight">{label || 'Unscanned'}</div>
        {headline && <div className="text-[10px] text-slate-500 leading-snug mt-1 line-clamp-2">{headline}</div>}
        {pts && (
          <svg viewBox="0 0 100 32" preserveAspectRatio="none" className="w-full h-5 mt-1.5 opacity-70">
            <polyline points={pts} fill="none" stroke="currentColor" strokeWidth="2"
              vectorEffect="non-scaling-stroke" strokeLinejoin="round" strokeLinecap="round" />
          </svg>
        )}
      </div>
    </div>
  );
}
