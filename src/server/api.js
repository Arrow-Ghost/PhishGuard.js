/**
 * REST API for the SOC dashboard. Every endpoint is backed by real scan output,
 * the per-project SQLite database, or live runtime telemetry - there is no
 * hard-coded demo data here.
 */

const path = require('path');
const { spawn } = require('child_process');
const express = require('express');
const { scanManifest } = require('../core/scanner');
const { computePosture, gradeMeta } = require('../core/score');
const { getGlobalIntel, fetchKevIdSet } = require('../core/intel');
const { modelImpact, buildAttackTree } = require('../core/impact');
const { getPackageTimeline } = require('../core/history');
const { analyseProvenance } = require('../core/provenance');
const remediate = require('../core/remediate');
const { packageRoot } = require('../util/paths');

function severityRank(s) {
  return { critical: 4, high: 3, moderate: 2, low: 1, info: 0 }[s] || 0;
}

/** Window shorthand ("24h", "7d", "30d", "all") -> ISO timestamp. */
const WINDOW_HOURS = { '1h': 1, '6h': 6, '12h': 12, '24h': 24, '48h': 48, '7d': 168, '14d': 336, '30d': 720, '90d': 2160 };

function windowToIso(win) {
  if (!win || win === 'all') return new Date(0).toISOString();
  const hours = WINDOW_HOURS[win];
  // An unknown window used to fall through to "all time", silently answering a
  // different question than the one asked.
  if (!hours) throw new Error(`Unknown window "${win}". Use one of: ${Object.keys(WINDOW_HOURS).join(', ')}, all`);
  return new Date(Date.now() - hours * 3600000).toISOString();
}

/** Blend the static scan score with a time-decayed penalty from recent BLOCKED telemetry. */
function liveScore(scanScore, logs) {
  const now = Date.now();
  const base = Number.isFinite(scanScore) ? scanScore : 100;
  let penalty = 0;
  for (const l of logs) {
    if (l.status !== 'BLOCKED' && l.severity !== 'critical') continue;
    const t = new Date(l.timestamp).getTime();
    if (!Number.isFinite(t)) continue;
    const ageH = (now - t) / 3600000;
    if (!(ageH >= 0) || ageH > 72) continue;
    const decay = Math.exp(-ageH / 24); // ~24h half-life
    penalty += (l.severity === 'critical' ? 6 : 3) * decay;
  }
  return Math.max(0, Math.min(100, Math.round(base - penalty)));
}

function buildGraph(report, remediated, ignored) {
  if (!report) return { nodes: [], links: [] };
  const rootNode = {
    id: 'node-root', name: report.project.name || 'project', type: 'root', r: 34,
    version: report.project.version || '0.0.0', riskScore: 0, category: 'safe',
    license: null, author: 'this repository',
    description: `${report.counts.total} packages resolved from ${report.lockfile.source}.`,
    findings: `Posture ${report.score}/100 (grade ${report.grade}) - ${report.status}. Same score the dashboard gauge shows: runtime telemetry, remediation and accepted risk are all already folded in.`, cves: [], recommendations: [],
  };

  // keep the graph legible: all direct deps + every non-safe package + a slice of safe transitive
  const direct = report.packages.filter(p => p.direct);
  const risky = report.packages.filter(p => !p.direct && p.category !== 'safe');
  const safeSlice = report.packages.filter(p => !p.direct && p.category === 'safe').slice(0, 60);
  const chosen = [...direct, ...risky, ...safeSlice];

  const nodes = [rootNode];
  const links = [];
  for (const p of chosen) {
    // ring 1 = direct deps, ring 2 = risky transitive, ring 3 = healthy transitive.
    // The client lays nodes out on these rings so the graph reads outward by trust.
    const rem = remediated && remediated.get(p.name);
    const isIgnored = !!(ignored && ignored.has(p.name));
    const isRemediated = !!(rem && rem.applied);
    const isQuarantined = isRemediated || isIgnored;
    // Accepted risk is neutralised outright; a remediated package is zeroed once
    // the fix is installed and de-escalated while the install is still pending.
    const effRisk = isIgnored
      ? 0
      : isRemediated
        ? (rem.installed ? 0 : Math.round(p.riskScore * 0.25))
        : p.riskScore;
    const effCategory = isQuarantined
      ? (effRisk >= 35 ? 'warning' : 'safe')
      : p.category;
    const ring = p.direct ? 1 : effCategory !== 'safe' ? 2 : 3;
    const group = p.direct ? 'direct' : effCategory !== 'safe' ? 'risky' : 'transitive';
    const cves = p.findings.filter(f => f.identifier).map(f => f.identifier);
    const recs = p.findings.map(f => f.fixedVersion
      ? `Upgrade ${p.name} to ${f.fixedVersion} (${f.identifier || f.type})`
      : f.title).slice(0, 5);
    nodes.push({
      id: `node-${p.name}`,
      name: p.name,
      type: 'dependency',
      r: p.direct ? 20 : 13 + Math.round((effRisk / 100) * 7),
      ring,
      group,
      version: p.version || p.range || '?',
      riskScore: effRisk,
      category: effCategory,
      quarantined: isQuarantined,
      ignored: isIgnored,
      remediation: rem
        ? { strategy: rem.strategy, target: rem.target, pinned: rem.pinned, pending: rem.pending, installed: rem.installed }
        : null,
      direct: p.direct,
      dev: p.dev,
      findingCount: p.findings.length,
      topSeverity: p.findings.length
        ? p.findings.map(f => f.severity).sort((a, b) => severityRank(b) - severityRank(a))[0]
        : null,
      license: p.registry && p.registry.license,
      usage: p.usage || null,
      author: p.direct ? 'direct dependency' : `transitive (depth ${p.depth})`,
      description: p.findings.length
        ? p.findings.map(f => f.title).join(' • ')
        : 'No advisories, deprecations or name-similarity flags.',
      findings: isIgnored
        ? `ACCEPTED RISK - ${p.name} was explicitly marked as trusted, so its findings are excluded from the score. Revoke trust to bring them back.`
        : isRemediated
          ? `QUARANTINED - package.json pins ${p.name} to ${rem.pinned}. ${
              rem.installed
                ? 'The installed version already satisfies the pin; this package is neutralised.'
                : 'Pending: run npm install so the tree resolves to the pinned version.'}`
          : p.findings.length
        ? p.findings.map(f => `${f.severity.toUpperCase()}: ${f.description}`).join('\n\n')
        : 'Passed all checks.',
      cves,
      recommendations: recs,
    });
    links.push({ source: 'node-root', target: `node-${p.name}` });
  }
  return { nodes, links };
}

function classify(report, quarantine) {
  const qNames = new Set(quarantine.map(q => q.name));
  const trusted = [];
  const monitored = [];
  const quarantined = quarantine.map(q => ({
    name: q.name, version: q.version, score: q.risk_score ?? 0,
    reason: q.reason, publisher: null,
  }));
  if (report) {
    for (const p of report.packages) {
      if (qNames.has(p.name)) continue;
      const entry = {
        name: p.name, version: p.version, publisher: null,
        score: Math.max(0, 100 - p.riskScore),
        reason: p.findings[0] ? p.findings[0].title : null,
        usage: p.usage || null,
      };
      if (p.category === 'safe' && !p.deprecated) {
        if (p.direct) trusted.push(entry);
      } else {
        monitored.push(entry);
      }
    }
  }
  trusted.sort((a, b) => b.score - a.score);
  monitored.sort((a, b) => a.score - b.score);
  return { trusted: trusted.slice(0, 40), monitored, quarantined };
}

function threatIntel(report, kevSet, remediated) {
  if (!report) return { items: [], summary: null };
  const seen = new Set();
  const items = [];
  for (const f of report.findings) {
    if (f.type === 'unresolved') continue;
    const key = `${f.packageName}:${f.identifier || f.type}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const exploited = !!(kevSet && f.identifier && kevSet.has(String(f.identifier).toUpperCase()));
    const rem = remediated && remediated.get(f.packageName);
    items.push({
      remediated: !!(rem && rem.applied),
      remediationPending: !!(rem && rem.pending),
      id: key,
      identifier: f.identifier || f.type.toUpperCase(),
      type: f.type,
      title: f.title,
      description: f.description,
      package: f.packageName,
      version: f.packageVersion || '?',
      direct: !!f.direct,
      severity: f.severity,
      fixedVersion: f.fixedVersion || null,
      cwes: f.cwes || [],
      knownExploited: exploited,
      actionable: !!f.fixedVersion,
      source: f.offline
        ? 'PhishGuard offline DB'
        : f.type === 'vulnerability' ? 'OSV.dev'
        : f.type === 'deprecated' ? 'npm registry' : 'PhishGuard heuristics',
      url: f.url || null,
      time: f.published || report.generatedAt,
    });
  }
  items.sort((a, b) =>
    (a.remediated - b.remediated) ||
    (b.knownExploited - a.knownExploited) ||
    (b.direct - a.direct) ||
    (severityRank(b.severity) - severityRank(a.severity)) ||
    String(b.time).localeCompare(String(a.time))
  );
  const summary = {
    total: items.length,
    exploited: items.filter(i => i.knownExploited).length,
    direct: items.filter(i => i.direct).length,
    fixable: items.filter(i => i.actionable).length,
    remediated: items.filter(i => i.remediated).length,
    critical: items.filter(i => i.severity === 'critical').length,
    high: items.filter(i => i.severity === 'high').length,
  };
  return { items: items.slice(0, 60), summary };
}

function analyzeFinding(f) {
  const base = {
    engine: 'heuristic',
    subject: `${f.packageName}@${f.packageVersion || '?'}`,
    identifier: f.identifier || null,
  };
  if (f.type === 'vulnerability') {
    return {
      ...base,
      summary: `${f.packageName} ${f.packageVersion || ''} is affected by ${f.identifier || 'a known advisory'}: ${f.title}.`,
      risk: f.severity === 'critical' ? 'Critical' : f.severity === 'high' ? 'High' : f.severity === 'moderate' ? 'Medium' : 'Low',
      reason: f.description || 'Installed version falls within the advisory\'s affected range (OSV).',
      impact: f.direct
        ? 'Directly reachable from your application code.'
        : 'Reachable transitively; exploitability depends on how the parent dependency uses it.',
      recommended: f.fixedVersion
        ? `Upgrade ${f.packageName} to ${f.fixedVersion} or later, then re-run the scan.`
        : `No fixed version is published yet. Assess usage, add a policy/allowlist mitigation, and monitor ${f.identifier || 'the advisory'}.`,
    };
  }
  if (f.type === 'typosquat') {
    return {
      ...base,
      summary: `${f.packageName} closely resembles a popular package and does not look established.`,
      risk: f.severity === 'critical' ? 'Critical' : 'Medium',
      reason: f.description,
      impact: 'If this is not the package you intended, arbitrary install/runtime code from an unknown author is in your tree.',
      recommended: 'Confirm the intended package name, remove the suspicious one, and check your install history for how it was added.',
    };
  }
  if (f.type === 'lifecycle-script') {
    return {
      ...base,
      summary: f.title,
      risk: f.severity === 'critical' ? 'Critical' : f.severity === 'high' ? 'High' : f.severity === 'moderate' ? 'Medium' : 'Low',
      reason: f.description,
      impact: 'Lifecycle scripts run with full OS access during `npm install`, before any application code or runtime agent is active - this is how most real npm supply-chain compromises actually execute.',
      recommended: f.severity === 'critical'
        ? `Do not install ${f.packageName} until this is reviewed. If already installed, treat as a compromise: rotate exposed secrets and audit what ran.`
        : `Review ${f.packageName}'s install script before approving it in \`phishguard install\`. Prefer packages with no lifecycle scripts when a substitute exists.`,
    };
  }
  if (f.type === 'malicious') {
    return {
      ...base,
      summary: `${f.packageName} matches PhishGuard's known-malicious list.`,
      risk: 'Critical',
      reason: f.description,
      impact: 'Assume credential theft / code execution during install or runtime.',
      recommended: 'Remove immediately, rotate any secrets exposed to CI or dev machines, and audit git history for when it appeared.',
    };
  }
  if (f.type === 'deprecated') {
    return {
      ...base,
      summary: `${f.packageName} is deprecated by its maintainers.`,
      risk: 'Low',
      reason: f.description,
      impact: 'No new security fixes; future advisories will go unpatched.',
      recommended: f.fixedVersion ? `Move to ${f.fixedVersion} or a maintained alternative.` : 'Plan a migration to a maintained alternative.',
    };
  }
  return {
    ...base,
    summary: f.title || 'Finding recorded.',
    risk: 'Info', reason: f.description || '', impact: 'See description.', recommended: 'Review in context.',
  };
}

function analyzeLog(log) {
  const isNet = /network|fetch|xhr|beacon/i.test(log.action);
  const isDom = /dom|script|inject/i.test(log.action);
  const isStore = /storage|cookie|localstorage/i.test(log.action);
  return {
    engine: 'heuristic',
    subject: log.sourcePackage,
    summary: isNet
      ? `${log.sourcePackage} attempted a network request to ${log.callerUrl}.`
      : isDom
      ? `${log.sourcePackage} attempted to inject or modify a script element.`
      : isStore
      ? `${log.sourcePackage} accessed browser storage / cookies.`
      : `${log.sourcePackage} triggered a monitored runtime event: ${log.action}.`,
    risk: log.status === 'BLOCKED' ? 'Critical' : log.severity === 'warning' ? 'Medium' : 'Low',
    reason: log.details || 'Matched a runtime policy rule.',
    impact: isNet
      ? 'Potential exfiltration of tokens, cookies or form data to an untrusted origin.'
      : isDom
      ? 'Potential DOM-based XSS / remote payload execution.'
      : isStore
      ? 'Potential credential harvesting from client storage.'
      : 'Unexpected privileged API usage by a dependency.',
    recommended: log.status === 'BLOCKED'
      ? 'Identify the owning dependency, quarantine it, and rotate any exposed session tokens.'
      : 'Confirm the behaviour is expected for this dependency; tighten the allowlist if not.',
  };
}

function linregForecast(snapshots, days = 14) {
  // snapshots: [{captured_at, score}] newest-first
  const pts = [...snapshots].reverse().map((s, i) => [i, s.score]);
  const n = pts.length;
  if (n < 2) {
    const flat = n === 1 ? pts[0][1] : 100;
    return Array.from({ length: days }, (_, i) => ({
      day: `Day +${i + 1}`, projectedScore: flat, riskProbability: Math.max(0, 100 - flat),
    }));
  }
  const sx = pts.reduce((a, [x]) => a + x, 0);
  const sy = pts.reduce((a, [, y]) => a + y, 0);
  const sxx = pts.reduce((a, [x]) => a + x * x, 0);
  const sxy = pts.reduce((a, [x, y]) => a + x * y, 0);
  const slope = (n * sxy - sx * sy) / (n * sxx - sx * sx || 1);
  const intercept = (sy - slope * sx) / n;
  return Array.from({ length: days }, (_, i) => {
    const x = n - 1 + (i + 1);
    const score = Math.max(0, Math.min(100, Math.round(intercept + slope * x)));
    return { day: `Day +${i + 1}`, projectedScore: score, riskProbability: 100 - score };
  });
}

/* --------------------------- report renderers ---------------------------- */

function renderMarkdownReport(b) {
  const L = [];
  L.push(`# PhishGuard forensic report — ${b.project.name}`);
  L.push('');
  L.push(`- **Generated:** ${b.generatedAt}`);
  L.push(`- **Window:** ${b.window} (since ${b.windowStart})`);
  if (b.project.lockfile) L.push(`- **Lockfile:** ${b.project.lockfile.source}`);
  if (b.posture) L.push(`- **Posture:** ${b.posture.score}/100 (grade ${b.posture.grade}) — ${b.posture.status}`);
  L.push('');
  L.push('## Summary');
  L.push('');
  L.push('| Metric | Value |');
  L.push('| --- | --- |');
  for (const [k, v] of Object.entries(b.summary)) {
    L.push(`| ${k.replace(/([A-Z])/g, ' $1').replace(/^./, c => c.toUpperCase())} | ${v} |`);
  }
  L.push('');
  if (b.findings.length) {
    L.push('## Supply-chain findings (latest scan)');
    L.push('');
    L.push('| Severity | Package | Advisory | Title | Fix | KEV |');
    L.push('| --- | --- | --- | --- | --- | --- |');
    for (const f of b.findings.slice(0, 300)) {
      L.push(`| ${f.severity} | \`${f.package}@${f.version || '?'}\`${f.direct ? ' *(direct)*' : ''} | ${f.identifier || '—'} | ${(f.title || '').replace(/\|/g, '\\|')} | ${f.fixedVersion || '—'} | ${f.knownExploited ? '**YES**' : '—'} |`);
    }
    L.push('');
  }
  if (b.runtimeEvents.length) {
    L.push('## Runtime telemetry');
    L.push('');
    L.push('| Time | Origin | Status | Severity | Source | Action | Detail |');
    L.push('| --- | --- | --- | --- | --- | --- | --- |');
    for (const l of b.runtimeEvents.slice(0, 300)) {
      L.push(`| ${l.timestamp} | ${(l.origin || 'system').toUpperCase()} | ${l.status} | ${l.severity} | \`${l.sourcePackage}\` | ${l.action} | ${(l.details || '').replace(/\|/g, '\\|').slice(0, 160)} |`);
    }
    L.push('');
  }
  if (b.scans.length) {
    L.push('## Scan history in window');
    L.push('');
    L.push('| Ran at | Score | Grade | Status | Packages | Vulnerable |');
    L.push('| --- | --- | --- | --- | --- | --- |');
    for (const s of b.scans) {
      L.push(`| ${s.ran_at} | ${s.score} | ${s.grade} | ${s.status} | ${s.total_packages} | ${s.vulnerable_count} |`);
    }
    L.push('');
  }
  if (b.quarantine.length) {
    L.push('## Quarantine registry');
    L.push('');
    for (const q of b.quarantine) L.push(`- \`${q.name}${q.version ? '@' + q.version : ''}\` — ${q.reason} (${q.quarantined_at})`);
    L.push('');
  }
  L.push('---');
  L.push('');
  L.push('_Generated by PhishGuard. Advisory data: OSV.dev, GitHub Advisory Database, CISA KEV._');
  return L.join('\n');
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

function renderHtmlReport(b) {
  const sevColor = s => ({ critical: '#f43f5e', high: '#fb923c', moderate: '#f59e0b', low: '#64748b' }[s] || '#64748b');
  const rows = b.findings.slice(0, 400).map(f => `<tr>
    <td><span class="pill" style="background:${sevColor(f.severity)}22;color:${sevColor(f.severity)}">${esc(f.severity)}</span></td>
    <td class="mono">${esc(f.package)}@${esc(f.version || '?')}${f.direct ? ' <em>direct</em>' : ''}</td>
    <td class="mono">${f.url ? `<a href="${esc(f.url)}">${esc(f.identifier || '—')}</a>` : esc(f.identifier || '—')}</td>
    <td>${esc(f.title)}</td><td class="mono">${esc(f.fixedVersion || '—')}</td>
    <td>${f.knownExploited ? '<b style="color:#f43f5e">KEV</b>' : '—'}</td></tr>`).join('');
  const logRows = b.runtimeEvents.slice(0, 300).map(l => `<tr>
    <td class="mono">${esc(new Date(l.timestamp).toLocaleString())}</td>
    <td class="mono">${esc((l.origin || 'system').toUpperCase())}</td>
    <td><span class="pill" style="background:${l.status === 'BLOCKED' ? '#f43f5e22' : '#64748b22'};color:${l.status === 'BLOCKED' ? '#f43f5e' : '#94a3b8'}">${esc(l.status)}</span></td>
    <td class="mono">${esc(l.sourcePackage)}</td><td>${esc(l.action)}</td><td>${esc((l.details || '').slice(0, 200))}</td></tr>`).join('');
  return `<!doctype html><html><head><meta charset="utf-8"><title>PhishGuard report — ${esc(b.project.name)}</title>
<style>
:root{color-scheme:light}
body{font:14px/1.55 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:40px;background:#f8fafc;color:#0f172a}
.wrap{max-width:1100px;margin:0 auto;background:#fff;padding:40px;border-radius:14px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
h1{font-size:22px;margin:0 0 4px} h2{font-size:15px;margin:32px 0 10px;padding-bottom:6px;border-bottom:1px solid #e2e8f0;text-transform:uppercase;letter-spacing:.06em;color:#475569}
.sub{color:#64748b;font-size:13px;margin-bottom:24px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0}
.card{border:1px solid #e2e8f0;border-radius:10px;padding:14px}
.card b{display:block;font-size:22px;margin-bottom:2px}
.card span{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.05em}
table{border-collapse:collapse;width:100%;font-size:12px;margin-top:8px}
th{text-align:left;background:#f1f5f9;padding:8px;font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:#475569}
td{padding:8px;border-top:1px solid #f1f5f9;vertical-align:top}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px}
.pill{padding:2px 7px;border-radius:99px;font-size:10px;font-weight:700;text-transform:uppercase}
footer{margin-top:36px;padding-top:16px;border-top:1px solid #e2e8f0;color:#94a3b8;font-size:11px}
@media print{body{padding:0;background:#fff}.wrap{box-shadow:none;padding:0}}
</style></head><body><div class="wrap">
<h1>PhishGuard forensic report</h1>
<div class="sub">${esc(b.project.name)} ${esc(b.project.version || '')} · window ${esc(b.window)} · generated ${esc(new Date(b.generatedAt).toLocaleString())}
${b.posture ? ` · posture <b>${b.posture.score}/100 (${esc(b.posture.grade)})</b> · ${esc(b.posture.status)}` : ''}</div>
<div class="cards">
${Object.entries(b.summary).map(([k, v]) => `<div class="card"><b>${v}</b><span>${esc(k.replace(/([A-Z])/g, ' $1'))}</span></div>`).join('')}
</div>
${rows ? `<h2>Supply-chain findings</h2><table><thead><tr><th>Severity</th><th>Package</th><th>Advisory</th><th>Title</th><th>Fix</th><th>Exploited</th></tr></thead><tbody>${rows}</tbody></table>` : ''}
${logRows ? `<h2>Runtime telemetry</h2><table><thead><tr><th>Time</th><th>Origin</th><th>Status</th><th>Source</th><th>Action</th><th>Detail</th></tr></thead><tbody>${logRows}</tbody></table>` : ''}
${b.scans.length ? `<h2>Scan history</h2><table><thead><tr><th>Ran at</th><th>Score</th><th>Grade</th><th>Status</th><th>Packages</th><th>Vulnerable</th></tr></thead><tbody>${b.scans.map(s => `<tr><td class="mono">${esc(new Date(s.ran_at).toLocaleString())}</td><td>${s.score}</td><td>${esc(s.grade)}</td><td>${esc(s.status)}</td><td>${s.total_packages}</td><td>${s.vulnerable_count}</td></tr>`).join('')}</tbody></table>` : ''}
<footer>Generated by PhishGuard · advisory data from OSV.dev, GitHub Advisory Database and CISA KEV · ${esc(b.windowStart)} → ${esc(b.generatedAt)}</footer>
</div></body></html>`;
}

/** Live hook-verification demos - these actually exercise the runtime agent. */
function demoScenarios() {
  return [
    { id: 'DEMO-net', label: 'Credential exfiltration', kind: 'network', severity: 'critical',
      target: 'http://eval-server.cc/exfiltrate?cookie=session_token',
      blurb: 'Simulates a compromised package POSTing a session token to an attacker host.' },
    { id: 'DEMO-dom', label: 'Remote script injection', kind: 'dom', severity: 'critical',
      target: 'https://raw.githubusercontent.com/malicious-actor/exploit/main/steal.js',
      blurb: 'Simulates a dependency appending a <script> tag pointing at a raw payload host.' },
    { id: 'DEMO-track', label: 'Untrusted telemetry beacon', kind: 'network', severity: 'warning',
      target: 'http://untrusted-analytics-tracker.cc/collect',
      blurb: 'Simulates silent analytics exfiltration from a transitive dependency.' },
    { id: 'DEMO-store', label: 'Client storage write', kind: 'storage', severity: 'warning',
      target: 'localStorage["pg_cached_tz"]',
      blurb: 'Simulates a library caching state in unencrypted browser storage.' },
    { id: 'DEMO-node-net', label: 'Node: outbound exfiltration', kind: 'node-network', severity: 'critical',
      target: 'a sandboxed, dependency-attributed Node process',
      blurb: 'Simulates a compromised server-side dependency calling fetch() to an attacker host.' },
    { id: 'DEMO-node-proc', label: 'Node: malicious subprocess', kind: 'node-process', severity: 'critical',
      target: 'a sandboxed, dependency-attributed Node process',
      blurb: 'Simulates a compromised dependency shelling out to download-and-execute a remote payload.' },
    { id: 'DEMO-node-fs', label: 'Node: credential file read', kind: 'node-fs', severity: 'critical',
      target: 'a sandboxed, dependency-attributed Node process',
      blurb: 'Simulates a compromised dependency reading a .env-style secrets file.' },
  ];
}

function createApi(ctx) {
  const { db, config, getReport, runScan, project, autoscan, port } = ctx;
  const router = express.Router();

  /**
   * Which packages have been remediated, and whether the fix has taken effect.
   * Every endpoint that reports risk consults this so a quarantine is reflected
   * everywhere immediately - not only after the next scan.
   */
  async function remediationState() {
    try {
      const rows = await db.getQuarantine();
      return remediate.resolveRemediationState(project.root, getReport(), rows);
    } catch {
      return new Map();
    }
  }

  /** Packages the user has explicitly vouched for (accepted risk). */
  async function ignoredSet() {
    try {
      const rows = await db.getIgnored();
      return new Set(rows.map(r => r.name));
    } catch {
      return new Set();
    }
  }

  // CISA KEV id set, memoised for the process (the feed updates ~daily).
  let kevCache = { at: 0, set: null };
  async function getKevSet() {
    if (kevCache.set && Date.now() - kevCache.at < 6 * 3600 * 1000) return kevCache.set;
    try {
      const set = await fetchKevIdSet(project.root, { offline: config.offline });
      kevCache = { at: Date.now(), set };
      return set;
    } catch {
      return kevCache.set || new Set();
    }
  }

  router.get('/health', async (req, res) => {
    res.json({ status: 'HEALTHY', timestamp: new Date().toISOString(), db: db.file });
  });

  router.get('/project', async (req, res) => {
    const report = getReport();
    res.json({
      name: (report && report.project.name) || project.name,
      version: (report && report.project.version) || project.version,
      root: project.root,
      lockfile: report ? report.lockfile : null,
      lastScanAt: report ? report.generatedAt : null,
      offline: config.offline,
      failOn: config.failOn,
    });
  });

  router.post('/scan/run', async (req, res) => {
    try {
      const report = await runScan();
      res.json(report);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/scan/latest', (req, res) => {
    res.json(getReport() || null);
  });

  router.get('/scan/history', async (req, res) => {
    res.json(await db.listScans(Number(req.query.limit) || 60));
  });

  router.get('/scan/:id', async (req, res) => {
    const report = await db.getScanById(req.params.id);
    if (!report) return res.status(404).json({ error: 'scan not found' });
    if (report.pruned) {
      return res.status(410).json({
        error: 'This scan is older than the detail-retention window; only its summary row remains.',
        id: report.id, pruned: true,
      });
    }
    res.json(report);
  });

  // Legacy: scan a pasted package.json string/object.
  router.post('/scan', async (req, res) => {
    const { packageJson } = req.body || {};
    if (!packageJson) return res.status(400).json({ error: 'Missing packageJson' });
    try {
      const manifest = typeof packageJson === 'string' ? JSON.parse(packageJson) : packageJson;
      if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
        return res.status(400).json({ error: 'packageJson must be a JSON object' });
      }
      const report = await scanManifest(manifest, {
        cacheRoot: project.root, offline: config.offline, includeDev: config.includeDev,
      });
      // shape kept close to the old endpoint for the existing UI
      res.json({
        score: report.score,
        status: report.status,
        grade: report.grade,
        scannedCount: report.counts.total,
        criticalCount: report.counts.critical + report.counts.malicious + report.counts.typosquat,
        warningCount: report.counts.warning + report.counts.moderate + report.counts.deprecated,
        counts: report.counts,
        dependencies: report.packages.map(p => ({
          name: p.name, version: p.range || p.version, riskScore: p.riskScore, category: p.category,
          findings: p.findings.map(f => ({ type: f.type.toUpperCase(), title: f.title, description: f.description, severity: f.severity })),
        })),
      });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  router.get('/security-score', async (req, res) => {
    const report = getReport();
    const logs = await db.getLogs(400);
    const history = await db.getPostureHistory(24);

    if (!report) {
      return res.json({
        score: null, grade: null, label: 'Unscanned', tone: 'muted',
        blurb: 'Run a scan to compute a posture score.',
        status: 'UNSCANNED', trend: [], bands: [], headline: 'No scan data yet.',
        factors: { positive: [], negative: ['No scan has been run yet'] },
      });
    }

    const kevSet = await getKevSet();
    const remediated = await remediationState();
    const posture = computePosture({
      packages: report.packages,
      counts: report.counts,
      lockfilePresent: !!(report.lockfile && report.lockfile.present),
      logs,
      kevSet,
      remediated,
      ignored: await ignoredSet(),
    });

    const trend = history.length ? [...history].reverse().map(h => h.score) : [posture.score];

    // Flattened evidence, kept for the compact positive/negative lists.
    const factors = { positive: [], negative: [] };
    for (const band of posture.bands) {
      for (const e of band.evidence) {
        if (e.tone === 'good') factors.positive.push(e.text);
        else factors.negative.push(e.text);
      }
    }

    res.json({
      score: posture.score,
      grade: posture.grade,
      label: posture.label,
      tone: posture.tone,
      blurb: posture.blurb,
      headline: posture.headline,
      status: report.status,
      trend,
      bands: posture.bands,
      kevHits: posture.kevHits,
      blockedRuntime: posture.blockedRuntime,
      scanScore: report.score,
      remediation: posture.remediation,
      accepted: posture.accepted,
      factors,
      computedAt: new Date().toISOString(),
    });
  });

  router.get('/dependency-graph', async (req, res) => {
    res.json(buildGraph(getReport(), await remediationState(), await ignoredSet()));
  });

  router.get('/packages/classification', async (req, res) => {
    const q = await db.getQuarantine();
    res.json(classify(getReport(), q));
  });

  router.get('/threat-intel', async (req, res) => {
    res.json(threatIntel(getReport(), await getKevSet(), await remediationState()));
  });

  router.get('/incidents', async (req, res) => {
    const report = getReport();
    const logs = await db.getLogs(200);
    const fromFindings = report
      ? report.findings
          .filter(f => f.severity === 'critical' || f.severity === 'high' || f.type === 'malicious' || f.type === 'typosquat')
          .map((f, i) => ({
            id: `SCA-${String(i + 1).padStart(3, '0')}`,
            kind: 'supply-chain',
            vector: f.type,
            package: `${f.packageName}@${f.packageVersion || '?'}`,
            severity: f.severity,
            identifier: f.identifier,
            title: f.title,
            detail: f.description,
            mitigation: f.fixedVersion ? `Upgrade to ${f.fixedVersion}` : 'No fixed version published',
            direct: !!f.direct,
            at: report.generatedAt,
            stack: null,
          }))
      : [];
    const fromLogs = logs
      .filter(l => l.status === 'BLOCKED')
      .map((l, i) => ({
        id: `RT-${String(i + 1).padStart(3, '0')}`,
        kind: 'runtime',
        vector: l.action,
        package: l.sourcePackage,
        severity: l.severity,
        identifier: null,
        title: l.action,
        detail: l.details,
        mitigation: 'Quarantine owning dependency; rotate exposed tokens',
        at: l.timestamp,
        stack: l.stack || null,
      }));
    res.json([...fromFindings, ...fromLogs]);
  });

  router.get('/threat-prediction', async (req, res) => {
    const report = getReport();
    const history = await db.getPostureHistory(60);
    const forecast = linregForecast(history);
    const packageRisks = report
      ? report.packages
          .filter(p => p.category !== 'safe')
          .slice(0, 8)
          .map(p => ({
            name: p.name,
            version: p.version,
            score: p.riskScore,
            driver: p.findings[0] ? p.findings[0].title : 'elevated risk',
          }))
      : [];
    res.json({ forecast, packageRisks, basis: history.length < 2 ? 'insufficient-history' : 'linear-regression' });
  });

  router.post('/analyze-threat', async (req, res) => {
    const { logId, findingId } = req.body || {};
    try {
      if (findingId) {
        const report = getReport();
        const f = report && report.findings[Number(findingId)];
        if (!f) return res.status(404).json({ error: 'finding not found' });
        return res.json(analyzeFinding(f));
      }
      const logs = await db.getLogs(400);
      const log = logId ? logs.find(l => l.id === logId) : logs[0];
      if (!log) return res.status(404).json({ error: 'log not found' });
      res.json(analyzeLog(log));
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  /* ------------------------------ telemetry ------------------------------ */
  router.get('/telemetry', async (req, res) => {
    res.json(await db.getLogs(Number(req.query.limit) || 200));
  });

  router.post('/telemetry', async (req, res) => {
    try {
      const saved = await db.insertLog(req.body || {});
      ctx.broadcast('NEW_LOG', saved);
      if (saved.status === 'BLOCKED') {
        const report = getReport();
        const logs = await db.getLogs(200);
        await db.addPostureSnapshot(
          liveScore(report ? report.score : 100, logs),
          logs.filter(l => l.status === 'BLOCKED').length, 0, 'runtime'
        );
      }
      res.status(201).json({ success: true, logId: saved.id });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  /* ------------------------------ quarantine ----------------------------- */
  /* ---------------------------- remediation ----------------------------- */
  // Every actionable fix in the current scan, ranked by risk removed.
  router.get('/remediation/plan', async (req, res) => {
    try {
      const plan = remediate.planAll(project.root, getReport());
      const state = await remediationState();
      const ignored = await ignoredSet();
      for (const item of plan.items || []) {
        const st = state.get(item.package);
        item.remediated = !!(st && st.applied);
        item.remediationPending = !!(st && st.pending);
        item.ignored = ignored.has(item.package);
      }
      if (plan.stats) {
        plan.stats.remediated = (plan.items || []).filter(i => i.remediated).length;
        plan.stats.pendingInstall = (plan.items || []).filter(i => i.remediationPending).length;
      }
      res.json(plan);
    } catch (err) {
      res.status(500).json({ available: false, reason: err.message, items: [] });
    }
  });

  // Dry run for one package: exact before/after, no writes.
  router.post('/remediation/preview', (req, res) => {
    const { name, mode, targetVersion } = req.body || {};
    if (!name) return res.status(400).json({ error: 'name is required' });
    try {
      res.json(remediate.planQuarantine(project.root, getReport(), name, { mode, targetVersion }));
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // Writes package.json. Backs up first; the response says how to undo.
  router.post('/remediation/apply', async (req, res) => {
    const { name, mode, targetVersion, reason } = req.body || {};
    if (!name) return res.status(400).json({ error: 'name is required' });
    try {
      const plan = remediate.planQuarantine(project.root, getReport(), name, { mode, targetVersion });
      const result = remediate.applyPlan(project.root, plan);

      await db.addQuarantine({
        name,
        version: plan.installedVersion,
        reason: reason || plan.summary,
        riskScore: null,
      });
      const log = await db.insertLog({
        sourcePackage: name,
        action: result.applied ? 'Package Remediated' : 'Package Quarantined',
        status: 'FLAGGED',
        severity: 'warning',
        callerUrl: 'phishguard://remediation',
        details: plan.summary,
        rule: `remediation strategy: ${plan.strategy}`,
        enforcement: result.applied
          ? `package.json rewritten (backup ${result.backup}) — run ${result.needsInstall}`
          : 'recorded in the quarantine registry; no safe manifest edit available',
      });
      ctx.broadcast('NEW_LOG', log);

      // Recompute posture with the new remediation state and snapshot it, so the
      // score, grade and trend all move immediately instead of waiting for a scan.
      let posture = null;
      try {
        const report = getReport();
        if (report) {
          const logs = await db.getLogs(400);
          posture = computePosture({
            packages: report.packages,
            counts: report.counts,
            lockfilePresent: !!(report.lockfile && report.lockfile.present),
            logs,
            kevSet: await getKevSet(),
            remediated: await remediationState(),
          });
          await db.addPostureSnapshot(
            posture.score,
            report.counts.critical + report.counts.malicious,
            report.counts.warning + report.counts.moderate,
            'remediation'
          );
        }
      } catch { /* snapshot is best-effort */ }

      ctx.broadcast('QUARANTINE', { name, version: plan.installedVersion, plan, result, posture });
      res.json({ success: true, plan, result, posture });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  /* --------------------------- accepted risk ---------------------------- */
  // Marking a package trusted excludes it from scoring. It is never deleted
  // from the scan, so the decision stays visible and can be revoked.
  router.get('/ignore', async (req, res) => {
    try {
      res.json({ ignored: await db.getIgnored() });
    } catch (err) {
      res.status(500).json({ error: err.message, ignored: [] });
    }
  });

  router.post('/ignore', async (req, res) => {
    const { name, version, reason, acknowledged } = req.body || {};
    if (!name) return res.status(400).json({ error: 'name is required' });
    // The client must confirm it asked the trust question first.
    if (acknowledged !== true) {
      return res.status(400).json({ error: 'acknowledged:true is required — confirm you trust this package before ignoring it.' });
    }
    try {
      const saved = await db.addIgnored({ name, version, reason });
      const log = await db.insertLog({
        sourcePackage: name,
        action: 'Package Trusted',
        status: 'ALLOWED',
        severity: 'info',
        callerUrl: 'phishguard://accepted-risk',
        details: `${name}${version ? '@' + version : ''} marked as accepted risk. ${reason || ''}`.trim(),
        rule: 'manual trust decision',
        enforcement: 'excluded from posture scoring; still listed in scans and reports for audit',
      });
      ctx.broadcast('NEW_LOG', log);
      ctx.broadcast('QUARANTINE', { name, ignored: true });
      res.json({ success: true, ignored: saved });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/ignore/release', async (req, res) => {
    const { name } = req.body || {};
    if (!name) return res.status(400).json({ error: 'name is required' });
    try {
      await db.releaseIgnored(name);
      const log = await db.insertLog({
        sourcePackage: name,
        action: 'Trust Revoked',
        status: 'FLAGGED',
        severity: 'warning',
        callerUrl: 'phishguard://accepted-risk',
        details: `${name} is no longer trusted; its advisories count against the score again.`,
        rule: 'manual trust revocation',
        enforcement: 'restored to posture scoring',
      });
      ctx.broadcast('NEW_LOG', log);
      ctx.broadcast('QUARANTINE_RELEASED', { name, ignored: false });
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/remediation/backups', (req, res) => {
    try {
      res.json({ backups: remediate.listBackups(project.root) });
    } catch (err) {
      res.status(500).json({ error: err.message, backups: [] });
    }
  });

  // Dry run: what would a restore actually change?
  router.get('/remediation/restore/preview', (req, res) => {
    try {
      res.json(remediate.previewRestore(project.root, req.query.file));
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  router.post('/remediation/restore', async (req, res) => {
    try {
      const out = remediate.restore(project.root, (req.body || {}).file);
      const log = await db.insertLog({
        sourcePackage: 'phishguard',
        action: 'Manifest Restored',
        status: 'ALLOWED',
        severity: 'info',
        callerUrl: 'phishguard://remediation',
        details: `package.json restored from ${out.restoredFrom}`,
        enforcement: `previous state saved to ${out.savedCurrentTo} — run ${out.needsInstall}`,
      });
      ctx.broadcast('NEW_LOG', log);
      try {
        const report = getReport();
        if (report) {
          const posture = computePosture({
            packages: report.packages,
            counts: report.counts,
            lockfilePresent: !!(report.lockfile && report.lockfile.present),
            logs: await db.getLogs(400),
            kevSet: await getKevSet(),
            remediated: await remediationState(),
          });
          await db.addPostureSnapshot(
            posture.score,
            report.counts.critical + report.counts.malicious,
            report.counts.warning + report.counts.moderate,
            'remediation'
          );
        }
      } catch { /* best-effort */ }
      ctx.broadcast('QUARANTINE_RELEASED', { restored: true });
      res.json({ success: true, ...out });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // Registry-only quarantine (no manifest edit) - kept for the map's soft action.
  router.post('/quarantine', async (req, res) => {
    const { name, version, reason, riskScore } = req.body || {};
    if (!name) return res.status(400).json({ error: 'name is required' });
    try {
      await db.addQuarantine({ name, version, reason, riskScore });
      const log = await db.insertLog({
        sourcePackage: name, action: 'Package Quarantined', status: 'FLAGGED', severity: 'warning',
        callerUrl: 'phishguard://quarantine',
        details: `Quarantine recorded for ${name}${version ? '@' + version : ''}. ${reason || ''}`.trim(),
        rule: 'manual quarantine',
        enforcement: 'recorded in the quarantine registry (registry-only, manifest untouched)',
      });
      ctx.broadcast('NEW_LOG', log);
      ctx.broadcast('QUARANTINE', { name, version });
      res.json({ success: true, note: 'Recorded in the quarantine registry. Use /api/remediation/apply to change package.json.' });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/quarantine/release', async (req, res) => {
    const { name } = req.body || {};
    if (!name) return res.status(400).json({ error: 'name is required' });
    await db.releaseQuarantine(name);
    ctx.broadcast('QUARANTINE_RELEASED', { name });
    res.json({ success: true });
  });

  /* ------------------------ dependency evolution ------------------------- */
  // Which packages the timeline dropdown can offer: everything actually
  // installed, worst-risk first so the interesting ones are at the top.
  router.get('/packages/timeline-index', (req, res) => {
    const report = getReport();
    if (!report) return res.json({ packages: [] });
    const packages = report.packages
      .map(p => ({
        name: p.name,
        version: p.version,
        direct: p.direct,
        dev: p.dev,
        category: p.category,
        riskScore: p.riskScore,
        findingCount: p.findings.length,
      }))
      .sort((a, b) =>
        (b.direct - a.direct) ||
        (b.riskScore - a.riskScore) ||
        a.name.localeCompare(b.name)
      );
    res.json({ packages, total: packages.length });
  });

  router.get('/packages/:scope/:pkg/timeline', async (req, res) => {
    req.params.name = `${req.params.scope}/${req.params.pkg}`;
    return timelineHandler(req, res);
  });

  router.get('/packages/:name/timeline', (req, res) => timelineHandler(req, res));

  async function timelineHandler(req, res) {
    // package names can be scoped (@scope/name) - Express gives us the raw segment
    const name = decodeURIComponent(req.params.name);
    const report = getReport();
    const installed = report
      ? (report.packages.find(p => p.name === name) || {}).version || null
      : null;
    try {
      const data = await getPackageTimeline(project.root, name, installed, {
        offline: config.offline,
        cacheTtlHours: config.cacheTtlHours,
      });
      res.json(data);
    } catch (err) {
      res.status(502).json({ error: err.message, name, available: false, events: [] });
    }
  }

  /* ------------------------ supply-chain provenance ---------------------- */
  // Who can publish into this tree, and can those artifacts be verified?
  router.get('/supply-chain/provenance', async (req, res) => {
    try {
      const data = await analyseProvenance(project.root, getReport(), {
        offline: config.offline,
        cacheTtlHours: 72,
        limit: Math.min(Number(req.query.limit) || 120, 400),
      });
      res.json(data);
    } catch (err) {
      res.status(502).json({ available: false, reason: err.message, packages: [], publishers: [] });
    }
  });

  /* --------------------------- global OSINT intel ------------------------ */
  router.get('/global-intel', async (req, res) => {
    try {
      const data = await getGlobalIntel(project.root, getReport(), {
        offline: config.offline,
        ttlHours: Number(req.query.ttlHours) || 6,
        limit: Math.min(Number(req.query.limit) || 120, 300),
      });
      res.json(data);
    } catch (err) {
      res.status(502).json({ error: err.message, items: [], sources: [], degraded: true });
    }
  });

  /* ------------------------------ auto-scan ------------------------------ */
  router.get('/autoscan', async (req, res) => {
    res.json(await autoscan.get());
  });

  router.post('/autoscan', async (req, res) => {
    const { enabled, intervalMinutes } = req.body || {};
    try {
      const state = await autoscan.set({ enabled, intervalMinutes });
      ctx.broadcast('AUTOSCAN', state);
      res.json(state);
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  /* --------------------------- forensics report -------------------------- */
  router.get('/forensics/report', async (req, res) => {
    const win = String(req.query.window || '7d');
    const format = String(req.query.format || 'json').toLowerCase();
    let since;
    try {
      since = windowToIso(win);
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
    const report = getReport();

    const [scans, logs, snapshots] = await Promise.all([
      db.listScansSince(since),
      db.getLogsSince(since),
      db.getPostureHistorySince(since),
    ]);
    const quarantine = await db.getQuarantine();
    const kevSet = await getKevSet();

    const findings = report
      ? report.findings.map(f => ({
          package: f.packageName,
          version: f.packageVersion,
          direct: !!f.direct,
          type: f.type,
          severity: f.severity,
          identifier: f.identifier,
          title: f.title,
          fixedVersion: f.fixedVersion,
          knownExploited: !!(f.identifier && kevSet.has(String(f.identifier).toUpperCase())),
          url: f.url,
        }))
      : [];

    const bundle = {
      generatedAt: new Date().toISOString(),
      window: win,
      windowStart: since,
      project: {
        name: (report && report.project.name) || project.name,
        version: (report && report.project.version) || project.version,
        root: project.root,
        lockfile: report ? report.lockfile : null,
      },
      posture: report
        ? { score: report.score, grade: report.grade, status: report.status, counts: report.counts }
        : null,
      summary: {
        scansInWindow: scans.length,
        runtimeEvents: logs.length,
        blockedEvents: logs.filter(l => l.status === 'BLOCKED').length,
        findingsInLatestScan: findings.length,
        knownExploited: findings.filter(f => f.knownExploited).length,
        quarantined: quarantine.length,
      },
      scans, findings, runtimeEvents: logs, postureSnapshots: snapshots, quarantine,
    };

    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    const base = `phishguard-${(bundle.project.name || 'repo').replace(/[^a-z0-9_-]/gi, '_')}-${win}-${stamp}`;

    if (format === 'csv') {
      const rows = [
        ['section', 'timestamp', 'severity', 'subject', 'identifier', 'title', 'detail'],
        ...findings.map(f => ['finding', bundle.generatedAt, f.severity, `${f.package}@${f.version || '?'}`,
          f.identifier || '', (f.title || '').replace(/"/g, "'"), f.fixedVersion ? `fix:${f.fixedVersion}` : 'no fix']),
        ...logs.map(l => [`runtime:${l.origin || 'system'}`, l.timestamp, l.severity, l.sourcePackage, '',
          (l.action || '').replace(/"/g, "'"), (l.details || '').replace(/"/g, "'")]),
        ...scans.map(s => ['scan', s.ran_at, s.status, s.project_name, s.id,
          `score ${s.score} (${s.grade})`, `${s.total_packages} packages, ${s.vulnerable_count} vulnerable`]),
      ];
      const csv = rows.map(r => r.map(c => `"${String(c ?? '')}"`).join(',')).join('\n');
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${base}.csv"`);
      return res.send(csv);
    }

    if (format === 'md' || format === 'markdown') {
      const md = renderMarkdownReport(bundle);
      res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${base}.md"`);
      return res.send(md);
    }

    if (format === 'html') {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${base}.html"`);
      return res.send(renderHtmlReport(bundle));
    }

    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    if (req.query.download === '1') {
      res.setHeader('Content-Disposition', `attachment; filename="${base}.json"`);
    }
    res.json(bundle);
  });

  /* --------------------------- sandbox scenarios ------------------------- */
  router.get('/sandbox/scenarios', async (req, res) => {
    const report = getReport();
    const kevSet = await getKevSet();
    if (!report) return res.json({ scenarios: [], demos: demoScenarios(), project: project.name });

    const byName = new Map(report.packages.map(p => [p.name, p]));
    const projectName = (report.project && report.project.name) || project.name;
    const seen = new Set();
    const scenarios = [];

    const ordered = [...report.findings].sort((a, b) => {
      const kevA = a.identifier && kevSet.has(String(a.identifier).toUpperCase()) ? 1 : 0;
      const kevB = b.identifier && kevSet.has(String(b.identifier).toUpperCase()) ? 1 : 0;
      if (kevA !== kevB) return kevB - kevA;
      if (!!a.direct !== !!b.direct) return a.direct ? -1 : 1;
      return severityRank(b.severity) - severityRank(a.severity);
    });

    for (const f of ordered) {
      if (f.type === 'unresolved') continue;
      const key = `${f.packageName}:${f.identifier || f.type}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const pkg = byName.get(f.packageName);
      const impact = modelImpact(f, pkg, kevSet);
      const tree = buildAttackTree(f, pkg, byName, { projectName, kevSet });
      scenarios.push({
        id: `SC-${scenarios.length + 1}`,
        package: f.packageName,
        version: f.packageVersion,
        direct: !!f.direct,
        depth: pkg ? pkg.depth : null,
        kind: f.type,
        severity: f.severity,
        identifier: f.identifier,
        title: f.title,
        description: f.description,
        fixedVersion: f.fixedVersion,
        url: f.url,
        cwes: f.cwes || [],
        impact,
        tree,
      });
      if (scenarios.length >= 40) break;
    }

    res.json({
      project: project.name,
      scannedAt: report.generatedAt,
      counts: {
        total: scenarios.length,
        critical: scenarios.filter(s => s.severity === 'critical').length,
        high: scenarios.filter(s => s.severity === 'high').length,
        moderate: scenarios.filter(s => s.severity === 'moderate').length,
        low: scenarios.filter(s => s.severity === 'low').length,
        knownExploited: scenarios.filter(s => s.impact.knownExploited).length,
      },
      scenarios,
      demos: demoScenarios(),
    });
  });

  // Fires a Node-agent demo (network/process/fs) in a disposable child
  // process, never on the hub's own long-running process - installing the
  // real shields here would risk the hub's own OSV/npm-registry calls or
  // scanner subprocess use being caught by the demo's own block list.
  router.post('/sandbox/node-demo', (req, res) => {
    const { vector } = req.body || {};
    if (!['network', 'process', 'fs'].includes(vector)) {
      return res.status(400).json({ error: 'vector must be one of: network, process, fs' });
    }
    const runner = path.join(packageRoot(), 'agent', 'node', '__demoFixtures__', 'runner.js');
    const hubUrl = `http://localhost:${port || config.port || 4173}`;
    try {
      const child = spawn(process.execPath, [runner, vector, hubUrl], { stdio: 'ignore', detached: true });
      child.unref();
      res.json({ dispatched: true, vector });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  /* ------------------------------ db explorer --------------------------- */
  router.get('/db-stats', async (req, res) => {
    res.json(await db.getStats());
  });

  router.get('/db/table/:name', async (req, res) => {
    try {
      res.json(await db.getTableRows(req.params.name, Number(req.query.limit) || 200));
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  router.post('/db/query', async (req, res) => {
    const { sql } = req.body || {};
    if (!sql) return res.status(400).json({ error: 'sql is required' });
    try {
      res.json(await db.runReadOnlyQuery(sql));
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  return router;
}

module.exports = { createApi };
