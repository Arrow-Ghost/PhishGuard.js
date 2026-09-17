#!/usr/bin/env node
/**
 * phishguard CLI
 *
 *   phishguard scan       [--json] [--offline] [--no-dev] [--fail-on <level>] [--no-save] [--cwd <dir>]
 *   phishguard dashboard  [--port <n>] [--no-open] [--no-scan] [--cwd <dir>]
 *   phishguard init       [--cwd <dir>]
 *   phishguard --help | --version
 */

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const pkg = require('../package.json');
const { resolveTargetRoot } = require('../src/util/paths');
const { loadConfig, DEFAULTS } = require('../src/util/config');

const C = {
  reset: '\x1b[0m', dim: '\x1b[2m', bold: '\x1b[1m',
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', blue: '\x1b[34m', cyan: '\x1b[36m', grey: '\x1b[90m',
};
const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (col, s) => (useColor ? col + s + C.reset : s);

/* --------------------------------- args --------------------------------- */
function parseArgs(argv) {
  const out = { _: [], flags: {} };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      if (key.startsWith('no-')) { out.flags[key.slice(3)] = false; continue; }
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) { out.flags[key] = next; i++; }
      else out.flags[key] = true;
    } else {
      out._.push(a);
    }
  }
  return out;
}

const SEV_ORDER = { none: 0, low: 1, warning: 2, moderate: 2, high: 3, critical: 4 };

function sevColor(s) {
  return s === 'critical' ? C.red : s === 'high' ? C.yellow : s === 'moderate' ? C.yellow : C.grey;
}

/* -------------------------------- output -------------------------------- */
function printReport(report) {
  const { counts: n } = report;
  console.log('');
  console.log(c(C.bold, `  ${report.project.name} ${c(C.grey, report.project.version || '')}`));
  console.log(c(C.grey, `  ${report.lockfile.source}  •  ${n.total} packages (${n.direct} direct, ${n.transitive} transitive)  •  ${report.durationMs}ms`));
  if (report.offline) console.log(c(C.yellow, '  ⚠ offline / degraded data - results may be incomplete'));
  console.log('');

  const gradeCol = report.score >= 80 ? C.green : report.score >= 55 ? C.yellow : C.red;
  console.log(`  ${c(C.bold, 'Posture')}  ${c(gradeCol, `${report.score}/100  grade ${report.grade}`)}${report.postureLabel ? c(C.grey, ` (${report.postureLabel})`) : ''}   ${c(gradeCol, report.status)}`);
  const bands = report.postureBands || report.bands;
  if (Array.isArray(bands)) {
    for (const b of bands) {
      const col = b.score >= 85 ? C.green : b.score >= 55 ? C.yellow : C.red;
      console.log(`      ${c(C.grey, b.label.padEnd(22))} ${c(col, String(b.score).padStart(3))}${c(C.grey, '/100')}  ${c(C.grey, `w=${Math.round(b.weight * 100)}%`)}`);
    }
  }
  console.log('');

  const line = (label, val, col) => console.log(`  ${col(String(val).padStart(4))}  ${label}`);
  line('critical vulnerabilities', n.critical, n.critical ? (s => c(C.red, s)) : (s => c(C.grey, s)));
  line('high vulnerabilities', n.high, n.high ? (s => c(C.yellow, s)) : (s => c(C.grey, s)));
  line('moderate vulnerabilities', n.moderate, s => c(C.grey, s));
  line('low vulnerabilities', n.low, s => c(C.grey, s));
  line('deprecated packages', n.deprecated, n.deprecated ? (s => c(C.yellow, s)) : (s => c(C.grey, s)));
  line('typosquat suspects', n.typosquat, n.typosquat ? (s => c(C.red, s)) : (s => c(C.grey, s)));
  line('known-malicious packages', n.malicious, n.malicious ? (s => c(C.red, s)) : (s => c(C.grey, s)));
  console.log('');

  const shown = report.packages.filter(p => p.category !== 'safe').slice(0, 25);
  if (shown.length) {
    console.log(c(C.bold, '  Findings'));
    for (const p of shown) {
      const tag = p.direct ? c(C.blue, 'direct') : c(C.grey, `depth ${p.depth}`);
      console.log(`  ${c(sevColor(p.category === 'critical' ? 'critical' : 'high'), '●')} ${c(C.bold, p.name)}@${p.version || p.range} ${c(C.grey, `(risk ${p.riskScore}, ${tag})`)}`);
      for (const f of p.findings) {
        const fix = f.fixedVersion ? c(C.green, `  → fix: ${f.fixedVersion}`) : '';
        console.log(`      ${c(sevColor(f.severity), f.severity.toUpperCase().padEnd(8))} ${f.identifier ? c(C.cyan, f.identifier + ' ') : ''}${f.title}${fix}`);
      }
    }
    if (report.packages.filter(p => p.category !== 'safe').length > shown.length) {
      console.log(c(C.grey, `  … and ${report.packages.filter(p => p.category !== 'safe').length - shown.length} more`));
    }
  } else {
    console.log(c(C.green, '  No advisories, deprecations or typosquat suspects found.'));
  }
  console.log('');
}

/* -------------------------------- scan --------------------------------- */
async function cmdScan(flags) {
  const { scanProject } = require('../src/core/scanner');
  const root = resolveTargetRoot(flags.cwd);
  const config = loadConfig(root);
  const failOn = flags['fail-on'] || config.failOn;

  const showProgress = !flags.json && process.stderr.isTTY;
  const report = await scanProject(root, {
    includeDev: flags.dev === false ? false : config.includeDev,
    offline: flags.offline === true || config.offline,
    cacheTtlHours: config.cacheTtlHours,
    onProgress: (e) => {
      if (!showProgress) return;
      if (e.done && e.total) process.stderr.write(`\r  ${c(C.grey, `${e.phase}… ${e.done}/${e.total}`)}   `);
      else if (e.message) process.stderr.write(`\r  ${c(C.grey, e.message)}`.padEnd(60));
    },
  });
  if (showProgress) process.stderr.write('\r' + ' '.repeat(64) + '\r');

  let saved = false;
  if (flags.save !== false) {
    try {
      const db = require('../src/server/db').open(root);
      await db.init();

      // Re-score with the same inputs the dashboard uses (runtime telemetry,
      // remediation state, accepted risk) so `phishguard scan` and the SOC
      // gauge never report different numbers for the same repo.
      try {
        const { computePosture } = require('../src/core/score');
        const remediate = require('../src/core/remediate');
        const { fetchKevIdSet } = require('../src/core/intel');
        const logs = await db.getLogs(400);
        const remediated = remediate.resolveRemediationState(root, report, await db.getQuarantine());
        const ignored = new Set((await db.getIgnored()).map(r => r.name));
        // KEV drives the exploitability band; the server passes it too, so the
        // CLI must as well or the two would score the same repo differently.
        let kevSet = null;
        try { kevSet = await fetchKevIdSet(root, { offline: flags.offline === true || config.offline }); } catch { /* optional */ }
        const posture = computePosture({
          packages: report.packages,
          counts: report.counts,
          lockfilePresent: !!(report.lockfile && report.lockfile.present),
          logs, remediated, ignored, kevSet,
        });
        report.score = posture.score;
        report.grade = posture.grade;
        report.postureLabel = posture.label;
        report.postureBands = posture.bands;
        report.postureRemediation = posture.remediation;
        report.postureAccepted = posture.accepted;
      } catch { /* fall back to the scan-only score */ }

      await db.insertScan(report);
      await db.close();
      saved = true;
    } catch (err) {
      if (!flags.json) console.error(c(C.yellow, `  (could not persist scan history: ${err.message})`));
    }
  }

  if (flags.json) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    printReport(report);
    if (saved) console.log(c(C.grey, `  history saved to ${path.join(root, '.phishguard', 'phishguard.db')}`));
    console.log(c(C.grey, `  run  phishguard dashboard  for the full SOC console`));
    console.log('');
  }

  const threshold = SEV_ORDER[failOn] ?? SEV_ORDER.critical;
  if (failOn === 'none') return 0;
  const worst = Math.max(
    report.counts.malicious ? SEV_ORDER.critical : 0,
    report.counts.typosquat ? SEV_ORDER.critical : 0,
    report.counts.critical ? SEV_ORDER.critical : 0,
    report.counts.high ? SEV_ORDER.high : 0,
    report.counts.moderate ? SEV_ORDER.moderate : 0,
    report.counts.deprecated ? SEV_ORDER.warning : 0,
    report.counts.low ? SEV_ORDER.low : 0,
  );
  if (worst >= threshold) {
    if (!flags.json) console.error(c(C.red, `  ✗ findings at or above "${failOn}" — exiting 1`));
    return 1;
  }
  if (!flags.json) console.log(c(C.green, `  ✓ no findings at or above "${failOn}"`));
  return 0;
}

/* ------------------------------ dashboard ----------------------------- */
async function cmdDashboard(flags) {
  const { startServer } = require('../src/server/server');
  const portArg = Number(flags.port);
  const handle = await startServer({
    cwd: flags.cwd,
    port: Number.isInteger(portArg) && portArg > 0 && portArg < 65536 ? portArg : undefined,
    scanOnStart: flags.scan !== false,
  });
  console.log('');
  console.log(c(C.green, `  PhishGuard SOC  ${c(C.bold, handle.url)}`));
  console.log(c(C.grey, `  watching: ${handle.root}`));
  console.log(c(C.grey, `  press Ctrl+C to stop`));
  console.log('');

  if (flags.open !== false) openBrowser(handle.url);

  const shutdown = async () => {
    console.log('\n' + c(C.grey, '  shutting down…'));
    await handle.stop();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

function openBrowser(url) {
  const cmd = process.platform === 'win32' ? 'cmd' : process.platform === 'darwin' ? 'open' : 'xdg-open';
  const args = process.platform === 'win32' ? ['/c', 'start', '""', url] : [url];
  try { spawn(cmd, args, { stdio: 'ignore', detached: true }).unref(); } catch { /* ignore */ }
}

/* -------------------------------- init -------------------------------- */
function cmdInit(flags) {
  const root = resolveTargetRoot(flags.cwd);
  const cfgPath = path.join(root, 'phishguard.config.json');
  if (fs.existsSync(cfgPath)) {
    console.log(c(C.yellow, `  phishguard.config.json already exists at ${cfgPath}`));
  } else {
    fs.writeFileSync(cfgPath, JSON.stringify(DEFAULTS, null, 2) + '\n');
    console.log(c(C.green, `  wrote ${cfgPath}`));
  }

  const gi = path.join(root, '.gitignore');
  const entry = '.phishguard/';
  let giText = fs.existsSync(gi) ? fs.readFileSync(gi, 'utf8') : '';
  if (!giText.split(/\r?\n/).includes(entry)) {
    fs.writeFileSync(gi, giText + (giText && !giText.endsWith('\n') ? '\n' : '') + entry + '\n');
    console.log(c(C.green, `  added "${entry}" to .gitignore`));
  }

  console.log('');
  console.log(c(C.bold, '  Next steps'));
  console.log(`    ${c(C.cyan, 'npx phishguard scan')}        one-off / CI dependency scan`);
  console.log(`    ${c(C.cyan, 'npx phishguard dashboard')}   live SOC dashboard for this repo`);
  console.log('');
  console.log(c(C.grey, '  Optional runtime agent (browser apps): import at the top of your entry file,'));
  console.log(c(C.grey, '  before anything else, to stream live network/DOM telemetry to the dashboard:'));
  console.log(c(C.grey, "    import 'phishguard/agent';"));
  console.log('');
}

/* -------------------------------- help -------------------------------- */
function help() {
  console.log(`
  ${c(C.bold, 'phishguard')} ${c(C.grey, 'v' + pkg.version)} — zero-trust dependency & supply-chain scanner

  ${c(C.bold, 'Usage')}
    phishguard <command> [options]

  ${c(C.bold, 'Commands')}
    scan          Scan this repo's dependencies against live OSV advisories,
                  typosquatting heuristics and npm deprecation flags.
    dashboard     Start the self-hosted SOC dashboard + telemetry hub for this repo.
    init          Create phishguard.config.json and print setup steps.

  ${c(C.bold, 'scan options')}
    --json            Emit the full report as JSON (no pretty output).
    --offline         Use only bundled advisory data (no network).
    --no-dev          Exclude devDependencies.
    --fail-on <lvl>   Exit 1 when a finding at/above <lvl> exists.
                      lvl = critical | high | moderate | warning | none  (default: critical)
    --no-save         Don't append this scan to .phishguard history.
    --cwd <dir>       Target a different project directory.

  ${c(C.bold, 'dashboard options')}
    --port <n>        HTTP/WebSocket port (default: 4173 or config).
    --no-open         Don't open a browser.
    --no-scan         Don't run a scan on startup (use last saved scan).
    --cwd <dir>       Target a different project directory.

  ${c(C.grey, 'Data is stored per-repo in .phishguard/  (add it to .gitignore, or run `phishguard init`).')}
`);
}

/* -------------------------------- main -------------------------------- */
(async () => {
  const { _, flags } = parseArgs(process.argv.slice(2));
  const cmd = _[0];

  if (flags.version || cmd === 'version') { console.log(pkg.version); return; }
  if (!cmd || flags.help || cmd === 'help') { help(); return; }

  try {
    if (cmd === 'scan') {
      // set exitCode (don't process.exit) so piped stdout flushes fully
      process.exitCode = await cmdScan(flags);
    } else if (cmd === 'dashboard' || cmd === 'dash') {
      await cmdDashboard(flags);
    } else if (cmd === 'init') {
      cmdInit(flags);
    } else {
      console.error(c(C.red, `  unknown command: ${cmd}`));
      help();
      process.exitCode = 2;
    }
  } catch (err) {
    console.error('\n' + c(C.red, `  error: ${err.message}`));
    if (process.env.PHISHGUARD_DEBUG) console.error(err.stack);
    process.exitCode = 1;
  }
})();
