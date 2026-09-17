/**
 * The PhishGuard SOC hub: Express REST API + WebSocket telemetry stream +
 * static hosting for the built dashboard. One instance is bound to one target
 * repository.
 */

const http = require('http');
const path = require('path');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const { WebSocketServer } = require('ws');

const { resolveTargetRoot, packageRoot } = require('../util/paths');
const { loadConfig } = require('../util/config');
const { scanProject } = require('../core/scanner');
const remediate = require('../core/remediate');
const { computePosture } = require('../core/score');
const { fetchKevIdSet } = require('../core/intel');
const dbLayer = require('./db');
const { createApi } = require('./api');

const DASHBOARD_DIST = path.join(packageRoot(), 'dashboard', 'dist');

function fallbackPage(project, report) {
  const rows = report
    ? report.findings.slice(0, 40).map(f =>
        `<tr><td>${f.severity}</td><td>${f.packageName}@${f.packageVersion || '?'}</td><td>${f.identifier || f.type}</td><td>${(f.title || '').replace(/</g, '&lt;')}</td></tr>`
      ).join('')
    : '<tr><td colspan="4">No scan yet - POST /api/scan/run</td></tr>';
  return `<!doctype html><meta charset="utf8"><title>PhishGuard - ${project.name}</title>
  <style>body{font:14px system-ui;margin:2rem;background:#0a0e17;color:#e2e8f0}
  h1{font-size:1.1rem}table{border-collapse:collapse;width:100%;margin-top:1rem}
  td,th{border:1px solid #242b3d;padding:.4rem .6rem;text-align:left;font-size:12px}
  .s{color:#94a3b8}code{background:#161b26;padding:.1rem .3rem;border-radius:4px}</style>
  <h1>&#128737; PhishGuard &mdash; ${project.name} <span class="s">${project.version || ''}</span></h1>
  <p class="s">The built dashboard UI was not found at <code>dashboard/dist</code>. This is the raw API fallback.
  Run <code>npm run build:dashboard</code> in the phishguard package to get the full SOC console.</p>
  <p>Score: <b>${report ? report.score + '/100 (' + report.grade + ')' : 'n/a'}</b> &nbsp; Status: <b>${report ? report.status : 'UNSCANNED'}</b>
  &nbsp; Packages: <b>${report ? report.counts.total : 0}</b></p>
  <table><thead><tr><th>Severity</th><th>Package</th><th>ID</th><th>Title</th></tr></thead><tbody>${rows}</tbody></table>`;
}

/**
 * @param {object} opts { cwd, port, scanOnStart=true, onLog, silent }
 * @returns {Promise<{ url, port, root, stop, runScan, getReport }>}
 */
async function startServer(opts = {}) {
  const root = resolveTargetRoot(opts.cwd);
  const config = loadConfig(root);
  const port = opts.port || config.port || 4173;
  const log = opts.silent ? () => {} : (...a) => console.log('[phishguard]', ...a);

  const db = dbLayer.open(root);
  await db.init();

  // load the most recent persisted scan as the starting report
  let report = await db.getLatestScan();

  const app = express();
  app.use(cors());
  app.use(express.json({ limit: '2mb' }));

  const server = http.createServer(app);
  const wss = new WebSocketServer({ server });
  const clients = new Set();

  function broadcast(type, data) {
    const msg = JSON.stringify({ type, data });
    for (const ws of clients) {
      if (ws.readyState === ws.OPEN) ws.send(msg);
    }
  }

  wss.on('connection', async (ws) => {
    clients.add(ws);
    try {
      ws.send(JSON.stringify({ type: 'SEEDED_LOGS', data: await db.getLogs(200) }));
      if (report) ws.send(JSON.stringify({ type: 'SCAN_COMPLETE', data: scanSummary(report) }));
    } catch { /* ignore */ }

    ws.on('message', async (raw) => {
      // Runtime agents (interceptor.js / domShield.js) push telemetry here.
      try {
        const p = JSON.parse(raw);
        const saved = await db.insertLog({
          sourcePackage: p.callerContext || p.sourcePackage,
          callerUrl: p.target || p.callerUrl,
          action: p.action,
          details: p.details || (p.target ? `Target: ${p.target}${p.latencyMs != null ? ` [${p.latencyMs}ms]` : ''}` : ''),
          status: p.status,
          severity: p.severity,
          stack: p.stack,
          rule: p.rule,
          enforcement: p.enforcement,
          latencyMs: p.latencyMs,
          stackFrames: p.stackFrames,
        });
        broadcast('NEW_LOG', saved);
        if (opts.onLog) opts.onLog(saved);
      } catch { /* ignore malformed frames */ }
    });

    ws.on('close', () => clients.delete(ws));
  });

  let inFlightScan = null;

  async function runScan(scanOpts = {}) {
    // Single-flight: a manual re-scan fired while the scheduler is mid-scan used
    // to run a second pass concurrently, and whichever finished last overwrote
    // the other. Callers now share the running scan.
    if (inFlightScan) return inFlightScan;
    inFlightScan = doScan(scanOpts).finally(() => { inFlightScan = null; });
    return inFlightScan;
  }

  async function doScan(scanOpts = {}) {
    broadcast('SCAN_STARTED', { at: new Date().toISOString() });
    // CISA KEV drives the exploitability band; a failure here just means that
    // band scores on severity alone.
    let kevSet = null;
    try { kevSet = await fetchKevIdSet(root, { offline: config.offline }); } catch { /* optional */ }

    const fresh = await scanProject(root, {
      includeDev: config.includeDev,
      offline: config.offline,
      cacheTtlHours: config.cacheTtlHours,
      kevSet,
      onProgress: (e) => broadcast('SCAN_PROGRESS', e),
      ...scanOpts,
    });

    // Re-score the fresh report with the exact same inputs /api/security-score
    // uses - runtime telemetry, remediation state resolved against THIS scan,
    // and the accepted-risk list. Doing it here (rather than inside the scan)
    // means the stored score and the live gauge are the same number by
    // construction, not by coincidence.
    try {
      const logs = await db.getLogs(400);
      const remediated = remediate.resolveRemediationState(root, fresh, await db.getQuarantine());
      const ignored = new Set((await db.getIgnored()).map(r => r.name));
      const posture = computePosture({
        packages: fresh.packages,
        counts: fresh.counts,
        lockfilePresent: !!(fresh.lockfile && fresh.lockfile.present),
        logs, kevSet, remediated, ignored,
      });
      fresh.score = posture.score;
      fresh.grade = posture.grade;
      fresh.postureLabel = posture.label;
      fresh.postureTone = posture.tone;
      fresh.postureBands = posture.bands;
      fresh.postureHeadline = posture.headline;
      fresh.postureRemediation = posture.remediation;
      fresh.postureAccepted = posture.accepted;
    } catch (err) {
      log('posture re-score skipped:', err.message);
    }
    await db.insertScan(fresh);

    // Trim history so the per-repo database does not grow without bound.
    try {
      const removed = await db.prune();
      if (removed.scans) {
        log(`pruned ${removed.scans} old scan(s), ${removed.packages} package rows, ${removed.findings} findings`);
      }
      // DELETE only marks pages free; the file keeps its size until a VACUUM.
      // Vacuuming on every scan would be wasteful, so only do it once the free
      // list is worth reclaiming (~20MB).
      const free = await db.get('PRAGMA freelist_count');
      const pageRow = await db.get('PRAGMA page_size');
      const freeBytes = (free?.freelist_count || 0) * (pageRow?.page_size || 4096);
      if (freeBytes > 8 * 1024 * 1024) {
        await db.vacuum();
        log(`vacuumed ~${Math.round(freeBytes / 1048576)}MB of reclaimable space`);
      }
    } catch (err) {
      log('prune skipped:', err.message);
    }

    report = fresh;
    broadcast('SCAN_COMPLETE', scanSummary(fresh));
    return fresh;
  }

  /* ----------------------------- auto-scan ------------------------------ */
  // Allowed cadences, in minutes. Kept server-side so the UI dropdown and the
  // scheduler can never disagree.
  const AUTOSCAN_INTERVALS = [15, 30, 60, 180, 360, 720, 1440];
  let autoscanTimer = null;
  let autoscanState = { enabled: false, intervalMinutes: 60, lastRunAt: null, nextRunAt: null, running: false };

  function clearAutoscan() {
    if (autoscanTimer) { clearInterval(autoscanTimer); autoscanTimer = null; }
    autoscanState.nextRunAt = null;
  }

  function scheduleAutoscan() {
    clearAutoscan();
    if (!autoscanState.enabled) return;
    const ms = autoscanState.intervalMinutes * 60 * 1000;
    autoscanState.nextRunAt = new Date(Date.now() + ms).toISOString();
    autoscanTimer = setInterval(async () => {
      if (autoscanState.running) return;         // never overlap scans
      autoscanState.running = true;
      broadcast('AUTOSCAN', { ...autoscanState });
      try {
        await runScan();
        autoscanState.lastRunAt = new Date().toISOString();
      } catch (err) {
        log('auto-scan failed:', err.message);
      } finally {
        autoscanState.running = false;
        autoscanState.nextRunAt = new Date(Date.now() + ms).toISOString();
        broadcast('AUTOSCAN', { ...autoscanState });
      }
    }, ms);
    if (autoscanTimer.unref) autoscanTimer.unref();
  }

  const autoscan = {
    intervals: AUTOSCAN_INTERVALS,
    async get() {
      return { ...autoscanState, intervals: AUTOSCAN_INTERVALS };
    },
    async set({ enabled, intervalMinutes }) {
      if (intervalMinutes != null) {
        const n = Number(intervalMinutes);
        if (!AUTOSCAN_INTERVALS.includes(n)) {
          throw new Error(`intervalMinutes must be one of: ${AUTOSCAN_INTERVALS.join(', ')}`);
        }
        autoscanState.intervalMinutes = n;
      }
      if (enabled != null) autoscanState.enabled = !!enabled;
      await db.setSetting('autoscan', {
        enabled: autoscanState.enabled, intervalMinutes: autoscanState.intervalMinutes,
      });
      scheduleAutoscan();
      return { ...autoscanState, intervals: AUTOSCAN_INTERVALS };
    },
  };

  // restore persisted schedule
  try {
    const saved = await db.getSetting('autoscan', null);
    if (saved && typeof saved === 'object') {
      autoscanState.enabled = !!saved.enabled;
      if (AUTOSCAN_INTERVALS.includes(Number(saved.intervalMinutes))) {
        autoscanState.intervalMinutes = Number(saved.intervalMinutes);
      }
      scheduleAutoscan();
      if (autoscanState.enabled) log(`auto-scan enabled: every ${autoscanState.intervalMinutes} min`);
    }
  } catch { /* settings table is best-effort */ }

  app.use('/api', createApi({
    db, config, broadcast, autoscan,
    project: { name: (report && report.project.name) || path.basename(root), version: report && report.project.version, root },
    getReport: () => report,
    runScan,
  }));

  // static dashboard (built) or fallback
  const hasDist = fs.existsSync(path.join(DASHBOARD_DIST, 'index.html'));
  if (hasDist) {
    app.use(express.static(DASHBOARD_DIST));
    app.get(/^\/(?!api\/).*/, (req, res) => res.sendFile(path.join(DASHBOARD_DIST, 'index.html')));
  } else {
    app.get('/', (req, res) => res.type('html').send(fallbackPage(
      { name: (report && report.project.name) || path.basename(root), version: report && report.project.version },
      report
    )));
  }

  await new Promise((resolve) => server.listen(port, resolve));
  const url = `http://localhost:${port}`;
  log(`SOC hub for "${path.basename(root)}" -> ${url}`);
  log(`data: ${db.file}`);
  if (!hasDist) log('dashboard/dist not built - serving API + fallback page only');

  if (opts.scanOnStart !== false) {
    runScan().catch(err => log('initial scan failed:', err.message));
  }

  return {
    url, port, root,
    getReport: () => report,
    runScan,
    stop: () => new Promise((resolve) => {
      clearAutoscan();
      for (const ws of clients) ws.close();
      wss.close(() => server.close(() => db.close().then(resolve)));
    }),
  };
}

function scanSummary(r) {
  return {
    at: r.generatedAt, score: r.score, grade: r.grade, status: r.status,
    counts: r.counts, project: r.project, lockfile: r.lockfile,
  };
}

module.exports = { startServer };
