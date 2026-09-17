/**
 * Per-project persistence (SQLite).
 *
 * The database lives at `<targetРrepo>/.phishguard/phishguard.db` so a single
 * PhishGuard install can track many repos independently and the history travels
 * with the repo. No demo data is ever seeded - the tables start empty and fill
 * from real scans + runtime telemetry.
 */

const sqlite3 = require('sqlite3');
const crypto = require('crypto');
const { dbPath } = require('../util/paths');

function open(root) {
  const file = dbPath(root);
  const db = new sqlite3.Database(file);
  const run = (sql, params = []) =>
    new Promise((res, rej) => db.run(sql, params, function (e) { e ? rej(e) : res(this); }));
  const all = (sql, params = []) =>
    new Promise((res, rej) => db.all(sql, params, (e, rows) => (e ? rej(e) : res(rows))));
  const get = (sql, params = []) =>
    new Promise((res, rej) => db.get(sql, params, (e, row) => (e ? rej(e) : res(row))));

  const api = {
    file,
    _db: db,
    run, all, get,
    close: () => new Promise((res) => db.close(() => res())),
  };

  Object.assign(api, buildApi(api));
  return api;
}

async function init(db) {
  await db.run(`PRAGMA journal_mode = WAL;`);
  await db.run(`PRAGMA busy_timeout = 5000;`);
  await db.run(`
    CREATE TABLE IF NOT EXISTS scans (
      id             TEXT PRIMARY KEY,
      ran_at         TEXT NOT NULL,
      project_name   TEXT NOT NULL,
      project_version TEXT,
      manifest_hash  TEXT,
      lockfile       TEXT,
      offline        INTEGER NOT NULL DEFAULT 0,
      total_packages INTEGER NOT NULL,
      direct_count   INTEGER NOT NULL,
      vulnerable_count INTEGER NOT NULL,
      critical_count INTEGER NOT NULL,
      high_count     INTEGER NOT NULL,
      moderate_count INTEGER NOT NULL,
      low_count      INTEGER NOT NULL,
      deprecated_count INTEGER NOT NULL,
      typosquat_count INTEGER NOT NULL,
      score          INTEGER NOT NULL,
      grade          TEXT NOT NULL,
      status         TEXT NOT NULL,
      duration_ms    INTEGER,
      report_json    TEXT NOT NULL
    );
  `);
  await db.run(`CREATE INDEX IF NOT EXISTS idx_scans_ran_at ON scans(ran_at);`);

  await db.run(`
    CREATE TABLE IF NOT EXISTS scan_packages (
      id           TEXT PRIMARY KEY,
      scan_id      TEXT NOT NULL,
      name         TEXT NOT NULL,
      version      TEXT,
      is_direct    INTEGER NOT NULL,
      is_dev       INTEGER NOT NULL,
      depth        INTEGER,
      risk_score   INTEGER NOT NULL,
      category     TEXT NOT NULL,
      FOREIGN KEY (scan_id) REFERENCES scans(id)
    );
  `);
  await db.run(`CREATE INDEX IF NOT EXISTS idx_pkgs_scan ON scan_packages(scan_id);`);
  await db.run(`CREATE INDEX IF NOT EXISTS idx_pkgs_cat ON scan_packages(category);`);

  await db.run(`
    CREATE TABLE IF NOT EXISTS scan_findings (
      id            TEXT PRIMARY KEY,
      scan_id       TEXT NOT NULL,
      package_name  TEXT NOT NULL,
      package_version TEXT,
      is_direct     INTEGER NOT NULL,
      type          TEXT NOT NULL,
      severity      TEXT NOT NULL,
      identifier    TEXT,
      title         TEXT,
      description   TEXT,
      fixed_version TEXT,
      url           TEXT,
      FOREIGN KEY (scan_id) REFERENCES scans(id)
    );
  `);
  await db.run(`CREATE INDEX IF NOT EXISTS idx_find_scan ON scan_findings(scan_id);`);
  await db.run(`CREATE INDEX IF NOT EXISTS idx_find_sev ON scan_findings(severity);`);

  await db.run(`
    CREATE TABLE IF NOT EXISTS posture_snapshots (
      id            TEXT PRIMARY KEY,
      captured_at   TEXT NOT NULL,
      source        TEXT NOT NULL,          -- 'scan' | 'runtime'
      score         INTEGER NOT NULL,
      critical_count INTEGER NOT NULL,
      warning_count INTEGER NOT NULL,
      scan_id       TEXT
    );
  `);
  await db.run(`CREATE INDEX IF NOT EXISTS idx_posture_at ON posture_snapshots(captured_at);`);

  await db.run(`
    CREATE TABLE IF NOT EXISTS security_logs (
      id             TEXT PRIMARY KEY,
      timestamp      TEXT NOT NULL,
      source_package TEXT NOT NULL,
      caller_url     TEXT NOT NULL,
      action         TEXT NOT NULL,
      details        TEXT,
      status         TEXT NOT NULL,
      severity       TEXT NOT NULL,
      stack          TEXT
    );
  `);
  // Additive migration: older databases predate the enforcement columns.
  // SQLite has no "ADD COLUMN IF NOT EXISTS", so attempt and ignore duplicates.
  for (const col of ['rule TEXT', 'enforcement TEXT', 'latency_ms REAL', 'stack_frames INTEGER']) {
    try { await db.run(`ALTER TABLE security_logs ADD COLUMN ${col};`); }
    catch (err) { if (!/duplicate column/i.test(err.message)) throw err; }
  }

  await db.run(`CREATE INDEX IF NOT EXISTS idx_logs_ts ON security_logs(timestamp);`);
  await db.run(`CREATE INDEX IF NOT EXISTS idx_logs_sev ON security_logs(severity);`);

  await db.run(`
    CREATE TABLE IF NOT EXISTS quarantine (
      id            TEXT PRIMARY KEY,
      name          TEXT NOT NULL UNIQUE,
      version       TEXT,
      reason        TEXT NOT NULL,
      risk_score    INTEGER,
      quarantined_at TEXT NOT NULL,
      released_at   TEXT
    );
  `);

  // Accepted-risk list: packages the user has explicitly vouched for. These are
  // excluded from scoring but never deleted from the scan, so the decision stays
  // auditable and reversible.
  await db.run(`
    CREATE TABLE IF NOT EXISTS ignored_packages (
      name        TEXT PRIMARY KEY,
      version     TEXT,
      reason      TEXT,
      scope       TEXT NOT NULL DEFAULT 'package',
      ignored_at  TEXT NOT NULL,
      released_at TEXT
    );
  `);

  // Small key/value store so preferences (auto-scan schedule, ...) survive restarts.
  await db.run(`
    CREATE TABLE IF NOT EXISTS settings (
      key        TEXT PRIMARY KEY,
      value      TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
  `);
}

function buildApi(db) {
  const uid = (p) => `${p}-${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`;

  return {
    init: () => init(db),

    /* ------------------------------- scans ------------------------------- */
    async insertScan(report) {
      const id = uid('scan');
      const c = report.counts;
      let n = 0;
      const pid = () => `pkg-${id}-${(n++).toString(36)}`;
      let m = 0;
      const fid = () => `find-${id}-${(m++).toString(36)}`;

      await db.run('BEGIN IMMEDIATE');
      try {
        await db.run(
          `INSERT INTO scans (id, ran_at, project_name, project_version, manifest_hash, lockfile,
             offline, total_packages, direct_count, vulnerable_count, critical_count, high_count,
             moderate_count, low_count, deprecated_count, typosquat_count, score, grade, status,
             duration_ms, report_json)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
          [
            id, report.generatedAt, report.project.name, report.project.version,
            report.project.manifestHash, report.lockfile.source, report.offline ? 1 : 0,
            c.total, c.direct, c.vulnerable, c.critical, c.high, c.moderate, c.low,
            c.deprecated, c.typosquat, report.score, report.grade, report.status,
            report.durationMs, JSON.stringify(report),
          ]
        );
        for (const p of report.packages) {
          await db.run(
            `INSERT INTO scan_packages (id, scan_id, name, version, is_direct, is_dev, depth, risk_score, category)
             VALUES (?,?,?,?,?,?,?,?,?)`,
            [pid(), id, p.name, p.version, p.direct ? 1 : 0, p.dev ? 1 : 0, p.depth, p.riskScore, p.category]
          );
        }
        for (const f of report.findings) {
          await db.run(
            `INSERT INTO scan_findings (id, scan_id, package_name, package_version, is_direct, type, severity, identifier, title, description, fixed_version, url)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
            [fid(), id, f.packageName, f.packageVersion, f.direct ? 1 : 0, f.type, f.severity,
             f.identifier || null, f.title || null, f.description || null, f.fixedVersion || null, f.url || null]
          );
        }
        await db.run(
          `INSERT INTO posture_snapshots (id, captured_at, source, score, critical_count, warning_count, scan_id)
           VALUES (?,?,?,?,?,?,?)`,
          [uid('snap'), report.generatedAt, 'scan', report.score,
           c.critical + c.malicious + (c.directHigh || 0), c.warning + c.moderate + c.deprecated, id]
        );
        await db.run('COMMIT');
      } catch (err) {
        try { await db.run('ROLLBACK'); } catch { /* ignore */ }
        throw err;
      }
      return { id };
    },

    /**
     * Keep the database from growing without bound.
     *
     * Every scan stores a full report blob (~200KB on a mid-size tree) plus one
     * row per package. With auto-scan on a 15-minute cadence that is ~96 scans
     * and ~20MB a day, so old scans are pruned along with their child rows.
     * Runtime logs and posture snapshots are capped the same way.
     */
    async prune({ keepScans = 50, keepFullReports = 10, keepLogs = 2000, keepSnapshots = 1000 } = {}) {
      const removed = { scans: 0, packages: 0, findings: 0, logs: 0, snapshots: 0, blobsDropped: 0 };

      const old = await db.all(
        `SELECT id FROM scans ORDER BY ran_at DESC LIMIT -1 OFFSET ?`, [keepScans]
      );
      if (old.length) {
        const ids = old.map(r => r.id);
        const marks = ids.map(() => '?').join(',');
        const countOf = async (table) => {
          const row = await db.get(`SELECT COUNT(*) c FROM ${table} WHERE scan_id IN (${marks})`, ids);
          return row ? row.c : 0;
        };
        removed.packages = await countOf('scan_packages');
        removed.findings = await countOf('scan_findings');
        await db.run('BEGIN IMMEDIATE');
        try {
          await db.run(`DELETE FROM scan_packages WHERE scan_id IN (${marks})`, ids);
          await db.run(`DELETE FROM scan_findings  WHERE scan_id IN (${marks})`, ids);
          await db.run(`UPDATE posture_snapshots SET scan_id = NULL WHERE scan_id IN (${marks})`, ids);
          await db.run(`DELETE FROM scans WHERE id IN (${marks})`, ids);
          await db.run('COMMIT');
          removed.scans = ids.length;
        } catch (err) {
          try { await db.run('ROLLBACK'); } catch { /* ignore */ }
          throw err;
        }
      }

      // The trend charts and history list only read the summary columns. Keeping
      // a ~200KB report blob on every retained scan is what actually bloats the
      // file, so drop the blob on all but the most recent few and keep the row.
      const blobCut = await db.get(
        `SELECT ran_at FROM scans ORDER BY ran_at DESC LIMIT 1 OFFSET ?`, [keepFullReports]
      );
      if (blobCut) {
        const r = await db.run(
          `UPDATE scans SET report_json = '' WHERE ran_at < ? AND report_json != ''`, [blobCut.ran_at]
        );
        removed.blobsDropped = r.changes || 0;
      }

      const logCut = await db.get(
        `SELECT timestamp t FROM security_logs ORDER BY timestamp DESC LIMIT 1 OFFSET ?`, [keepLogs]
      );
      if (logCut) {
        const r = await db.run(`DELETE FROM security_logs WHERE timestamp < ?`, [logCut.t]);
        removed.logs = r.changes || 0;
      }

      const snapCut = await db.get(
        `SELECT captured_at t FROM posture_snapshots ORDER BY captured_at DESC LIMIT 1 OFFSET ?`, [keepSnapshots]
      );
      if (snapCut) {
        const r = await db.run(`DELETE FROM posture_snapshots WHERE captured_at < ?`, [snapCut.t]);
        removed.snapshots = r.changes || 0;
      }

      return removed;
    },

    /** Reclaim the space freed by prune(). Cheap enough to run occasionally. */
    vacuum() {
      return db.run('VACUUM');
    },

    async getLatestScan() {
      // Skip rows whose blob was pruned so a restart always restores a usable report.
      const row = await db.get(
        `SELECT report_json FROM scans WHERE report_json != '' ORDER BY ran_at DESC LIMIT 1`
      );
      if (!row) return null;
      try { return JSON.parse(row.report_json); } catch { return null; }
    },

    async getScanById(id) {
      const row = await db.get(`SELECT report_json FROM scans WHERE id = ?`, [id]);
      if (!row) return null;
      // Older scans keep their summary row but have the full report pruned.
      if (!row.report_json) return { pruned: true, id };
      try { return JSON.parse(row.report_json); } catch { return { pruned: true, id }; }
    },

    listScans(limit = 60) {
      return db.all(
        `SELECT id, ran_at, project_name, project_version, total_packages, direct_count,
                vulnerable_count, critical_count, high_count, moderate_count, low_count,
                deprecated_count, typosquat_count, score, grade, status, duration_ms, offline
         FROM scans ORDER BY ran_at DESC LIMIT ?`, [limit]
      );
    },

    getFindings(scanId, { severity, type } = {}) {
      let sql = `SELECT * FROM scan_findings WHERE scan_id = ?`;
      const params = [scanId];
      if (severity) { sql += ` AND severity = ?`; params.push(severity); }
      if (type) { sql += ` AND type = ?`; params.push(type); }
      sql += ` ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'moderate' THEN 2 ELSE 1 END DESC`;
      return db.all(sql, params);
    },

    /* ---------------------------- posture trend ---------------------------- */
    getPostureHistory(limit = 60) {
      return db.all(
        `SELECT captured_at, source, score, critical_count, warning_count
         FROM posture_snapshots ORDER BY captured_at DESC LIMIT ?`, [limit]
      );
    },

    addPostureSnapshot(score, criticalCount, warningCount, source = 'runtime') {
      return db.run(
        `INSERT INTO posture_snapshots (id, captured_at, source, score, critical_count, warning_count, scan_id)
         VALUES (?,?,?,?,?,?,NULL)`,
        [uid('snap'), new Date().toISOString(), source, score, criticalCount, warningCount]
      );
    },

    /* ------------------------------- logs ------------------------------- */
    async insertLog(log) {
      const row = {
        id: log.id || uid('log'),
        timestamp: log.timestamp || new Date().toISOString(),
        source_package: log.sourcePackage || 'unknown',
        caller_url: log.callerUrl || log.target || 'unknown',
        action: log.action || 'Runtime Event',
        details: log.details || '',
        status: log.status || 'ALLOWED',
        severity: (log.severity || 'info').toLowerCase(),
        stack: log.stack || '',
        rule: log.rule || null,
        enforcement: log.enforcement || null,
        latency_ms: typeof log.latencyMs === 'number' ? log.latencyMs : null,
        stack_frames: typeof log.stackFrames === 'number' ? log.stackFrames : null,
      };
      await db.run(
        `INSERT OR REPLACE INTO security_logs (id, timestamp, source_package, caller_url, action, details, status, severity, stack, rule, enforcement, latency_ms, stack_frames)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [row.id, row.timestamp, row.source_package, row.caller_url, row.action, row.details, row.status, row.severity, row.stack,
         row.rule, row.enforcement, row.latency_ms, row.stack_frames]
      );
      return {
        id: row.id, timestamp: row.timestamp, sourcePackage: row.source_package,
        callerUrl: row.caller_url, action: row.action, details: row.details,
        status: row.status, severity: row.severity, stack: row.stack,
        rule: row.rule, enforcement: row.enforcement,
        latencyMs: row.latency_ms, stackFrames: row.stack_frames,
      };
    },

    async getLogs(limit = 200) {
      const rows = await db.all(`SELECT * FROM security_logs ORDER BY timestamp DESC LIMIT ?`, [limit]);
      return rows.map(r => ({
        id: r.id, timestamp: r.timestamp, sourcePackage: r.source_package, callerUrl: r.caller_url,
        action: r.action, details: r.details, status: r.status, severity: r.severity, stack: r.stack,
        rule: r.rule || null, enforcement: r.enforcement || null,
        latencyMs: r.latency_ms != null ? r.latency_ms : null,
        stackFrames: r.stack_frames != null ? r.stack_frames : null,
      }));
    },

    /** Logs within a window - powers the forensics report export. */
    async getLogsSince(sinceIso, limit = 5000) {
      const rows = await db.all(
        `SELECT * FROM security_logs WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT ?`,
        [sinceIso, limit]
      );
      return rows.map(r => ({
        id: r.id, timestamp: r.timestamp, sourcePackage: r.source_package, callerUrl: r.caller_url,
        action: r.action, details: r.details, status: r.status, severity: r.severity, stack: r.stack,
        rule: r.rule || null, enforcement: r.enforcement || null,
        latencyMs: r.latency_ms != null ? r.latency_ms : null,
        stackFrames: r.stack_frames != null ? r.stack_frames : null,
      }));
    },

    /** Scans within a window, newest first. */
    listScansSince(sinceIso, limit = 500) {
      return db.all(
        `SELECT id, ran_at, project_name, project_version, total_packages, direct_count,
                vulnerable_count, critical_count, high_count, moderate_count, low_count,
                deprecated_count, typosquat_count, score, grade, status, duration_ms, offline
         FROM scans WHERE ran_at >= ? ORDER BY ran_at DESC LIMIT ?`,
        [sinceIso, limit]
      );
    },

    getPostureHistorySince(sinceIso, limit = 2000) {
      return db.all(
        `SELECT captured_at, source, score, critical_count, warning_count
         FROM posture_snapshots WHERE captured_at >= ? ORDER BY captured_at DESC LIMIT ?`,
        [sinceIso, limit]
      );
    },

    /* --------------------------- accepted risk --------------------------- */
    getIgnored() {
      return db.all(`SELECT * FROM ignored_packages WHERE released_at IS NULL ORDER BY ignored_at DESC`);
    },

    async addIgnored({ name, version, reason, scope }) {
      await db.run(
        `INSERT INTO ignored_packages (name, version, reason, scope, ignored_at, released_at)
         VALUES (?,?,?,?,?,NULL)
         ON CONFLICT(name) DO UPDATE SET
           version = excluded.version, reason = excluded.reason,
           scope = excluded.scope, ignored_at = excluded.ignored_at, released_at = NULL`,
        [name, version || null, reason || null, scope || 'package', new Date().toISOString()]
      );
      return { name, version, reason, scope: scope || 'package' };
    },

    releaseIgnored(name) {
      return db.run(`UPDATE ignored_packages SET released_at = ? WHERE name = ?`,
        [new Date().toISOString(), name]);
    },

    /* ------------------------------ settings ----------------------------- */
    async getSetting(key, fallback = null) {
      const row = await db.get(`SELECT value FROM settings WHERE key = ?`, [key]);
      if (!row) return fallback;
      try { return JSON.parse(row.value); } catch { return fallback; }
    },

    async setSetting(key, value) {
      await db.run(
        `INSERT INTO settings (key, value, updated_at) VALUES (?,?,?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
        [key, JSON.stringify(value), new Date().toISOString()]
      );
      return value;
    },

    /* ---------------------------- quarantine ---------------------------- */
    getQuarantine() {
      return db.all(`SELECT * FROM quarantine WHERE released_at IS NULL ORDER BY quarantined_at DESC`);
    },

    addQuarantine({ name, version, reason, riskScore }) {
      return db.run(
        `INSERT INTO quarantine (id, name, version, reason, risk_score, quarantined_at)
         VALUES (?,?,?,?,?,?)
         ON CONFLICT(name) DO UPDATE SET reason = excluded.reason, version = excluded.version,
           risk_score = excluded.risk_score, quarantined_at = excluded.quarantined_at, released_at = NULL`,
        [uid('q'), name, version || null, reason || 'Manual quarantine', riskScore ?? null, new Date().toISOString()]
      );
    },

    releaseQuarantine(name) {
      return db.run(`UPDATE quarantine SET released_at = ? WHERE name = ? AND released_at IS NULL`,
        [new Date().toISOString(), name]);
    },

    /* --------------------------- db explorer --------------------------- */
    async getStats() {
      const tables = ['scans', 'scan_packages', 'scan_findings', 'posture_snapshots', 'security_logs', 'quarantine', 'ignored_packages', 'settings'];
      const counts = {};
      let total = 0;
      for (const t of tables) {
        const row = await db.get(`SELECT COUNT(*) AS c FROM ${t}`);
        counts[t] = row.c;
        total += row.c;
      }
      const jm = await db.get(`PRAGMA journal_mode`);
      return {
        engine: `SQLite ${sqlite3.VERSION || '3'}`,
        dbFile: db.file,
        status: 'OPTIMAL',
        journalMode: (jm && (jm.journal_mode || jm['journal_mode'])) || 'wal',
        tables: tables.map(name => ({ name, rows: counts[name] })),
        totalRecords: total,
      };
    },

    getTableRows(table, limit = 200) {
      const allowed = ['scans', 'scan_packages', 'scan_findings', 'posture_snapshots', 'security_logs', 'quarantine', 'ignored_packages', 'settings'];
      if (!allowed.includes(table)) return Promise.reject(new Error('Unknown or restricted table'));
      // `scans.report_json` is a ~200KB blob per row - selecting it here turned
      // a table preview into a 10MB response. Summarise it instead.
      if (table === 'scans') {
        return db.all(
          `SELECT id, ran_at, project_name, project_version, manifest_hash, lockfile, offline,
                  total_packages, direct_count, vulnerable_count, critical_count, high_count,
                  moderate_count, low_count, deprecated_count, typosquat_count,
                  score, grade, status, duration_ms,
                  ('<' || (LENGTH(report_json) / 1024) || ' KB JSON>') AS report_json
           FROM scans ORDER BY ran_at DESC LIMIT ?`, [limit]
        );
      }
      return db.all(`SELECT * FROM ${table} LIMIT ?`, [limit]);
    },

    async runReadOnlyQuery(sql) {
      const norm = sql.trim().toUpperCase();
      if (!/^(SELECT|WITH|PRAGMA|EXPLAIN)\b/.test(norm)) {
        throw new Error('Only SELECT / WITH / PRAGMA / EXPLAIN statements are allowed.');
      }
      if (/;\s*\S/.test(sql.trim())) throw new Error('Multiple statements are not allowed.');
      const t0 = process.hrtime.bigint();
      const rows = await db.all(sql);
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      return {
        columns: rows.length ? Object.keys(rows[0]) : [],
        rows,
        rowCount: rows.length,
        latencyMs: ms.toFixed(2),
        executedAt: new Date().toISOString(),
      };
    },
  };
}

module.exports = { open };
