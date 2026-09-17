/**
 * Vulnerability lookup via OSV.dev (https://osv.dev), with an on-disk cache and
 * a bundled offline advisory set as a fallback when the network is unavailable
 * or `offline` mode is set.
 *
 * Strategy: one `/v1/querybatch` call per 500 packages returns the vuln *ids*
 * that affect each package@version. We then fetch the full record for each
 * unique id once (`/v1/vulns/{id}`, cached by id). This is an order of
 * magnitude fewer requests than querying every package individually.
 *
 * OSV is free, unauthenticated, and covers the npm ecosystem via GHSA + CVE.
 */

const fs = require('fs');
const path = require('path');
const semver = require('semver');
const { requestJson, pool } = require('./http');
const cache = require('./cache');

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns/';
const OFFLINE_DB = path.join(__dirname, '..', 'data', 'offline-advisories.json');

function loadOffline() {
  try {
    return JSON.parse(fs.readFileSync(OFFLINE_DB, 'utf8'));
  } catch {
    return { advisories: {} };
  }
}

const SEVERITY_ORDER = { critical: 4, high: 3, moderate: 2, low: 1, unknown: 0 };

function normaliseSeverityLabel(raw) {
  if (!raw) return null;
  const s = String(raw).toLowerCase();
  if (s.startsWith('crit')) return 'critical';
  if (s.startsWith('high')) return 'high';
  if (s.startsWith('mod') || s.startsWith('med')) return 'moderate';
  if (s.startsWith('low')) return 'low';
  return null;
}

function severityFromCvssVector(vector) {
  if (!vector || typeof vector !== 'string') return null;
  const highish = (vector.match(/[ISAC]:H/g) || []).length;
  if (/AV:N/.test(vector) && highish >= 2) return 'critical';
  if (highish >= 2) return 'high';
  if (highish === 1) return 'moderate';
  return 'low';
}

function pickIdentifier(vuln) {
  const aliases = vuln.aliases || [];
  const cve = aliases.find(a => /^CVE-/i.test(a));
  return cve || vuln.id;
}

function pickFixedVersion(vuln, name, currentVersion) {
  const affected = (vuln.affected || []).filter(
    a => a.package && a.package.name === name && (a.package.ecosystem || '').toLowerCase() === 'npm'
  );
  const fixes = [];
  for (const a of affected) {
    for (const range of a.ranges || []) {
      for (const ev of range.events || []) {
        if (ev.fixed) fixes.push(ev.fixed);
      }
    }
  }
  const valid = fixes.filter(v => semver.valid(v));
  if (!valid.length) return null;
  valid.sort(semver.compare);
  if (currentVersion && semver.valid(currentVersion)) {
    const next = valid.find(v => semver.gt(v, currentVersion));
    return next || valid[valid.length - 1];
  }
  return valid[0];
}

function deriveSeverity(vuln, name) {
  let label = normaliseSeverityLabel(vuln.database_specific && vuln.database_specific.severity);
  if (!label) {
    for (const a of vuln.affected || []) {
      if (a.package && a.package.name === name) {
        label = normaliseSeverityLabel(a.database_specific && a.database_specific.severity);
        if (label) break;
      }
    }
  }
  if (!label && Array.isArray(vuln.severity)) {
    for (const s of vuln.severity) {
      label = severityFromCvssVector(s.score);
      if (label) break;
    }
  }
  return label || 'moderate';
}

/** CWE ids, when the advisory carries a classification. */
function pickCwes(vuln) {
  const out = new Set();
  const ds = vuln.database_specific || {};
  for (const v of [].concat(ds.cwe_ids || [], ds.cwes || [])) {
    const s = typeof v === 'string' ? v : (v && (v.cweId || v.cwe_id || v.id));
    if (s) out.add(String(s).toUpperCase());
  }
  for (const a of vuln.affected || []) {
    const ads = a.database_specific || {};
    for (const v of [].concat(ads.cwe_ids || [], ads.cwes || [])) {
      const s = typeof v === 'string' ? v : (v && (v.cweId || v.cwe_id || v.id));
      if (s) out.add(String(s).toUpperCase());
    }
  }
  return [...out].slice(0, 6);
}

function normaliseVuln(vuln, name, version) {
  return {
    id: vuln.id,
    identifier: pickIdentifier(vuln),
    aliases: vuln.aliases || [],
    cwes: pickCwes(vuln),
    title: (vuln.summary || vuln.details || vuln.id || '').split('\n')[0].slice(0, 200),
    description: (vuln.details || vuln.summary || '').slice(0, 600),
    severity: deriveSeverity(vuln, name),
    fixedVersion: pickFixedVersion(vuln, name, version),
    url: `https://osv.dev/vulnerability/${vuln.id}`,
    published: vuln.published || vuln.modified || null,
  };
}

function offlineLookup(offline, name, version) {
  const list = (offline.advisories && offline.advisories[name]) || [];
  const hits = [];
  for (const adv of list) {
    let inRange = true;
    if (adv.range && semver.valid(version)) {
      try {
        inRange = semver.satisfies(version, adv.range, { includePrerelease: true });
      } catch {
        inRange = false;
      }
    }
    if (inRange) {
      hits.push({
        id: adv.id,
        identifier: adv.cve || adv.id,
        aliases: adv.cve ? [adv.cve] : [],
        title: adv.title,
        description: adv.description || adv.title,
        severity: normaliseSeverityLabel(adv.severity) || 'moderate',
        fixedVersion: adv.fixed || null,
        url: adv.url || (adv.cve ? `https://nvd.nist.gov/vuln/detail/${adv.cve}` : null),
        published: adv.published || null,
        offline: true,
      });
    }
  }
  return hits;
}

function chunk(arr, size) {
  const out = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

/** Collapse advisory records that share a CVE id (OSV often has several GHSA
 *  entries aliasing one CVE): keep the worst severity and the lowest known fix. */
function dedupeAdvisories(list) {
  const byId = new Map();
  for (const a of list) {
    const prev = byId.get(a.identifier);
    if (!prev) { byId.set(a.identifier, a); continue; }
    const worse = SEVERITY_ORDER[a.severity] > SEVERITY_ORDER[prev.severity] ? a : prev;
    let fixedVersion = prev.fixedVersion;
    if (a.fixedVersion && (!fixedVersion || (semver.valid(a.fixedVersion) && semver.valid(fixedVersion) && semver.lt(a.fixedVersion, fixedVersion)))) {
      fixedVersion = a.fixedVersion;
    }
    byId.set(a.identifier, {
      ...worse,
      fixedVersion,
      aliases: [...new Set([...(prev.aliases || []), ...(a.aliases || [])])],
    });
  }
  return [...byId.values()];
}

/**
 * @returns { map: Map<`${name}@${version}`, { advisories, degraded }>, meta }
 */
async function queryVulnerabilities(root, packages, opts = {}) {
  const { offline = false, cacheTtlMs = 24 * 3600 * 1000, onProgress } = opts;
  const offlineDb = loadOffline();
  const targets = packages.filter(p => p.version && semver.valid(p.version));
  const result = new Map();

  // 1. serve from cache where possible
  const uncached = [];
  for (const pkg of targets) {
    const key = `${pkg.name}@${pkg.version}`;
    const cached = cache.get(root, 'osv', key, cacheTtlMs);
    if (cached) result.set(key, { advisories: cached, degraded: false });
    else uncached.push(pkg);
  }

  if (!uncached.length) {
    return {
      map: result,
      meta: { source: 'cache', degraded: false, scanned: targets.length, skipped: packages.length - targets.length },
    };
  }

  // 2. offline mode -> bundled data only
  if (offline) {
    for (const pkg of uncached) {
      const key = `${pkg.name}@${pkg.version}`;
      result.set(key, { advisories: offlineLookup(offlineDb, pkg.name, pkg.version), degraded: true });
    }
    return {
      map: result,
      meta: { source: 'offline', degraded: true, scanned: targets.length, skipped: packages.length - targets.length },
    };
  }

  // 3. batch query OSV for ids
  let networkFailed = false;
  const idHits = new Map();      // key -> Set<id>   (only for packages a batch covered)
  const batchCovered = new Set(); // keys the batch endpoint answered for
  let progressDone = 0;
  for (const group of chunk(uncached, 500)) {
    const res = await requestJson(OSV_BATCH_URL, {
      method: 'POST',
      body: { queries: group.map(p => ({ package: { name: p.name, ecosystem: 'npm' }, version: p.version })) },
      timeoutMs: 20000,
    });
    if (!res.ok || !res.data || !Array.isArray(res.data.results)) {
      networkFailed = true;
      progressDone += group.length;
      if (onProgress) onProgress(progressDone, uncached.length);
      continue;
    }
    res.data.results.forEach((r, i) => {
      const pkg = group[i];
      if (!pkg) return;
      const key = `${pkg.name}@${pkg.version}`;
      idHits.set(key, new Set((r.vulns || []).map(v => v.id)));
      batchCovered.add(key);
    });
    progressDone += group.length;
    if (onProgress) onProgress(progressDone, uncached.length);
  }

  if (batchCovered.size === 0) {
    // total failure -> offline fallback for everything uncached, cache nothing
    for (const pkg of uncached) {
      const key = `${pkg.name}@${pkg.version}`;
      result.set(key, { advisories: offlineLookup(offlineDb, pkg.name, pkg.version), degraded: true });
    }
    return {
      map: result,
      meta: {
        source: 'osv-unreachable-offline-fallback', degraded: true,
        scanned: targets.length, skipped: packages.length - targets.length,
      },
    };
  }

  // 4. fetch full records for each unique id once
  const uniqueIds = [...new Set([].concat(...[...idHits.values()].map(s => [...s])))];
  const vulnById = new Map();
  const vulnFailed = new Set();
  await pool(uniqueIds, 10, async (id) => {
    const cachedVuln = cache.get(root, 'osv-vuln', id, 30 * 24 * 3600 * 1000);
    if (cachedVuln) {
      vulnById.set(id, cachedVuln);
      return;
    }
    const res = await requestJson(OSV_VULN_URL + encodeURIComponent(id), { timeoutMs: 15000 });
    if (res.ok && res.data) {
      cache.set(root, 'osv-vuln', id, res.data);
      vulnById.set(id, res.data);
    } else {
      vulnFailed.add(id);
    }
  });

  // 5. assemble; only cache a package's advisory list when it is *complete*
  //    (the batch covered it AND every referenced advisory record resolved).
  for (const pkg of uncached) {
    const key = `${pkg.name}@${pkg.version}`;
    if (!batchCovered.has(key)) {
      result.set(key, { advisories: offlineLookup(offlineDb, pkg.name, pkg.version), degraded: true });
      continue;
    }
    const ids = [...(idHits.get(key) || new Set())];
    const complete = ids.every(id => !vulnFailed.has(id));
    const advisories = dedupeAdvisories(
      ids
        .map(id => vulnById.get(id))
        .filter(v => v && !v.withdrawn)
        .map(v => normaliseVuln(v, pkg.name, pkg.version))
    );
    if (complete) cache.set(root, 'osv', key, advisories);
    result.set(key, { advisories, degraded: !complete });
  }

  return {
    map: result,
    meta: {
      source: networkFailed || vulnFailed.size ? 'osv.dev (partial)' : 'osv.dev',
      degraded: networkFailed || vulnFailed.size > 0,
      scanned: targets.length,
      skipped: packages.length - targets.length,
    },
  };
}

module.exports = { queryVulnerabilities, SEVERITY_ORDER, normaliseSeverityLabel };
