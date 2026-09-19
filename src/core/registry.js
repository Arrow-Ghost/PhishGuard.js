/**
 * npm registry metadata: real `deprecated` flags plus a few signals used by the
 * trust classifier (publish cadence, package age, maintainer count).
 * One request per unique package name, cached for 72h by default.
 */

const fs = require('fs');
const path = require('path');
const { requestJson, pool } = require('./http');
const cache = require('./cache');
const { extractLifecycleScripts } = require('./lifecycle');

const REGISTRY = 'https://registry.npmjs.org';
const OFFLINE_DB = path.join(__dirname, '..', 'data', 'offline-advisories.json');

function loadOfflineDeprecations() {
  try {
    return JSON.parse(fs.readFileSync(OFFLINE_DB, 'utf8')).deprecated || {};
  } catch {
    return {};
  }
}

function summarise(packument, installedVersion) {
  const versions = packument.versions || {};
  const distTags = packument['dist-tags'] || {};
  const latest = distTags.latest;
  const time = packument.time || {};

  const vMeta = installedVersion && versions[installedVersion];
  const latestMeta = latest && versions[latest];
  const deprecated =
    (vMeta && vMeta.deprecated) ||
    (latestMeta && latestMeta.deprecated) ||
    (typeof packument.deprecated === 'string' ? packument.deprecated : null) ||
    null;

  const versionKeys = Object.keys(versions);
  const created = time.created || null;
  const modified = time.modified || packument.modified || null;

  let daysSincePublish = null;
  if (modified) {
    daysSincePublish = Math.round((Date.now() - new Date(modified).getTime()) / 86400000);
  }

  return {
    name: packument.name,
    latest: latest || null,
    deprecated: deprecated ? String(deprecated) : null,
    deprecatedExactVersion: !!(vMeta && vMeta.deprecated),
    versionsCount: versionKeys.length,
    maintainers: Array.isArray(packument.maintainers) ? packument.maintainers.length : null,
    created,
    modified,
    daysSincePublish,
    license: (latestMeta && latestMeta.license) || packument.license || null,
    homepage: packument.homepage || null,
    scripts: extractLifecycleScripts(vMeta && vMeta.scripts),
    unresolved: false,
  };
}

async function queryRegistry(root, packages, opts = {}) {
  const { offline = false, cacheTtlMs = 72 * 3600 * 1000, onProgress } = opts;
  const offlineDep = loadOfflineDeprecations();
  const names = [...new Set(packages.map(p => p.name))];
  const versionByName = new Map(packages.map(p => [p.name, p.version]));
  const out = new Map();
  let networkFailed = false;
  let done = 0;

  const blank = (name, notFound) => ({
    name,
    deprecated: offlineDep[name] || null,
    deprecatedExactVersion: false,
    versionsCount: null, maintainers: null, created: null, modified: null,
    daysSincePublish: null, latest: null, license: null, homepage: null,
    unresolved: true,
    notFound: !!notFound,
  });

  // scoped names: /@scope%2Fname
  const registryUrl = (name) => name.startsWith('@')
    ? `${REGISTRY}/@${encodeURIComponent(name.slice(1))}`
    : `${REGISTRY}/${encodeURIComponent(name)}`;

  await pool(names, 5, async (name) => {
    const installedVersion = versionByName.get(name);
    const cached = cache.get(root, 'registry', name, cacheTtlMs);
    if (cached) {
      out.set(name, cached);
    } else if (offline) {
      out.set(name, blank(name, false));
    } else {
      const res = await requestJson(registryUrl(name));
      if (res.ok && res.data) {
        const summary = summarise(res.data, installedVersion);
        cache.set(root, 'registry', name, summary);
        out.set(name, summary);
      } else if (res.ok && res.status === 404) {
        // Package genuinely absent from the registry - meaningful, not a failure.
        const nf = blank(name, true);
        cache.set(root, 'registry', name, nf);
        out.set(name, nf);
      } else {
        networkFailed = true;
        out.set(name, blank(name, false));
      }
    }
    done++;
    if (onProgress) onProgress(done, names.length);
  });

  return { map: out, meta: { degraded: offline || networkFailed } };
}

module.exports = { queryRegistry };
