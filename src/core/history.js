/**
 * Per-package evolution history.
 *
 * Joins two real sources into one chronological timeline for any package that
 * is actually installed in the target repo:
 *
 *   npm registry packument  -> every published version + its publish date,
 *                              deprecation state, latest tag
 *   OSV.dev (package query) -> every advisory ever filed against the package,
 *                              with its affected range and fixing version
 *
 * The result is the real life-story of that dependency: when it was first
 * published, when advisories landed, which release fixed them, where your
 * installed version sits, and what upgrading would buy you.
 */

const semver = require('semver');
const { requestJson } = require('./http');
const cache = require('./cache');

const REGISTRY = 'https://registry.npmjs.org';
const OSV_QUERY = 'https://api.osv.dev/v1/query';

const SEV_RANK = { critical: 4, high: 3, moderate: 2, low: 1 };

function normSeverity(raw) {
  const s = String(raw || '').toLowerCase();
  if (s.startsWith('crit')) return 'critical';
  if (s.startsWith('high')) return 'high';
  if (s.startsWith('mod') || s.startsWith('med')) return 'moderate';
  if (s.startsWith('low')) return 'low';
  return 'moderate';
}

function registryUrl(name) {
  return name.startsWith('@')
    ? `${REGISTRY}/@${encodeURIComponent(name.slice(1))}`
    : `${REGISTRY}/${encodeURIComponent(name)}`;
}

/** Full version history from the npm packument. */
async function fetchVersions(root, name, ttlMs, offline) {
  if (offline) return null;
  const cached = cache.get(root, 'history-reg', name, ttlMs);
  if (cached) return cached;
  const res = await requestJson(registryUrl(name), { timeoutMs: 20000 });
  if (!res.ok || !res.data) return null;
  const p = res.data;
  const time = p.time || {};
  const versions = Object.keys(p.versions || {})
    .filter(v => semver.valid(v))
    .map(v => ({
      version: v,
      published: time[v] || null,
      deprecated: !!(p.versions[v] && p.versions[v].deprecated),
    }))
    .sort((a, b) => semver.compare(a.version, b.version));
  const out = {
    name: p.name,
    latest: (p['dist-tags'] || {}).latest || null,
    created: time.created || (versions[0] && versions[0].published) || null,
    modified: time.modified || null,
    versions,
    deprecated: (() => {
      const latest = (p['dist-tags'] || {}).latest;
      const lm = latest && p.versions && p.versions[latest];
      return (lm && lm.deprecated) || null;
    })(),
    maintainers: Array.isArray(p.maintainers) ? p.maintainers.length : null,
    license: (() => {
      const latest = (p['dist-tags'] || {}).latest;
      const lm = latest && p.versions && p.versions[latest];
      return (lm && lm.license) || p.license || null;
    })(),
  };
  cache.set(root, 'history-reg', name, out);
  return out;
}

/** Every advisory OSV knows about for this package (all versions). */
async function fetchAllAdvisories(root, name, ttlMs, offline) {
  if (offline) return [];
  const cached = cache.get(root, 'history-osv', name, ttlMs);
  if (cached) return cached;
  const res = await requestJson(OSV_QUERY, {
    method: 'POST',
    body: { package: { name, ecosystem: 'npm' } },
    timeoutMs: 20000,
  });
  if (!res.ok || !res.data) return [];
  const vulns = (res.data.vulns || []).filter(v => !v.withdrawn);
  const out = vulns.map(v => {
    const affected = (v.affected || []).filter(
      a => a.package && a.package.name === name && String(a.package.ecosystem || '').toLowerCase() === 'npm'
    );
    const introduced = [];
    const fixed = [];
    for (const a of affected) {
      for (const r of a.ranges || []) {
        for (const ev of r.events || []) {
          if (ev.introduced && ev.introduced !== '0') introduced.push(ev.introduced);
          if (ev.fixed) fixed.push(ev.fixed);
        }
      }
    }
    const validFixed = fixed.filter(f => semver.valid(f)).sort(semver.compare);
    const aliases = v.aliases || [];
    return {
      id: v.id,
      identifier: aliases.find(a => /^CVE-/i.test(a)) || v.id,
      title: (v.summary || v.id || '').split('\n')[0].slice(0, 180),
      severity: normSeverity(
        (v.database_specific && v.database_specific.severity) ||
        (affected[0] && affected[0].database_specific && affected[0].database_specific.severity)
      ),
      published: v.published || v.modified || null,
      firstFixed: validFixed[0] || null,
      introduced: introduced.sort((a, b) => (semver.valid(a) && semver.valid(b) ? semver.compare(a, b) : 0))[0] || null,
      ranges: affected.map(a => (a.ranges || []).map(r =>
        (r.events || []).map(e => e.introduced ? `>=${e.introduced}` : e.fixed ? `<${e.fixed}` : '').filter(Boolean).join(' ')
      ).join(' || ')).filter(Boolean).join(' ; ') || null,
      url: `https://osv.dev/vulnerability/${v.id}`,
      affectsVersion(version) {
        if (!semver.valid(version)) return false;
        for (const a of affected) {
          for (const r of a.ranges || []) {
            let inRange = false;
            let lastIntro = null;
            for (const ev of (r.events || [])) {
              if (ev.introduced) lastIntro = ev.introduced === '0' ? '0.0.0' : ev.introduced;
              if (ev.fixed && lastIntro) {
                if (semver.gte(version, lastIntro) && semver.lt(version, ev.fixed)) inRange = true;
                lastIntro = null;
              }
            }
            if (lastIntro && semver.gte(version, lastIntro)) inRange = true;
            if (inRange) return true;
          }
          if ((a.versions || []).includes(version)) return true;
        }
        return false;
      },
    };
  });
  // strip the function before caching, recompute on read
  const serialisable = out.map(({ affectsVersion, ...rest }) => rest);
  cache.set(root, 'history-osv', name, serialisable);
  return out;
}

/** Re-attach range matching to a cached (plain) advisory record. */
function withMatcher(adv) {
  if (typeof adv.affectsVersion === 'function') return adv;
  return {
    ...adv,
    affectsVersion(version) {
      if (!semver.valid(version)) return false;
      const intro = adv.introduced && semver.valid(adv.introduced) ? adv.introduced : '0.0.0';
      if (!semver.gte(version, intro)) return false;
      if (adv.firstFixed && semver.valid(adv.firstFixed)) return semver.lt(version, adv.firstFixed);
      return true;
    },
  };
}

/**
 * @param {string} root              target repo (for the cache)
 * @param {string} name              package name
 * @param {string|null} installed    the version installed in this repo
 * @param {object} opts              { offline, cacheTtlHours }
 */
async function getPackageTimeline(root, name, installed, opts = {}) {
  const ttlMs = (opts.cacheTtlHours ?? 24) * 3600 * 1000;
  const offline = !!opts.offline;

  const [reg, rawAdvisories] = await Promise.all([
    fetchVersions(root, name, ttlMs, offline).catch(() => null),
    fetchAllAdvisories(root, name, ttlMs, offline).catch(() => []),
  ]);
  const advisories = (rawAdvisories || []).map(withMatcher);

  if (!reg) {
    return {
      name, installedVersion: installed, available: false,
      reason: offline ? 'Offline mode - registry history unavailable.' : 'Could not reach the npm registry for this package.',
      events: [], advisories: [], stats: null,
    };
  }

  const byVersion = new Map(reg.versions.map(v => [v.version, v]));
  const publishedAt = (v) => (byVersion.get(v) ? byVersion.get(v).published : null);

  const events = [];
  const pushEvent = (e) => { if (e.date) events.push(e); };

  // 1. first publish
  const first = reg.versions[0];
  if (first) {
    pushEvent({
      kind: 'created', date: first.published || reg.created, version: first.version,
      title: 'First published', detail: `${name} v${first.version} released to npm`, risk: 'safe',
    });
  }

  // 2. advisories, and the release that fixed each one
  const affectingInstalled = [];
  for (const a of advisories) {
    const hits = installed ? a.affectsVersion(installed) : false;
    if (hits) affectingInstalled.push(a);
    pushEvent({
      kind: 'advisory', date: a.published, version: a.introduced || null,
      title: a.identifier, detail: a.title, severity: a.severity, url: a.url,
      affectsInstalled: hits,
      risk: a.severity === 'critical' || a.severity === 'high' ? 'critical' : 'warning',
    });
    if (a.firstFixed && byVersion.has(a.firstFixed)) {
      pushEvent({
        kind: 'patched', date: publishedAt(a.firstFixed), version: a.firstFixed,
        title: `Patched in ${a.firstFixed}`, detail: `${a.identifier} fixed`, risk: 'safe', url: a.url,
      });
    }
  }

  // 3. the installed version
  if (installed && byVersion.has(installed)) {
    pushEvent({
      kind: 'installed', date: publishedAt(installed), version: installed,
      title: 'Your version', detail: `v${installed} is what this repo resolves`,
      risk: affectingInstalled.length ? 'critical' : 'safe',
      affectsInstalled: affectingInstalled.length > 0,
    });
  }

  // 4. deprecation + latest
  if (reg.deprecated) {
    pushEvent({
      kind: 'deprecated', date: reg.modified, version: reg.latest,
      title: 'Deprecated', detail: String(reg.deprecated).slice(0, 160), risk: 'warning',
    });
  }
  if (reg.latest && byVersion.has(reg.latest) && reg.latest !== installed) {
    pushEvent({
      kind: 'latest', date: publishedAt(reg.latest), version: reg.latest,
      title: `Latest ${reg.latest}`, detail: 'Newest published release', risk: 'safe',
    });
  }

  events.sort((a, b) => new Date(a.date) - new Date(b.date));

  // recommended upgrade: lowest version that clears every advisory hitting us
  let upgrade = null;
  if (affectingInstalled.length) {
    const targets = affectingInstalled.map(a => a.firstFixed).filter(v => v && semver.valid(v));
    if (targets.length) {
      const highest = targets.sort(semver.compare)[targets.length - 1];
      const clears = advisories.filter(a => a.affectsVersion(installed) && !a.affectsVersion(highest)).length;
      upgrade = {
        to: highest,
        publishedAt: publishedAt(highest),
        clears,
        of: affectingInstalled.length,
        isLatest: highest === reg.latest,
      };
    }
  }

  const behind = installed && reg.latest && semver.valid(installed) && semver.valid(reg.latest)
    ? reg.versions.filter(v => semver.gt(v.version, installed)).length
    : null;

  return {
    name,
    installedVersion: installed,
    available: true,
    latest: reg.latest,
    license: reg.license,
    maintainers: reg.maintainers,
    deprecated: reg.deprecated,
    firstPublished: reg.created,
    lastPublished: reg.modified,
    totalVersions: reg.versions.length,
    versionsBehind: behind,
    events,
    advisories: advisories.map(({ affectsVersion, ...rest }) => ({
      ...rest,
      affectsInstalled: installed ? withMatcher(rest).affectsVersion(installed) : false,
    })),
    upgrade,
    stats: {
      advisoriesTotal: advisories.length,
      advisoriesAffectingInstalled: affectingInstalled.length,
      worstAffecting: affectingInstalled.length
        ? affectingInstalled.map(a => a.severity).sort((x, y) => SEV_RANK[y] - SEV_RANK[x])[0]
        : null,
    },
  };
}

module.exports = { getPackageTimeline };
