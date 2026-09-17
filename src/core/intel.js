/**
 * Global OSINT threat intelligence.
 *
 * Three free, unauthenticated public feeds, normalised into one stream:
 *
 *   1. GitHub Advisory Database  (api.github.com/advisories)
 *        - `reviewed` npm advisories : CVE/GHSA affecting the npm ecosystem
 *        - `malware`  npm advisories : packages GitHub has confirmed MALICIOUS
 *          (this is the real supply-chain attack feed - the "what package
 *          caused it" answer)
 *   2. CISA KEV  (Known Exploited Vulnerabilities)
 *        - CVEs confirmed exploited in the wild, with vendor/product and the
 *          federally mandated remediation date
 *   3. OSV.dev  - used elsewhere for per-package matching; its ids are linked
 *
 * Every item carries a real `url` that opens the authoritative source page.
 * Items are cross-referenced against the current scan so the UI can flag the
 * ones that actually touch this repository.
 */

const semver = require('semver');
const { requestJson } = require('./http');
const cache = require('./cache');

const GH_ADVISORIES = 'https://api.github.com/advisories';
const CISA_KEV = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

const SEV_RANK = { critical: 4, high: 3, moderate: 2, low: 1, unknown: 0 };

function normSeverity(s) {
  const v = String(s || '').toLowerCase();
  if (v.startsWith('crit')) return 'critical';
  if (v.startsWith('high')) return 'high';
  if (v.startsWith('med') || v.startsWith('mod')) return 'moderate';
  if (v.startsWith('low')) return 'low';
  return 'moderate';
}

/* ------------------------- GitHub Advisory Database ------------------------ */

function mapGithubAdvisory(a, kind) {
  const packages = (a.vulnerabilities || [])
    .filter(v => v.package)
    .map(v => ({
      ecosystem: v.package.ecosystem,
      name: v.package.name,
      vulnerableRange: v.vulnerable_version_range || null,
      patched: v.first_patched_version || null,
    }));
  return {
    id: a.ghsa_id,
    kind,                                  // 'malware' | 'advisory'
    source: kind === 'malware' ? 'GitHub Security (malware)' : 'GitHub Advisory DB',
    identifier: a.cve_id || a.ghsa_id,
    ghsa: a.ghsa_id,
    cve: a.cve_id || null,
    title: a.summary || a.ghsa_id,
    description: (a.description || '').slice(0, 800),
    severity: normSeverity(a.severity),
    cvss: a.cvss && a.cvss.score ? a.cvss.score : null,
    cwes: (a.cwes || []).map(c => c.cwe_id).slice(0, 4),
    packages,
    ecosystem: packages[0] ? packages[0].ecosystem : 'npm',
    published: a.published_at || a.updated_at || null,
    updated: a.updated_at || null,
    url: a.html_url || (a.ghsa_id ? `https://github.com/advisories/${a.ghsa_id}` : null),
    references: (a.references || []).slice(0, 5),
  };
}

async function fetchGithub(root, { kind, ecosystem = 'npm', perPage = 60, ttlMs }) {
  const key = `gh:${kind}:${ecosystem}:${perPage}`;
  const cached = cache.get(root, 'intel', key, ttlMs);
  if (cached) return cached;

  const params = new URLSearchParams({
    per_page: String(perPage),
    sort: 'published',
    direction: 'desc',
    ecosystem,
  });
  if (kind === 'malware') params.set('type', 'malware');
  else params.set('type', 'reviewed');

  const res = await requestJson(`${GH_ADVISORIES}?${params}`, {
    headers: { accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28' },
    timeoutMs: 15000,
  });
  if (!res.ok || !Array.isArray(res.data)) return null;
  const items = res.data.map(a => mapGithubAdvisory(a, kind));
  cache.set(root, 'intel', key, items);
  return items;
}

/* --------------------------------- CISA KEV -------------------------------- */

function mapKev(v) {
  return {
    id: `KEV-${v.cveID}`,
    kind: 'exploited',
    source: 'CISA KEV',
    identifier: v.cveID,
    ghsa: null,
    cve: v.cveID,
    title: v.vulnerabilityName || v.cveID,
    description: [v.shortDescription, v.requiredAction && `Required action: ${v.requiredAction}`]
      .filter(Boolean).join(' ').slice(0, 800),
    severity: 'critical',                  // KEV = confirmed exploited in the wild
    cvss: null,
    cwes: Array.isArray(v.cwes) ? v.cwes.slice(0, 4) : [],
    packages: [],
    vendor: v.vendorProject || null,
    product: v.product || null,
    ransomware: String(v.knownRansomwareCampaignUse || '').toLowerCase() === 'known',
    dueDate: v.dueDate || null,
    ecosystem: null,
    published: v.dateAdded || null,
    updated: v.dateAdded || null,
    url: `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
    kevUrl: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    references: [],
  };
}

async function fetchKev(root, { ttlMs, limit = 60 }) {
  const cached = cache.get(root, 'intel', 'cisa-kev', ttlMs);
  if (cached) return cached;
  const res = await requestJson(CISA_KEV, { timeoutMs: 20000 });
  if (!res.ok || !res.data || !Array.isArray(res.data.vulnerabilities)) return null;
  const items = res.data.vulnerabilities
    .slice()
    .sort((a, b) => String(b.dateAdded).localeCompare(String(a.dateAdded)))
    .slice(0, limit)
    .map(mapKev);
  cache.set(root, 'intel', 'cisa-kev', items);
  return items;
}

/** The full KEV CVE id set - used by the scoring engine to flag exploited CVEs. */
async function fetchKevIdSet(root, { ttlMs = 12 * 3600 * 1000, offline = false } = {}) {
  if (offline) return new Set();
  const cached = cache.get(root, 'intel', 'cisa-kev-ids', ttlMs);
  if (cached) return new Set(cached);
  const res = await requestJson(CISA_KEV, { timeoutMs: 20000, retries: 1 });
  if (!res.ok || !res.data || !Array.isArray(res.data.vulnerabilities)) return new Set();
  const ids = res.data.vulnerabilities.map(v => v.cveID).filter(Boolean);
  cache.set(root, 'intel', 'cisa-kev-ids', ids);
  return new Set(ids);
}

/* ------------------------- repo cross-referencing -------------------------- */

function buildRepoIndex(report) {
  const byName = new Map();
  if (report) {
    for (const p of report.packages) {
      if (!byName.has(p.name)) byName.set(p.name, []);
      byName.get(p.name).push(p);
    }
  }
  const advisoryIds = new Set();
  if (report) {
    for (const f of report.findings) {
      if (f.identifier) advisoryIds.add(f.identifier.toUpperCase());
    }
  }
  return { byName, advisoryIds };
}

/** Does this intel item touch the scanned repo? Returns null or match detail. */
function matchAgainstRepo(item, index) {
  // direct advisory-id match (already surfaced by the OSV scan)
  const ids = [item.cve, item.ghsa, item.identifier].filter(Boolean).map(s => s.toUpperCase());
  for (const id of ids) {
    if (index.advisoryIds.has(id)) {
      return { reason: 'advisory-in-scan', packages: [], note: 'This advisory is already flagged in your latest scan.' };
    }
  }
  // package-name match (catches malware campaigns + advisories not yet in OSV)
  const hits = [];
  for (const pkg of item.packages || []) {
    const installed = index.byName.get(pkg.name);
    if (!installed) continue;
    for (const inst of installed) {
      let inRange = true;
      if (pkg.vulnerableRange && inst.version && semver.valid(inst.version)) {
        try {
          inRange = semver.satisfies(inst.version, pkg.vulnerableRange.replace(/,/g, ' '), { includePrerelease: true });
        } catch { inRange = true; }
      }
      hits.push({ name: inst.name, version: inst.version, direct: inst.direct, inRange });
    }
  }
  if (hits.length) {
    const affected = hits.filter(h => h.inRange);
    return {
      reason: affected.length ? 'package-version-affected' : 'package-present',
      packages: hits,
      note: affected.length
        ? `Installed ${affected.map(h => `${h.name}@${h.version}`).join(', ')} falls in the affected range.`
        : `You install ${hits.map(h => h.name).join(', ')}, but not an affected version.`,
    };
  }
  return null;
}

/**
 * @param {string} root        target repo root (for the cache)
 * @param {object|null} report latest scan report, for cross-referencing
 * @param {object} opts        { offline, ttlHours, limit }
 */
async function getGlobalIntel(root, report, opts = {}) {
  const { offline = false, ttlHours = 6, limit = 120 } = opts;
  const ttlMs = ttlHours * 3600 * 1000;

  if (offline) {
    return {
      items: [], sources: [], degraded: true,
      note: 'Offline mode - global threat intelligence feeds are disabled.',
    };
  }

  const [malware, advisories, kev] = await Promise.all([
    fetchGithub(root, { kind: 'malware', ecosystem: 'npm', perPage: 50, ttlMs }).catch(() => null),
    fetchGithub(root, { kind: 'advisory', ecosystem: 'npm', perPage: 60, ttlMs }).catch(() => null),
    fetchKev(root, { ttlMs, limit: 50 }).catch(() => null),
  ]);

  const sources = [
    { name: 'GitHub Security (malware)', ok: !!malware, count: malware ? malware.length : 0, url: 'https://github.com/advisories?query=type%3Amalware' },
    { name: 'GitHub Advisory DB', ok: !!advisories, count: advisories ? advisories.length : 0, url: 'https://github.com/advisories' },
    { name: 'CISA KEV', ok: !!kev, count: kev ? kev.length : 0, url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' },
  ];

  const index = buildRepoIndex(report);
  const all = [...(malware || []), ...(advisories || []), ...(kev || [])];

  for (const item of all) {
    const m = matchAgainstRepo(item, index);
    item.affectsRepo = !!m;
    item.repoMatch = m;
  }

  // Items that touch this repo are pinned to the top so the `limit` slice can
  // never drop them; everything else is ordered newest-first. The client
  // re-sorts the returned set (severity / malware / package / ...), so this
  // ordering only decides what survives the cap.
  const ts = (i) => new Date(i.published || 0).getTime() || 0;
  all.sort((a, b) => {
    if (a.affectsRepo !== b.affectsRepo) return a.affectsRepo ? -1 : 1;
    return ts(b) - ts(a);
  });

  const degraded = sources.some(s => !s.ok);
  return {
    items: all.slice(0, limit),
    sources,
    degraded,
    fetchedAt: new Date().toISOString(),
    stats: {
      total: all.length,
      affectingRepo: all.filter(i => i.affectsRepo).length,
      malware: all.filter(i => i.kind === 'malware').length,
      exploited: all.filter(i => i.kind === 'exploited').length,
      critical: all.filter(i => i.severity === 'critical').length,
    },
    note: degraded ? 'One or more upstream feeds were unreachable; showing what resolved.' : null,
  };
}

module.exports = { getGlobalIntel, fetchKevIdSet, SEV_RANK };
