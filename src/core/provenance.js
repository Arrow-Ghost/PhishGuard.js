/**
 * Supply-chain provenance & publisher-trust analysis.
 *
 * Answers the question no advisory feed can: *who can put code into your app,
 * and can you verify that what they published came from the source they claim?*
 *
 * Everything here is read from the npm registry packument:
 *   maintainers[]        - the human accounts that can publish this package.
 *                          A compromised npm account is the single most common
 *                          root cause of real supply-chain attacks.
 *   repository.url       - where the source is meant to live (no repo = opaque)
 *   dist.signatures      - registry signature (npm signs everything modern)
 *   dist.attestations    - BUILD PROVENANCE: a sigstore attestation tying the
 *                          tarball to a public CI run and a git commit. This is
 *                          the only signal that proves the published artifact
 *                          was built from the source you can actually read.
 *
 * Aggregated into a publisher reach graph, a bus factor, and a verifiability
 * breakdown for the repository being scanned.
 */

const { requestJson, pool } = require('./http');
const cache = require('./cache');

const REGISTRY = 'https://registry.npmjs.org';

function registryUrl(name) {
  return name.startsWith('@')
    ? `${REGISTRY}/@${encodeURIComponent(name.slice(1))}`
    : `${REGISTRY}/${encodeURIComponent(name)}`;
}

function parseRepo(raw) {
  if (!raw) return { host: null, slug: null, url: null };
  const url = typeof raw === 'string' ? raw : raw.url;
  if (!url || typeof url !== 'string') return { host: null, slug: null, url: null };
  const clean = url
    .replace(/^git\+/, '')
    .replace(/^git:\/\//, 'https://')
    .replace(/^ssh:\/\/git@/, 'https://')
    .replace(/^git@([^:]+):/, 'https://$1/')
    .replace(/\.git$/, '');
  try {
    const u = new URL(clean);
    const host = u.hostname.replace(/^www\./, '');
    const slug = u.pathname.replace(/^\/+/, '').split('/').slice(0, 2).join('/');
    return { host, slug: slug || null, url: slug ? `https://${host}/${slug}` : `https://${host}` };
  } catch {
    return { host: null, slug: null, url: null };
  }
}

/** Pull the provenance-relevant slice out of one packument. */
function extract(packument, installedVersion) {
  const versions = packument.versions || {};
  const latestTag = (packument['dist-tags'] || {}).latest;
  // prefer the version actually installed; fall back to latest
  const vMeta = (installedVersion && versions[installedVersion]) || (latestTag && versions[latestTag]) || {};
  const dist = vMeta.dist || {};
  const maintainers = (packument.maintainers || [])
    .map(m => (typeof m === 'string' ? m.split('<')[0].trim() : m && m.name))
    .filter(Boolean);
  const repo = parseRepo(packument.repository || vMeta.repository);
  const time = packument.time || {};

  return {
    name: packument.name,
    latest: latestTag || null,
    maintainers,
    maintainerCount: maintainers.length,
    repoHost: repo.host,
    repoSlug: repo.slug,
    repoUrl: repo.url,
    hasSignature: Array.isArray(dist.signatures) && dist.signatures.length > 0,
    hasAttestation: !!(dist.attestations && dist.attestations.url),
    attestationUrl: (dist.attestations && dist.attestations.url) || null,
    license: vMeta.license || packument.license || null,
    created: time.created || null,
    modified: time.modified || null,
    checkedVersion: (installedVersion && versions[installedVersion]) ? installedVersion : latestTag || null,
  };
}

async function fetchOne(root, name, installedVersion, ttlMs, offline) {
  if (offline) return null;
  const key = name + '@' + (installedVersion || 'latest');
  const cached = cache.get(root, 'provenance', key, ttlMs);
  if (cached) return cached;
  const res = await requestJson(registryUrl(name), { timeoutMs: 20000, retries: 1 });
  if (!res.ok || !res.data) return null;
  const out = extract(res.data, installedVersion);
  cache.set(root, 'provenance', key, out);
  return out;
}

/**
 * Rank which packages are worth spending a registry call on: every direct
 * dependency, everything the scan flagged, then the transitive packages that
 * the most other packages depend on (highest blast radius).
 */
function selectPackages(report, limit) {
  const dependents = new Map();
  for (const p of report.packages) {
    for (const parent of p.parents || []) {
      dependents.set(parent, (dependents.get(parent) || 0) + 1);
    }
  }
  const scored = report.packages.map(p => ({
    pkg: p,
    dependents: dependents.get(p.name) || 0,
    priority: (p.direct ? 1000 : 0) + (p.category !== 'safe' ? 500 : 0) + (dependents.get(p.name) || 0),
  }));
  scored.sort((a, b) => b.priority - a.priority || a.pkg.name.localeCompare(b.pkg.name));
  return scored.slice(0, limit);
}

/**
 * @param {string} root    target repo (cache location)
 * @param {object} report  latest scan report
 * @param {object} opts    { offline, cacheTtlHours, limit, onProgress }
 */
async function analyseProvenance(root, report, opts = {}) {
  const { offline = false, cacheTtlHours = 72, limit = 120, onProgress } = opts;
  const ttlMs = cacheTtlHours * 3600 * 1000;

  if (!report) {
    return { available: false, reason: 'No scan yet - run a scan first.', packages: [], publishers: [] };
  }
  if (offline) {
    return { available: false, reason: 'Offline mode - registry provenance lookups are disabled.', packages: [], publishers: [] };
  }

  const selected = selectPackages(report, limit);
  let done = 0;
  const results = await pool(selected, 8, async (entry) => {
    const meta = await fetchOne(root, entry.pkg.name, entry.pkg.version, ttlMs, offline);
    done++;
    if (onProgress) onProgress(done, selected.length);
    if (!meta) return null;
    return {
      ...meta,
      installedVersion: entry.pkg.version,
      direct: entry.pkg.direct,
      dev: entry.pkg.dev,
      category: entry.pkg.category,
      riskScore: entry.pkg.riskScore,
      dependents: entry.dependents,
    };
  });

  const packages = results.filter(Boolean);
  if (!packages.length) {
    return { available: false, reason: 'Could not reach the npm registry.', packages: [], publishers: [] };
  }

  /* ------------------------- publisher reach graph ------------------------ */
  const byPublisher = new Map();
  for (const p of packages) {
    for (const m of p.maintainers) {
      if (!byPublisher.has(m)) byPublisher.set(m, { name: m, packages: [], direct: 0, reach: 0 });
      const entry = byPublisher.get(m);
      entry.packages.push({
        name: p.name,
        version: p.installedVersion,
        direct: p.direct,
        soleOwner: p.maintainerCount === 1,
        dependents: p.dependents,
      });
      if (p.direct) entry.direct++;
      // reach = packages they can publish, plus everything downstream of those
      entry.reach += 1 + p.dependents;
    }
  }
  const publishers = [...byPublisher.values()]
    .map(e => ({
      ...e,
      count: e.packages.length,
      soleOwnerOf: e.packages.filter(p => p.soleOwner).length,
    }))
    .sort((a, b) => b.count - a.count || b.reach - a.reach || a.name.localeCompare(b.name));

  /* ------------------------------ bus factor ----------------------------- */
  // How few accounts, compromised together, cover half the analysed tree.
  const half = Math.ceil(packages.length / 2);
  const covered = new Set();
  let busFactor = 0;
  for (const pub of publishers) {
    if (covered.size >= half) break;
    busFactor++;
    for (const p of pub.packages) covered.add(p.name);
  }

  /* --------------------------- verifiability ----------------------------- */
  const attested = packages.filter(p => p.hasAttestation);
  const signedOnly = packages.filter(p => !p.hasAttestation && p.hasSignature);
  const unverified = packages.filter(p => !p.hasAttestation && !p.hasSignature);
  const singleMaintainer = packages.filter(p => p.maintainerCount === 1);
  const noRepo = packages.filter(p => !p.repoUrl);

  const hostCounts = new Map();
  for (const p of packages) {
    const h = p.repoHost || 'no public repo';
    hostCounts.set(h, (hostCounts.get(h) || 0) + 1);
  }
  const hosts = [...hostCounts.entries()]
    .map(([host, count]) => ({ host, count }))
    .sort((a, b) => b.count - a.count);

  /* ------------------------------ top risks ------------------------------ */
  const risks = packages
    .map(p => {
      const reasons = [];
      let weight = 0;
      if (p.maintainerCount === 1) { reasons.push('Single maintainer - one account takeover replaces it'); weight += 40; }
      if (!p.repoUrl) { reasons.push('No public source repository to audit'); weight += 30; }
      if (!p.hasSignature) { reasons.push('Tarball is unsigned'); weight += 25; }
      if (!p.hasAttestation) { reasons.push('No build provenance - cannot prove it was built from its source'); weight += 20; }
      if (p.direct) weight += 15;
      weight += Math.min(20, p.dependents * 2);
      return { ...p, reasons, weight };
    })
    .filter(p => p.reasons.length)
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 25);

  return {
    available: true,
    analysedAt: new Date().toISOString(),
    coverage: { analysed: packages.length, totalInTree: report.counts.total, limit },
    stats: {
      publishers: publishers.length,
      busFactor,
      attested: attested.length,
      signedOnly: signedOnly.length,
      unverified: unverified.length,
      singleMaintainer: singleMaintainer.length,
      noRepo: noRepo.length,
      attestedPct: Math.round((attested.length / packages.length) * 100),
    },
    publishers: publishers.slice(0, 40),
    hosts,
    risks,
    packages: packages.map(p => ({
      name: p.name,
      version: p.installedVersion,
      direct: p.direct,
      maintainers: p.maintainers,
      maintainerCount: p.maintainerCount,
      repoHost: p.repoHost,
      repoUrl: p.repoUrl,
      hasSignature: p.hasSignature,
      hasAttestation: p.hasAttestation,
      attestationUrl: p.attestationUrl,
      dependents: p.dependents,
      license: p.license,
    })),
  };
}

module.exports = { analyseProvenance, parseRepo };
