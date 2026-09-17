/**
 * The scan orchestrator.
 *
 *   resolve manifest + lockfile
 *     -> flat dependency list
 *     -> OSV advisories (live, cached, or offline fallback)
 *     -> npm registry metadata (deprecation, age)
 *     -> typosquatting heuristics
 *     -> per-package risk + project posture score
 *
 * Produces one canonical report object consumed by the CLI, the server API and
 * the persistence layer.
 */

const crypto = require('crypto');
const { readManifest, findLockfile } = require('./resolve');
const { parseLockfile } = require('./lockfile');
const { queryVulnerabilities } = require('./osv');
const { queryRegistry } = require('./registry');
const { checkTyposquat } = require('./typosquat');
const { packageRisk, categoryFor, gradeFor, statusFor, computePosture } = require('./score');

let OFFLINE_MALICIOUS = [];
let OFFLINE_DEPRECATED = {};
try {
  const db = require('../data/offline-advisories.json');
  OFFLINE_MALICIOUS = db.knownMalicious || [];
  OFFLINE_DEPRECATED = db.deprecated || {};
} catch { /* ignore */ }

/**
 * A package whose name resembles a popular one is only a *typosquat suspect* if
 * it also looks freshly-minted / low-reputation. Established packages that
 * happen to be name-close (merge2, postcss-js, jsesc, ...) are not flagged.
 */
function looksEstablished(reg) {
  if (!reg || reg.unresolved) return false;
  if (reg.versionsCount != null && reg.versionsCount >= 4) return true;
  if (reg.daysSincePublish != null && reg.daysSincePublish >= 365) return true;
  if (reg.maintainers != null && reg.maintainers >= 2 && (reg.versionsCount ?? 0) >= 2) return true;
  return false;
}

function hashManifest(manifest) {
  const relevant = JSON.stringify({
    d: manifest.dependencies || {},
    dd: manifest.devDependencies || {},
    od: manifest.optionalDependencies || {},
  });
  return crypto.createHash('sha256').update(relevant).digest('hex').slice(0, 16);
}

/**
 * Full scan of an on-disk project: resolves its manifest + lockfile then analyses.
 * @param {string} root  target project root
 * @param {object} opts  { includeDev, offline, cacheTtlHours, onProgress }
 */
async function scanProject(root, opts = {}) {
  const progress = opts.onProgress || (() => {});
  progress({ phase: 'resolve', message: 'Reading manifest and lockfile' });
  const { manifest } = readManifest(root);
  const lock = findLockfile(root);
  const { packages: rawPackages, source: lockSource } = parseLockfile(manifest, lock, {
    includeDev: opts.includeDev !== false,
  });
  return analyze({ root, manifest, lock, rawPackages, lockSource }, opts);
}

/**
 * Scan a bare manifest object (no lockfile) - used by the dashboard's
 * "paste a package.json" panel. Versions are best-effort from the ranges.
 * @param {object} manifest  parsed package.json
 * @param {object} opts       { cacheRoot, includeDev, offline, onProgress }
 */
async function scanManifest(manifest, opts = {}) {
  const root = opts.cacheRoot || process.cwd();
  const { packages: rawPackages, source: lockSource } = parseLockfile(manifest, null, {
    includeDev: opts.includeDev !== false,
  });
  return analyze({ root, manifest, lock: null, rawPackages, lockSource }, opts);
}

async function analyze({ root, manifest, lock, rawPackages, lockSource }, opts = {}) {
  const started = Date.now();
  const offline = !!opts.offline;
  const cacheTtlMs = (opts.cacheTtlHours ?? 24) * 3600 * 1000;
  const progress = opts.onProgress || (() => {});

  progress({ phase: 'osv', message: `Querying advisories for ${rawPackages.length} packages`, total: rawPackages.length });
  const osv = await queryVulnerabilities(root, rawPackages, {
    offline,
    cacheTtlMs,
    onProgress: (done, total) => progress({ phase: 'osv', done, total }),
  });

  // Pre-compute name-similarity candidates so we can limit registry lookups to
  // packages that actually need metadata (direct deps, vulnerable deps, and
  // typosquat suspects) rather than the entire transitive tree.
  const typoRawByName = new Map();
  for (const pkg of rawPackages) {
    if (!typoRawByName.has(pkg.name)) typoRawByName.set(pkg.name, checkTyposquat(pkg.name));
  }
  const needsRegistry = rawPackages.filter(p => {
    const key = `${p.name}@${p.version}`;
    const hasVuln = (osv.map.get(key)?.advisories || []).length > 0;
    return p.direct || hasVuln || typoRawByName.get(p.name);
  });

  progress({ phase: 'registry', message: `Checking npm registry metadata for ${new Set(needsRegistry.map(p => p.name)).size} packages` });
  const registry = await queryRegistry(root, needsRegistry, {
    offline,
    onProgress: (done, total) => progress({ phase: 'registry', done, total }),
  });

  progress({ phase: 'analyze', message: 'Scoring packages' });

  const maliciousSet = new Set(OFFLINE_MALICIOUS);
  const packages = [];
  const flatFindings = [];
  let directCritical = 0;
  let directHigh = 0;
  let typosquatHigh = 0;
  const counts = {
    total: rawPackages.length, direct: 0, transitive: 0, dev: 0,
    vulnerable: 0, critical: 0, high: 0, moderate: 0, low: 0,
    warning: 0, deprecated: 0, typosquat: 0, malicious: 0, unresolved: 0,
  };

  for (const pkg of rawPackages) {
    const key = `${pkg.name}@${pkg.version}`;
    const advEntry = osv.map.get(key) || { advisories: [] };
    const regEntry = registry.map.get(pkg.name) || {};
    const findings = [];

    // --- vulnerabilities ---
    for (const a of advEntry.advisories) {
      findings.push({
        type: 'vulnerability',
        severity: a.severity, // critical | high | moderate | low
        title: a.title,
        description: a.description,
        identifier: a.identifier,
        cwes: a.cwes || [],
        url: a.url,
        fixedVersion: a.fixedVersion,
        offline: !!a.offline,
      });
    }

    // --- deprecation (registry `deprecated` field, or bundled fallback list) ---
    const deprecationMsg = regEntry.deprecated || OFFLINE_DEPRECATED[pkg.name] || null;
    if (deprecationMsg) {
      findings.push({
        type: 'deprecated',
        severity: 'moderate',
        title: `Package is deprecated${regEntry.deprecatedExactVersion ? ` at v${pkg.version}` : ''}`,
        description: deprecationMsg,
        identifier: null,
        url: regEntry.homepage || `https://www.npmjs.com/package/${pkg.name}`,
        fixedVersion: regEntry.latest && regEntry.latest !== pkg.version ? regEntry.latest : null,
      });
    }

    // --- known malicious ---
    if (maliciousSet.has(pkg.name)) {
      findings.push({
        type: 'malicious',
        severity: 'critical',
        title: 'Package name matches a known-malicious package',
        description: `"${pkg.name}" is on PhishGuard's bundled known-malicious list. Remove it immediately and rotate any secrets it may have had access to.`,
        identifier: null,
        url: null,
        fixedVersion: null,
      });
    }

    // --- typosquatting (suppressed for established / reputable packages) ---
    const typoRaw = typoRawByName.get(pkg.name);
    const typo = typoRaw && !looksEstablished(regEntry) ? typoRaw : null;
    if (typo) {
      findings.push({
        type: 'typosquat',
        severity: typo.confidence >= 0.8 ? 'critical' : 'moderate',
        confidence: typo.confidence,
        title: `Possible typosquat of "${typo.target}"`,
        description: `"${pkg.name}" is very close to the popular package "${typo.target}" (${typo.pattern}, similarity ${typo.similarity}). Confirm this is the package you intended to install.`,
        identifier: null,
        url: `https://www.npmjs.com/package/${typo.target}`,
        fixedVersion: null,
      });
    }

    // --- unresolved version (no lockfile) ---
    if (!pkg.resolved && pkg.version) {
      findings.push({
        type: 'unresolved',
        severity: 'low',
        title: 'Version not pinned by a lockfile',
        description: `No lockfile entry for ${pkg.name}; advisories were checked against ${pkg.version} (lower bound of "${pkg.range}"). Commit a lockfile for exact results.`,
        identifier: null, url: null, fixedVersion: null,
      });
    } else if (!pkg.version) {
      findings.push({
        type: 'unresolved',
        severity: 'low',
        title: 'Version could not be determined',
        description: `Could not resolve a concrete version for ${pkg.name} ("${pkg.range}"). Skipped advisory lookup.`,
        identifier: null, url: null, fixedVersion: null,
      });
    }

    const risk = packageRisk(findings);
    const category = categoryFor(risk);

    // tally
    if (pkg.direct) counts.direct++; else counts.transitive++;
    if (pkg.dev) counts.dev++;
    const vulnFindings = findings.filter(f => f.type === 'vulnerability');
    if (vulnFindings.length) counts.vulnerable++;
    for (const f of vulnFindings) {
      if (f.severity === 'critical') { counts.critical++; if (pkg.direct) directCritical++; }
      else if (f.severity === 'high') { counts.high++; if (pkg.direct) directHigh++; }
      else if (f.severity === 'moderate') counts.moderate++;
      else if (f.severity === 'low') counts.low++;
    }
    if (category === 'warning') counts.warning++;
    if (findings.some(f => f.type === 'deprecated')) counts.deprecated++;
    if (findings.some(f => f.type === 'typosquat')) {
      counts.typosquat++;
      if (typo && typo.confidence >= 0.8) typosquatHigh++;
    }
    if (findings.some(f => f.type === 'malicious')) counts.malicious++;
    if (findings.some(f => f.type === 'unresolved')) counts.unresolved++;

    const record = {
      name: pkg.name,
      version: pkg.version,
      range: pkg.range,
      direct: pkg.direct,
      dev: pkg.dev,
      depth: pkg.depth,
      parents: pkg.parents || [],
      resolved: pkg.resolved,
      riskScore: risk,
      category,
      deprecated: deprecationMsg,
      typosquat: typo || null,
      malicious: maliciousSet.has(pkg.name),
      registry: {
        latest: regEntry.latest || null,
        versionsCount: regEntry.versionsCount ?? null,
        daysSincePublish: regEntry.daysSincePublish ?? null,
        maintainers: regEntry.maintainers ?? null,
        license: regEntry.license || null,
      },
      findings,
    };
    packages.push(record);
    for (const f of findings) {
      flatFindings.push({ packageName: pkg.name, packageVersion: pkg.version, direct: pkg.direct, ...f });
    }
  }

  packages.sort((a, b) => b.riskScore - a.riskScore || a.name.localeCompare(b.name));

  // One scoring model AND one set of inputs, everywhere. The caller supplies the
  // same runtime telemetry, remediation state and accepted-risk list the live
  // dashboard endpoint uses, so a stored scan and the live gauge cannot disagree.
  const posture = computePosture({
    packages,
    counts,
    lockfilePresent: !!lock,
    logs: opts.logs || [],
    kevSet: opts.kevSet || null,
    remediated: opts.remediated || null,
    ignored: opts.ignored || null,
  });
  const score = posture.score;
  const status = statusFor(counts, { directCritical, directHigh, typosquatHigh });
  counts.directCritical = directCritical;
  counts.directHigh = directHigh;

  return {
    project: {
      name: manifest.name || 'unknown',
      version: manifest.version || '0.0.0',
      root,
      manifestHash: hashManifest(manifest),
    },
    lockfile: { source: lockSource, name: lock ? lock.name : null, present: !!lock },
    generatedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    offline: offline || osv.meta.degraded || registry.meta.degraded,
    meta: {
      osv: osv.meta,
      registryDegraded: registry.meta.degraded,
    },
    counts,
    score,
    grade: posture.grade,
    postureLabel: posture.label,
    postureTone: posture.tone,
    postureBands: posture.bands,
    postureHeadline: posture.headline,
    postureRemediation: posture.remediation,
    postureAccepted: posture.accepted,
    bands: posture.bands,
    status,
    packages,
    findings: flatFindings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity)),
  };
}

function severityRank(s) {
  return { critical: 4, high: 3, moderate: 2, low: 1 }[s] || 0;
}

module.exports = { scanProject, scanManifest };
