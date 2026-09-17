/**
 * Risk scoring.
 *
 *   packageRisk(findings)  -> 0..100 for one package   (100 = worst)
 *   postureScore(packages) -> 0..100 for the project   (100 = clean)  [legacy]
 *   computePosture(input)  -> multi-factor posture with a transparent breakdown
 *
 * The posture model is deliberately explainable: five weighted bands, each
 * scored 0..100 on its own terms, each carrying the evidence that moved it.
 * A single number nobody can interrogate is not useful to a security team.
 *
 *   Vulnerability burden  35%  severity-weighted advisories, direct weighted 2x
 *   Exploitability        25%  CISA-KEV / in-the-wild, unfixable, reachable
 *   Supply-chain trust    20%  malware, typosquats, lockfile, pinned versions
 *   Maintenance health    12%  deprecations, abandonment, stale releases
 *   Runtime posture        8%  blocked agent events, time-decayed
 */

const FINDING_WEIGHT = {
  malicious: 100,
  'typosquat-high': 92,
  'typosquat-suspect': 68,
  'vuln-critical': 86,
  'vuln-high': 62,
  'vuln-moderate': 36,
  'vuln-low': 16,
  deprecated: 30,
  unresolved: 8,
};

function weightForFinding(f) {
  if (f.type === 'malicious') return FINDING_WEIGHT.malicious;
  if (f.type === 'typosquat') {
    return f.confidence >= 0.8 ? FINDING_WEIGHT['typosquat-high'] : FINDING_WEIGHT['typosquat-suspect'];
  }
  if (f.type === 'vulnerability') return FINDING_WEIGHT[`vuln-${f.severity}`] ?? FINDING_WEIGHT['vuln-moderate'];
  if (f.type === 'deprecated') return FINDING_WEIGHT.deprecated;
  if (f.type === 'unresolved') return FINDING_WEIGHT.unresolved;
  return 10;
}

function packageRisk(findings) {
  if (!findings.length) return 5;
  const weights = findings.map(weightForFinding).sort((a, b) => b - a);
  let risk = weights[0];
  for (let i = 1; i < weights.length; i++) risk += weights[i] * 0.15;
  return Math.min(100, Math.round(risk));
}

function categoryFor(risk) {
  if (risk >= 75) return 'critical';
  if (risk >= 35) return 'warning';
  return 'safe';
}

function gradeFor(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 55) return 'D';
  return 'F';
}

/** Human label + one-line meaning for a grade, for the UI. */
function gradeMeta(score) {
  const grade = gradeFor(score);
  const table = {
    A: { label: 'Strong',    tone: 'success', blurb: 'No material supply-chain exposure detected.' },
    B: { label: 'Good',      tone: 'success', blurb: 'Minor issues; no critical exposure on direct dependencies.' },
    C: { label: 'Fair',      tone: 'warning', blurb: 'Real exposure present. Prioritise the direct-dependency fixes.' },
    D: { label: 'Poor',      tone: 'danger',  blurb: 'Significant exposure. Patch before the next release.' },
    F: { label: 'Critical',  tone: 'danger',  blurb: 'Severe or actively exploited exposure. Treat as an incident.' },
  };
  return { grade, score, ...table[grade] };
}

/* ------------------------------ legacy simple ----------------------------- */
function postureScore(packages) {
  let penalty = 0;
  for (const p of packages) {
    const directMult = p.direct ? 1 : 0.5;
    if (p.category === 'critical') penalty += 12 * directMult;
    else if (p.category === 'warning') penalty += 4.5 * directMult;
    if (p.deprecated) penalty += 1.5 * directMult;
  }
  return Math.max(0, Math.min(100, Math.round(100 - penalty)));
}

/* --------------------------- multi-factor posture -------------------------- */

const BANDS = [
  { key: 'vulnerability', label: 'Vulnerability burden', weight: 0.35 },
  { key: 'exploitability', label: 'Exploitability',      weight: 0.25 },
  { key: 'supplyChain',    label: 'Supply-chain trust',  weight: 0.20 },
  { key: 'maintenance',    label: 'Maintenance health',  weight: 0.12 },
  { key: 'runtime',        label: 'Runtime posture',     weight: 0.08 },
];

const clamp = (n) => Math.max(0, Math.min(100, n));
/** Saturating penalty: k controls how fast the band degrades. */
const decayTo = (penalty, k) => clamp(Math.round(100 * Math.exp(-penalty / k)));

/**
 * How much of a finding's weight survives remediation.
 *   installed  -> the pinned version is already what resolves: risk is gone
 *   pending    -> package.json carries the fix but `npm install` has not run:
 *                 the exposure is scheduled for removal, not yet removed
 */
function remediationFactor(state) {
  if (!state || !state.applied) return 1;
  if (state.installed) return 0;
  return state.pending ? 0.25 : 1;
}

function bandVulnerability(packages, remediated, ignored) {
  const SEV = { critical: 10, high: 6, moderate: 2.5, low: 0.8 };
  let penalty = 0;
  const evidence = [];
  let crit = 0, high = 0, mod = 0, low = 0, directHit = 0;
  let fixedCount = 0, pendingCount = 0;
  let ignoredCount = 0;
  for (const p of packages) {
    if (ignored && ignored.has(p.name)) {
      ignoredCount += p.findings.filter(f => f.type === 'vulnerability').length;
      continue;                                  // explicitly accepted risk
    }
    const rem = remediated && remediated.get(p.name);
    const factor = remediationFactor(rem);
    if (rem && rem.applied) {
      const vulnCount = p.findings.filter(f => f.type === 'vulnerability').length;
      if (vulnCount) {
        if (rem.installed) fixedCount += vulnCount;
        else if (rem.pending) pendingCount += vulnCount;
      }
    }
    for (const f of p.findings) {
      if (f.type !== 'vulnerability') continue;
      const base = SEV[f.severity] ?? SEV.moderate;
      const reach = p.direct ? 2 : 1;           // direct deps are reachable from your code
      penalty += base * reach * factor;
      if (f.severity === 'critical') crit++;
      else if (f.severity === 'high') high++;
      else if (f.severity === 'moderate') mod++;
      else low++;
      if (p.direct) directHit++;
    }
  }
  if (crit) evidence.push({ tone: 'bad', text: `${crit} critical advisor${crit === 1 ? 'y' : 'ies'}` });
  if (high) evidence.push({ tone: 'bad', text: `${high} high-severity advisor${high === 1 ? 'y' : 'ies'}` });
  if (mod) evidence.push({ tone: 'warn', text: `${mod} moderate` });
  if (low) evidence.push({ tone: 'warn', text: `${low} low` });
  if (directHit) evidence.push({ tone: 'bad', text: `${directHit} on direct dependencies (2× weight)` });
  if (!crit && !high && !mod && !low) evidence.push({ tone: 'good', text: 'No known advisories in the tree' });
  if (fixedCount) evidence.push({ tone: 'good', text: `${fixedCount} advisor${fixedCount === 1 ? 'y' : 'ies'} remediated and installed` });
  if (pendingCount) evidence.push({ tone: 'good', text: `${pendingCount} advisor${pendingCount === 1 ? 'y' : 'ies'} fixed in package.json — pending npm install` });
  if (ignoredCount) evidence.push({ tone: 'warn', text: `${ignoredCount} advisor${ignoredCount === 1 ? 'y' : 'ies'} excluded as accepted risk` });
  return { score: decayTo(penalty, 45), penalty: Math.round(penalty), evidence, fixedCount, pendingCount, ignoredCount };
}

function bandExploitability(packages, kevSet, remediated, ignored) {
  let penalty = 0;
  const evidence = [];
  let kevHits = 0, noFix = 0, directCrit = 0;
  for (const p of packages) {
    if (ignored && ignored.has(p.name)) continue;   // accepted risk
    const factor = remediationFactor(remediated && remediated.get(p.name));
    for (const f of p.findings) {
      if (f.type !== 'vulnerability') continue;
      const id = (f.identifier || '').toUpperCase();
      if (kevSet && kevSet.has(id)) {
        kevHits++;
        penalty += (p.direct ? 30 : 18) * factor;   // actively exploited in the wild
      }
      if (!f.fixedVersion && (f.severity === 'critical' || f.severity === 'high')) {
        noFix++;
        penalty += 6 * factor;                      // nowhere to upgrade to
      }
      if (p.direct && f.severity === 'critical') { directCrit++; penalty += 10 * factor; }
    }
  }
  if (kevHits) evidence.push({ tone: 'bad', text: `${kevHits} CVE(s) on the CISA Known-Exploited list` });
  if (directCrit) evidence.push({ tone: 'bad', text: `${directCrit} critical on a direct dependency` });
  if (noFix) evidence.push({ tone: 'warn', text: `${noFix} high/critical with no published fix` });
  if (!kevHits && !directCrit && !noFix) evidence.push({ tone: 'good', text: 'Nothing known-exploited; fixes available' });
  return { score: decayTo(penalty, 40), penalty: Math.round(penalty), evidence, kevHits };
}

function bandSupplyChain(packages, counts, lockfilePresent) {
  let penalty = 0;
  const evidence = [];
  const malicious = counts.malicious || 0;
  const typo = counts.typosquat || 0;
  const unresolved = counts.unresolved || 0;
  penalty += malicious * 60;
  penalty += typo * 22;
  penalty += Math.min(unresolved, 25) * 0.8;
  if (!lockfilePresent) { penalty += 25; evidence.push({ tone: 'bad', text: 'No lockfile - installs are not reproducible' }); }
  else evidence.push({ tone: 'good', text: 'Lockfile present - versions pinned' });
  if (malicious) evidence.push({ tone: 'bad', text: `${malicious} known-malicious package(s)` });
  if (typo) evidence.push({ tone: 'bad', text: `${typo} typosquat suspect(s)` });
  if (unresolved) evidence.push({ tone: 'warn', text: `${unresolved} package(s) without a pinned version` });
  if (!malicious && !typo) evidence.push({ tone: 'good', text: 'No malware or name-confusion signals' });
  return { score: decayTo(penalty, 38), penalty: Math.round(penalty), evidence };
}

function bandMaintenance(packages) {
  let penalty = 0;
  const evidence = [];
  let deprecated = 0, stale = 0, directDeprecated = 0;
  for (const p of packages) {
    if (p.deprecated) {
      deprecated++;
      penalty += p.direct ? 9 : 3;
      if (p.direct) directDeprecated++;
    }
    const days = p.registry && p.registry.daysSincePublish;
    if (typeof days === 'number' && days > 730 && p.direct) { stale++; penalty += 4; }
  }
  if (deprecated) evidence.push({ tone: 'warn', text: `${deprecated} deprecated package(s)${directDeprecated ? `, ${directDeprecated} direct` : ''}` });
  if (stale) evidence.push({ tone: 'warn', text: `${stale} direct dep(s) with no release in 2+ years` });
  if (!deprecated && !stale) evidence.push({ tone: 'good', text: 'Dependencies are actively maintained' });
  return { score: decayTo(penalty, 30), penalty: Math.round(penalty), evidence };
}

function bandRuntime(logs) {
  const now = Date.now();
  let penalty = 0;
  let blocked = 0, flagged = 0;
  for (const l of logs || []) {
    const t = new Date(l.timestamp).getTime();
    if (!Number.isFinite(t)) continue;
    const ageH = (now - t) / 3600000;
    if (!(ageH >= 0) || ageH > 168) continue;        // one week window
    const decay = Math.exp(-ageH / 48);               // ~2-day half-life
    if (l.status === 'BLOCKED') { blocked++; penalty += 14 * decay; }
    else if (l.severity === 'warning') { flagged++; penalty += 4 * decay; }
  }
  const evidence = [];
  if (blocked) evidence.push({ tone: 'bad', text: `${blocked} blocked runtime event(s) in the last 7 days` });
  if (flagged) evidence.push({ tone: 'warn', text: `${flagged} flagged runtime event(s)` });
  if (!blocked && !flagged) evidence.push({ tone: 'good', text: 'No rogue runtime behaviour observed' });
  return { score: decayTo(penalty, 35), penalty: Math.round(penalty), evidence, blocked };
}

/**
 * @param {object} input { packages, counts, lockfilePresent, logs, kevSet }
 * @returns {{ score, grade, meta, bands, headline }}
 */
function computePosture(input = {}) {
  const {
    packages = [], counts = {}, lockfilePresent = false, logs = [], kevSet = null,
    remediated = null, ignored = null,
  } = input;

  const computed = {
    vulnerability: bandVulnerability(packages, remediated, ignored),
    exploitability: bandExploitability(packages, kevSet, remediated, ignored),
    supplyChain: bandSupplyChain(packages, counts, lockfilePresent),
    maintenance: bandMaintenance(packages),
    runtime: bandRuntime(logs),
  };

  let total = 0;
  const bands = BANDS.map(b => {
    const c = computed[b.key];
    total += c.score * b.weight;
    return {
      key: b.key,
      label: b.label,
      weight: b.weight,
      score: c.score,
      // points of the final 100 this band is currently contributing / losing
      contributes: Math.round(c.score * b.weight * 10) / 10,
      maxContribution: Math.round(b.weight * 100),
      evidence: c.evidence,
    };
  });

  const score = clamp(Math.round(total));
  const worst = [...bands].sort((a, b) => a.score - b.score)[0];

  return {
    score,
    ...gradeMeta(score),
    bands,
    kevHits: computed.exploitability.kevHits || 0,
    blockedRuntime: computed.runtime.blocked || 0,
    remediation: {
      // only count packages whose fix is actually in the manifest - a bare
      // registry entry with no manifest pin has not changed anything
      packages: remediated ? [...remediated.values()].filter(r => r.applied).length : 0,
      registryOnly: remediated ? [...remediated.values()].filter(r => !r.applied).length : 0,
      advisoriesFixed: computed.vulnerability.fixedCount || 0,
      advisoriesPending: computed.vulnerability.pendingCount || 0,
    },
    accepted: {
      packages: ignored ? ignored.size : 0,
      advisories: computed.vulnerability.ignoredCount || 0,
    },
    headline: worst && worst.score < 90
      ? `${worst.label} is the biggest drag (${worst.score}/100).`
      : 'All scoring bands are healthy.',
  };
}

/**
 * @param {object} counts  aggregate tallies from the scan
 * @param {object} [ctx]   { directCritical, directHigh, typosquatHigh }
 */
function statusFor(counts, ctx = {}) {
  const { directCritical = 0, directHigh = 0, typosquatHigh = 0 } = ctx;
  if (counts.malicious > 0 || typosquatHigh > 0 || directCritical > 0) return 'CRITICAL';
  if (counts.critical > 0 || directHigh > 0 || counts.high >= 5) return 'HIGH-RISK';
  if (counts.high > 0 || counts.moderate > 0 || counts.warning > 0 || counts.deprecated > 0 || counts.typosquat > 0) return 'WARNING';
  return 'SECURE';
}

module.exports = {
  packageRisk, categoryFor, postureScore, gradeFor, gradeMeta,
  statusFor, weightForFinding, computePosture, BANDS,
};
