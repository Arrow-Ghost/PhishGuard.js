/**
 * Remediation engine - the part of PhishGuard that actually changes the repo.
 *
 * Everything here writes to the target project's real package.json, so every
 * mutation is:
 *   1. planned first  (planQuarantine / planAll produce an exact before/after)
 *   2. backed up      (.phishguard/backups/package.json.<timestamp>.bak)
 *   3. reversible     (restore() puts the most recent backup back)
 *
 * Strategy selection is what makes this correct rather than theatrical:
 *
 *   direct dependency + a published fix  -> raise the range in dependencies
 *   direct dependency + no fix           -> remove it (destructive: flagged loudly)
 *   transitive dependency + a fix        -> npm "overrides" entry forcing the
 *                                           safe version. You cannot uninstall a
 *                                           transitive package; an override is
 *                                           the supported way to pin one.
 *   transitive dependency + no fix       -> registry-only quarantine, no edit
 *
 * PhishGuard never runs `npm install` for you - it reports the command to run.
 */

const fs = require('fs');
const path = require('path');
const semver = require('semver');

const DEP_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];

function manifestPath(root) {
  return path.join(root, 'package.json');
}

function readManifest(root) {
  const file = manifestPath(root);
  const raw = fs.readFileSync(file, 'utf8');
  return { file, raw, json: JSON.parse(raw) };
}

/** Preserve the file's existing indentation so the diff stays minimal. */
function detectIndent(raw) {
  const m = raw.match(/\n(\s+)"/);
  return m ? m[1] : '  ';
}

function backupDir(root) {
  const dir = path.join(root, '.phishguard', 'backups');
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeBackup(root, raw) {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const file = path.join(backupDir(root), `package.json.${stamp}.bak`);
  fs.writeFileSync(file, raw, 'utf8');
  return file;
}

function listBackups(root) {
  const dir = path.join(root, '.phishguard', 'backups');
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .filter(f => f.startsWith('package.json.') && f.endsWith('.bak'))
    .map(f => {
      const full = path.join(dir, f);
      const st = fs.statSync(full);
      return { file: f, path: full, savedAt: st.mtime.toISOString(), bytes: st.size };
    })
    .sort((a, b) => b.savedAt.localeCompare(a.savedAt));
}

/**
 * What a restore would change, before doing it.
 *
 * Restore rewrites the whole manifest, so it can also undo edits PhishGuard
 * never made (a script you fixed, a dependency you added). Surfacing those
 * up front is the difference between an undo and a surprise.
 */
function previewRestore(root, backupFile) {
  const backups = listBackups(root);
  if (!backups.length) throw new Error('No PhishGuard backups found for this project.');
  const chosen = backupFile ? backups.find(b => b.file === backupFile) : backups[0];
  if (!chosen) throw new Error(`Backup not found: ${backupFile}`);

  const current = JSON.parse(fs.readFileSync(manifestPath(root), 'utf8'));
  const target = JSON.parse(fs.readFileSync(chosen.path, 'utf8'));

  const keys = [...new Set([...Object.keys(current), ...Object.keys(target)])];
  const managed = new Set(['overrides', 'dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']);
  const changes = [];
  for (const k of keys) {
    const a = JSON.stringify(current[k]);
    const b = JSON.stringify(target[k]);
    if (a === b) continue;
    changes.push({ key: k, phishguardManaged: managed.has(k) });
  }
  return {
    backup: chosen.file,
    savedAt: chosen.savedAt,
    changes,
    // keys PhishGuard never edits - reverting these is probably not intended
    collateral: changes.filter(c => !c.phishguardManaged).map(c => c.key),
  };
}

function restore(root, backupFile) {
  const backups = listBackups(root);
  if (!backups.length) throw new Error('No PhishGuard backups found for this project.');
  const chosen = backupFile
    ? backups.find(b => b.file === backupFile)
    : backups[0];
  if (!chosen) throw new Error(`Backup not found: ${backupFile}`);
  const raw = fs.readFileSync(chosen.path, 'utf8');
  // Back up the current state too, so a restore is itself undoable.
  const current = fs.readFileSync(manifestPath(root), 'utf8');
  const safety = writeBackup(root, current);
  fs.writeFileSync(manifestPath(root), raw, 'utf8');
  return {
    restoredFrom: chosen.file,
    savedCurrentTo: path.basename(safety),
    needsInstall: 'npm install',
  };
}

/** Which manifest field declares this package, if any. */
function findField(json, name) {
  for (const f of DEP_FIELDS) {
    if (json[f] && Object.prototype.hasOwnProperty.call(json[f], name)) return f;
  }
  return null;
}

/**
 * Lowest version that clears every advisory currently hitting this package.
 * Advisories carry `fixedVersion` from the OSV scan.
 */
function safeTarget(pkgRecord) {
  const fixes = (pkgRecord.findings || [])
    .filter(f => f.type === 'vulnerability' && f.fixedVersion && semver.valid(f.fixedVersion))
    .map(f => f.fixedVersion)
    .sort(semver.compare);
  if (!fixes.length) return null;
  return fixes[fixes.length - 1]; // highest fix clears all lower ones
}

/**
 * The highest fix that stays inside the installed major version.
 * Upgrading across a major is the single most common way an automated
 * "fix" breaks a build, so it must never be the silent default.
 */
function inRangeTarget(pkgRecord) {
  const cur = pkgRecord.version;
  if (!cur || !semver.valid(cur)) return null;
  const major = semver.major(cur);
  const fixes = (pkgRecord.findings || [])
    .filter(f => f.type === 'vulnerability' && f.fixedVersion && semver.valid(f.fixedVersion))
    .map(f => f.fixedVersion)
    .filter(v => semver.major(v) === major)
    .sort(semver.compare);
  return fixes.length ? fixes[fixes.length - 1] : null;
}

function advisoriesCleared(pkgRecord, target) {
  if (!target) return 0;
  return (pkgRecord.findings || []).filter(f => {
    if (f.type !== 'vulnerability') return false;
    if (!f.fixedVersion || !semver.valid(f.fixedVersion)) return false;
    return semver.lte(f.fixedVersion, target);
  }).length;
}

/**
 * Build a concrete, reviewable plan for one package.
 * @returns {object} plan (never mutates anything)
 */
function planQuarantine(root, report, name, opts = {}) {
  const { json } = readManifest(root);
  const pkg = report && report.packages.find(p => p.name === name);
  if (!pkg) throw new Error(`${name} is not in the latest scan. Re-scan and try again.`);

  const field = findField(json, name);
  const isDirect = !!field;
  const fullTarget = safeTarget(pkg);
  const inRange = inRangeTarget(pkg);
  const target = opts.targetVersion || fullTarget;
  const currentRange = field ? json[field][name] : null;

  // Does the chosen target cross a major boundary from what is installed?
  let majorJump = false;
  if (target && pkg.version && semver.valid(target) && semver.valid(pkg.version)) {
    majorJump = semver.major(target) !== semver.major(pkg.version);
  }

  const plan = {
    package: name,
    installedVersion: pkg.version,
    direct: isDirect,
    field,
    currentRange,
    target,
    clears: advisoriesCleared(pkg, target),
    totalAdvisories: (pkg.findings || []).filter(f => f.type === 'vulnerability').length,
    majorJump,
    fromMajor: pkg.version && semver.valid(pkg.version) ? semver.major(pkg.version) : null,
    toMajor: target && semver.valid(target) ? semver.major(target) : null,
    // A safer alternative that keeps you inside the current major, when one exists
    alternative: (inRange && fullTarget && inRange !== fullTarget)
      ? {
          target: inRange,
          clears: advisoriesCleared(pkg, inRange),
          label: `stay on v${semver.major(pkg.version)}`,
        }
      : null,
    warnings: [],
    changes: [],
    strategy: null,
    editsManifest: false,
  };

  const forceRemove = opts.mode === 'remove';

  if (isDirect && target && !forceRemove) {
    plan.strategy = 'upgrade';
    plan.editsManifest = true;
    plan.changes.push({
      op: 'set',
      pointer: `${field}.${name}`,
      from: currentRange,
      to: `^${target}`,
    });
    if (currentRange && semver.validRange(currentRange) && semver.validRange(`^${target}`)) {
      const major = semver.major(target);
      const curMin = semver.minVersion(currentRange);
      if (curMin && semver.major(curMin) !== major) {
        plan.warnings.push(`BREAKING: this jumps ${semver.major(curMin)}.x → ${major}.x. Major upgrades routinely change APIs, config and CLI entry points - expect to fix build scripts and imports afterwards.`);
        if (plan.alternative) {
          plan.warnings.push(`Safer option: pin ^${plan.alternative.target} to stay on v${semver.major(curMin)} - clears ${plan.alternative.clears} of ${plan.totalAdvisories} advisories with no breaking change.`);
        }
        plan.warnings.push('Run your build and test suite immediately after applying, and use Restore if it breaks.');
      }
    }
  } else if (isDirect && (forceRemove || !target)) {
    plan.strategy = 'remove';
    plan.editsManifest = true;
    plan.changes.push({ op: 'delete', pointer: `${field}.${name}`, from: currentRange, to: null });
    plan.warnings.push(`${name} is imported directly by your code. Removing it will break any file that imports it.`);
    if (!target) plan.warnings.push('No fixed version is published, so there is nothing safe to upgrade to.');
  } else if (!isDirect && target) {
    plan.strategy = 'override';
    plan.editsManifest = true;
    const existing = (json.overrides && json.overrides[name]) || null;
    plan.changes.push({ op: 'set', pointer: `overrides.${name}`, from: existing, to: `^${target}` });
    plan.warnings.push(`${name} is transitive, so it cannot be uninstalled. An npm "overrides" entry forces every dependent onto ^${target}.`);
    plan.warnings.push('npm >= 8.3 is required for overrides. yarn uses "resolutions"; pnpm uses "pnpm.overrides".');
    if (majorJump) {
      plan.warnings.push(`BREAKING: this forces a major change (${plan.fromMajor}.x → ${plan.toMajor}.x) on packages that expect the old API. Build and test immediately after applying.`);
      if (plan.alternative) {
        plan.warnings.push(`Safer option: pin ^${plan.alternative.target} - clears ${plan.alternative.clears} of ${plan.totalAdvisories} with no major change.`);
      }
    }
  } else {
    plan.strategy = 'registry-only';
    plan.editsManifest = false;
    plan.warnings.push(`${name} is transitive and has no published fix, so no safe manifest edit exists.`);
    plan.warnings.push('It will be recorded in the quarantine registry and flagged on every future scan.');
  }

  plan.needsInstall = plan.editsManifest ? 'npm install' : null;
  plan.summary = describe(plan);
  return plan;
}

function describe(plan) {
  switch (plan.strategy) {
    case 'upgrade':
      return `Raise ${plan.package} in ${plan.field} from ${plan.currentRange} to ^${plan.target} — clears ${plan.clears} of ${plan.totalAdvisories} advisories.`;
    case 'override':
      return `Pin ${plan.package} to ^${plan.target} via npm overrides — clears ${plan.clears} of ${plan.totalAdvisories} advisories across every dependent.`;
    case 'remove':
      return `Remove ${plan.package} from ${plan.field}.`;
    default:
      return `Record ${plan.package} in the quarantine registry (no safe manifest edit available).`;
  }
}

/** Apply a plan to the real package.json. Backs up first. */
function applyPlan(root, plan) {
  if (!plan.editsManifest) {
    return { applied: false, reason: plan.summary, backup: null, needsInstall: null };
  }
  const { file, raw, json } = readManifest(root);
  const indent = detectIndent(raw);
  const backup = writeBackup(root, raw);

  for (const change of plan.changes) {
    const [head, ...rest] = change.pointer.split('.');
    const key = rest.join('.'); // package names can contain dots (lodash.merge)
    if (change.op === 'delete') {
      if (json[head]) delete json[head][key];
    } else {
      if (!json[head]) json[head] = {};
      json[head][key] = change.to;
    }
  }

  fs.writeFileSync(file, JSON.stringify(json, null, indent) + '\n', 'utf8');
  return {
    applied: true,
    backup: path.basename(backup),
    backupPath: backup,
    file,
    needsInstall: plan.needsInstall,
    summary: plan.summary,
  };
}

/**
 * Every actionable fix in the current scan, ranked by how much risk it removes.
 * This is what the Remediation Center renders.
 */
function planAll(root, report, opts = {}) {
  if (!report) return { available: false, reason: 'No scan yet.', items: [] };
  const { json } = readManifest(root);
  const sevWeight = { critical: 40, high: 22, moderate: 8, low: 2 };

  const items = [];
  for (const pkg of report.packages) {
    const vulns = (pkg.findings || []).filter(f => f.type === 'vulnerability');
    if (!vulns.length) continue;
    const target = safeTarget(pkg);
    const field = findField(json, pkg.name);
    const cleared = advisoriesCleared(pkg, target);
    const risk = vulns.reduce((a, f) => a + (sevWeight[f.severity] || 4), 0);
    const worst = vulns.map(f => f.severity)
      .sort((a, b) => (sevWeight[b] || 0) - (sevWeight[a] || 0))[0];

    items.push({
      package: pkg.name,
      installedVersion: pkg.version,
      direct: !!field,
      field,
      currentRange: field ? json[field][pkg.name] : null,
      target,
      strategy: field ? (target ? 'upgrade' : 'remove') : (target ? 'override' : 'registry-only'),
      advisories: vulns.length,
      clears: cleared,
      worstSeverity: worst,
      identifiers: vulns.map(f => f.identifier).filter(Boolean).slice(0, 4),
      dependents: pkg.parents ? pkg.parents.length : 0,
      // how much of this package's advisory weight the fix removes
      riskRemoved: target ? Math.round((cleared / vulns.length) * risk) : 0,
      riskTotal: risk,
      actionable: !!target,
    });
  }

  items.sort((a, b) =>
    (b.riskRemoved - a.riskRemoved) ||
    (b.direct - a.direct) ||
    a.package.localeCompare(b.package)
  );

  const actionable = items.filter(i => i.actionable);
  return {
    available: true,
    generatedAt: new Date().toISOString(),
    manifest: path.basename(manifestPath(root)),
    packageManager: json.packageManager || null,
    items,
    stats: {
      total: items.length,
      actionable: actionable.length,
      blocked: items.length - actionable.length,
      advisoriesFixable: actionable.reduce((a, i) => a + i.clears, 0),
      advisoriesTotal: items.reduce((a, i) => a + i.advisories, 0),
      directFixes: actionable.filter(i => i.direct).length,
      overrideFixes: actionable.filter(i => i.strategy === 'override').length,
    },
  };
}


/**
 * What has actually been remediated, and whether it has taken effect yet.
 *
 * A quarantine writes package.json, but node_modules is only rebuilt when the
 * developer runs `npm install`. Until then the fix is *committed but pending*:
 * real risk reduction, not yet a real version change. This resolver tells the
 * rest of the app which state each remediated package is in so the score can
 * credit it honestly instead of pretending nothing happened.
 *
 * @returns Map<packageName, { strategy, target, pending, applied, installed }>
 */
function resolveRemediationState(root, report, quarantineRows = []) {
  const state = new Map();
  if (!report) return state;

  let json = {};
  try { json = readManifest(root).json; } catch { /* no manifest */ }

  // A tree can resolve several copies of the same package at different
  // versions. The fix only counts as installed when EVERY copy satisfies the
  // pin - otherwise a vulnerable duplicate is still present.
  const byName = new Map();
  for (const p of report.packages) {
    if (!byName.has(p.name)) byName.set(p.name, []);
    byName.get(p.name).push(p);
  }

  for (const row of quarantineRows) {
    const name = row.name;
    const copies = byName.get(name) || [];

    // Where does the manifest now pin this package?
    const field = findField(json, name);
    const declared = field ? json[field][name] : null;
    const override = (json.overrides && json.overrides[name]) || null;
    const pinned = override || declared;

    let target = null;
    if (pinned) {
      try { const mv = semver.minVersion(pinned); target = mv ? mv.version : null; } catch { target = null; }
    }

    // Every resolved copy must satisfy the pin before the fix counts as live.
    let installedSatisfies = false;
    let unsatisfied = [];
    if (pinned && copies.length) {
      unsatisfied = copies.filter(c => {
        if (!c.version || !semver.valid(c.version)) return true;
        try { return !semver.satisfies(c.version, pinned); } catch { return true; }
      });
      installedSatisfies = unsatisfied.length === 0;
    }

    const applied = !!pinned;                 // manifest carries the fix
    const removed = copies.length === 0;      // no longer resolved in the tree at all

    state.set(name, {
      strategy: override ? 'override' : field ? 'upgrade' : 'registry-only',
      target,
      pinned,
      applied,
      installed: installedSatisfies || removed,
      pending: applied && !installedSatisfies && !removed,
      copies: copies.map(c => c.version),
      stillVulnerable: unsatisfied.map(c => c.version),
      quarantinedAt: row.quarantined_at || null,
    });
  }
  return state;
}

module.exports = {
  resolveRemediationState,
  previewRestore,
  planQuarantine, applyPlan, planAll, restore, listBackups, safeTarget, readManifest,
};
