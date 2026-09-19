/**
 * `phishguard install` orchestration.
 *
 *   1. npm install --ignore-scripts   - nothing untrusted executes yet
 *   2. walk node_modules on disk      - full-tree, free, complete
 *   3. registry lookup, scripts-only  - reputation data for severity, just
 *                                       for the small subset that has scripts
 *   4. classify + gate                - approved scripts run via `npm rebuild`
 *
 * This is the install-time counterpart to `phishguard scan`'s static
 * analysis: most real npm supply-chain attacks (event-stream, ua-parser-js,
 * the node-ipc/chalk maintainer-account compromises) execute here, in a
 * lifecycle script, before any scan or runtime agent is relevant.
 */

const crypto = require('crypto');
const readline = require('readline');
const { spawn } = require('child_process');

const { walkNodeModules } = require('./nodeModulesWalk');
const { queryRegistry } = require('./registry');
const { classifyLifecycleScripts, extractLifecycleScripts } = require('./lifecycle');
const { looksEstablished } = require('./reputation');

function scriptHash(scripts) {
  const combined = Object.entries(scripts || {}).sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`).join('\n');
  return crypto.createHash('sha256').update(combined).digest('hex');
}

function run(cmd, args, opts) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { stdio: 'inherit', ...opts });
    child.on('error', reject);
    child.on('exit', (code) => resolve(code ?? 1));
  });
}

async function promptYesNoAll(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const answer = await new Promise((resolve) => rl.question(question, resolve));
  rl.close();
  return answer.trim().toLowerCase();
}

/**
 * @param {string} root
 * @param {object} opts { passthroughArgs, yes, allow: string[], offline, log }
 * @returns {Promise<{ exitCode, flagged, approved, skipped }>}
 */
async function installGate(root, opts = {}) {
  const log = opts.log || ((...a) => console.log(...a));
  const passthrough = opts.passthroughArgs || [];
  const nonInteractive = !!opts.yes || !process.stdin.isTTY;
  const preApproved = new Set(opts.allow || []);

  log('[phishguard] installing with --ignore-scripts …');
  const installCode = await run('npm', ['install', '--ignore-scripts', ...passthrough], { cwd: root });
  if (installCode !== 0) return { exitCode: installCode, flagged: [], approved: [], skipped: [] };

  const installed = walkNodeModules(root);
  const withScripts = installed
    .map(p => ({ ...p, scripts: extractLifecycleScripts(p.scripts) }))
    .filter(p => p.scripts);

  if (!withScripts.length) {
    log('[phishguard] no lifecycle scripts found - nothing to gate.');
    return { exitCode: 0, flagged: [], approved: [], skipped: [] };
  }

  log(`[phishguard] ${withScripts.length} package(s) have install-time scripts - checking reputation …`);
  const { map: registryMap } = await queryRegistry(root, withScripts.map(p => ({ name: p.name, version: p.version })), {
    offline: opts.offline,
  });

  const db = opts.db; // optional - CLI passes the real db, tests may omit it
  const flagged = [];
  // Scripts that classify as safe (recognised build/tooling command on an
  // established package) still need to run - `--ignore-scripts` suppressed
  // ALL scripts, not just the risky ones, so a package like esbuild or husky
  // would otherwise be left half-installed. Only *flagged* scripts are gated.
  const approved = [];

  for (const pkg of withScripts) {
    const reg = registryMap.get(pkg.name) || {};
    const findings = classifyLifecycleScripts({ scripts: pkg.scripts, established: looksEstablished(reg) });
    if (!findings.length) { approved.push(pkg); continue; }
    const hash = scriptHash(pkg.scripts);
    const priorApproval = db ? await db.getScriptApproval(pkg.name) : null;
    const alreadyApproved = !!(priorApproval && priorApproval.script_hash === hash);
    flagged.push({ ...pkg, finding: findings[0], hash, alreadyApproved });
  }

  const skipped = [];

  if (!flagged.length) {
    log('[phishguard] lifecycle scripts present but none are flagged.');
  }

  for (const pkg of flagged) {
    if (pkg.alreadyApproved) { approved.push(pkg); continue; }
    if (preApproved.has(pkg.name)) { approved.push(pkg); continue; }

    log('');
    log(`[phishguard] ${pkg.finding.severity.toUpperCase()}  ${pkg.name}@${pkg.version}`);
    log(`  ${pkg.finding.description}`);

    if (nonInteractive) {
      log(`  skipped (non-interactive; pass --allow ${pkg.name} to approve without a prompt)`);
      skipped.push(pkg);
      continue;
    }

    const answer = await promptYesNoAll(
      `  Run this package's script? [y]es once / [a]lways (remember) / [N]o: `
    );
    if (answer === 'y' || answer === 'a') {
      approved.push(pkg);
      if (answer === 'a' && db) {
        await db.approveScript({ name: pkg.name, version: pkg.version, scriptHash: pkg.hash });
      }
    } else {
      skipped.push(pkg);
    }
  }

  for (const pkg of approved) {
    log(`[phishguard] running scripts for ${pkg.name}@${pkg.version} …`);
    await run('npm', ['rebuild', pkg.name], { cwd: root });
  }

  if (skipped.length) {
    log('');
    log(`[phishguard] ${skipped.length} package(s) skipped their install scripts:`);
    for (const p of skipped) log(`  - ${p.name}@${p.version}`);
  }

  return {
    exitCode: skipped.length ? 1 : 0,
    flagged, approved, skipped,
  };
}

module.exports = { installGate, scriptHash };
