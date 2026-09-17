/**
 * Host-project resolution.
 *
 * PhishGuard is designed to be installed as a dependency of an arbitrary repo
 * and run from that repo's root (`npx phishguard ...`). Nothing here is specific
 * to PhishGuard's own source tree - every path is derived from the *target*
 * project so a single global install can serve many repos.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

/**
 * Walk upward from `start` looking for a directory that contains package.json.
 * The walk stops at the filesystem root, the user's home directory, or after
 * `maxUp` levels - so running in a non-project folder does NOT silently scan
 * some unrelated ancestor project. Falls back to `start` if none is found.
 */
function findProjectRoot(start, { maxUp = 8 } = {}) {
  const origin = path.resolve(start || process.cwd());
  let dir = origin;
  const fsRoot = path.parse(dir).root;
  const home = os.homedir();
  for (let i = 0; i <= maxUp; i++) {
    if (fs.existsSync(path.join(dir, 'package.json'))) return dir;
    if (dir === fsRoot || dir === home) break;
    dir = path.dirname(dir);
  }
  return origin;
}

/**
 * Resolve the target project root.
 *   - explicit `--cwd` / PHISHGUARD_TARGET: that dir, or up to 3 parents, must
 *     hold a package.json (otherwise the caller errors clearly).
 *   - no argument: search upward from process.cwd() (bounded by home / 8 levels).
 */
function resolveTargetRoot(explicit) {
  const forced = explicit || process.env.PHISHGUARD_TARGET;
  if (forced) return findProjectRoot(path.resolve(forced), { maxUp: 3 });
  return findProjectRoot(process.cwd());
}

/** Per-project data directory: `<root>/.phishguard` */
function dataDir(root) {
  const dir = path.join(root, '.phishguard');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function dbPath(root) {
  return path.join(dataDir(root), 'phishguard.db');
}

function cacheDir(root) {
  const dir = path.join(dataDir(root), 'cache');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/** PhishGuard's own install directory (for bundled data + built dashboard). */
function packageRoot() {
  return path.resolve(__dirname, '..', '..');
}

module.exports = {
  findProjectRoot,
  resolveTargetRoot,
  dataDir,
  dbPath,
  cacheDir,
  packageRoot,
};
