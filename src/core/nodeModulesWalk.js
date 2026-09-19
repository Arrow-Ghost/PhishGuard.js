/**
 * Walk an installed `node_modules` tree on disk and read every package's
 * `package.json`. Used only by `phishguard install` (installGate.js) - the
 * scan path (scanner.js) deliberately never requires node_modules to exist,
 * so this stays isolated to the one command that does.
 *
 * Recurses into nested `node_modules` directories (npm's dedup/conflict
 * resolution nests a second copy of a package when versions collide), so a
 * package's lifecycle scripts are found regardless of where npm placed it.
 */

const fs = require('fs');
const path = require('path');

function readPackageJson(dir) {
  try {
    return JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
  } catch {
    return null;
  }
}

/**
 * `Dirent.isDirectory()` is false for a symlink entry itself, even when the
 * link points at a directory - npm installs `file:` deps (and workspaces,
 * and pnpm) as symlinks, so relying on isDirectory() alone silently skips
 * every one of them. Follow the link with statSync to find out what it
 * actually points to.
 */
function isDirLike(entry, fullPath) {
  if (entry.isDirectory()) return true;
  if (!entry.isSymbolicLink()) return false;
  try {
    return fs.statSync(fullPath).isDirectory();
  } catch {
    return false; // broken symlink
  }
}

/**
 * @param {string} root  project root (containing node_modules)
 * @returns {Array<{ name, version, scripts, dir }>}
 */
function walkNodeModules(root) {
  const out = [];
  const seenDirs = new Set();

  function walkDir(nodeModulesDir) {
    let entries;
    try {
      entries = fs.readdirSync(nodeModulesDir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const entryPath = path.join(nodeModulesDir, entry.name);
      if (entry.name === '.bin' || !isDirLike(entry, entryPath)) continue;
      if (entry.name.startsWith('@')) {
        // scoped packages: node_modules/@scope/<name>
        let scoped;
        try {
          scoped = fs.readdirSync(entryPath, { withFileTypes: true });
        } catch {
          continue;
        }
        for (const s of scoped) {
          const scopedPath = path.join(entryPath, s.name);
          if (isDirLike(s, scopedPath)) visitPackageDir(scopedPath);
        }
        continue;
      }
      visitPackageDir(entryPath);
    }
  }

  function visitPackageDir(dir) {
    let real;
    try {
      real = fs.realpathSync.native ? fs.realpathSync.native(dir) : fs.realpathSync(dir);
    } catch {
      return; // broken symlink or race with a concurrent install
    }
    if (seenDirs.has(real)) return; // symlinked/duplicated path, already visited
    seenDirs.add(real);

    const pkg = readPackageJson(dir);
    if (pkg && pkg.name && pkg.version) {
      out.push({ name: pkg.name, version: pkg.version, scripts: pkg.scripts || null, dir });
    }

    const nested = path.join(dir, 'node_modules');
    if (fs.existsSync(nested)) walkDir(nested);
  }

  walkDir(path.join(root, 'node_modules'));
  return out;
}

module.exports = { walkNodeModules };
