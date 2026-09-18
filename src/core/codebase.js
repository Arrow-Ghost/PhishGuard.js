/**
 * Codebase usage mapping.
 *
 * The dependency tree (resolve.js/lockfile.js) only knows what's *installed*.
 * This walks the project's own source files and finds which packages are
 * actually `import`ed / `require`d, and from where - so a finding on an
 * installed-but-never-imported package can be told apart from one your code
 * genuinely calls into.
 *
 * Static regex extraction, not a full parser: it can't resolve dynamic
 * specifiers (`require(someVar)`) and doesn't trace which *function* of a
 * package is called - only "this file references this package by name".
 */

const fs = require('fs');
const path = require('path');

const SOURCE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte']);
const IGNORED_DIRS = new Set([
  'node_modules', '.git', '.phishguard', 'dist', 'build', 'out', 'coverage',
  '.next', '.nuxt', '.cache', '.turbo', 'vendor', '.svelte-kit',
]);
const MAX_FILES = 6000;
const MAX_FILE_BYTES = 1.5 * 1024 * 1024; // skip huge bundled/generated files

// import x from 'y' | import 'y' | export x from 'y' | require('y') | import('y')
const IMPORT_RE = /\b(?:import|export)\b[^'"()]*?['"]([^'"]+)['"]|\brequire\(\s*['"]([^'"]+)['"]\s*\)|\bimport\(\s*['"]([^'"]+)['"]\s*\)/g;

function specifierToPackageName(spec) {
  if (!spec || spec.startsWith('.') || spec.startsWith('/') || spec.startsWith('node:')) return null;
  const parts = spec.split('/');
  if (spec.startsWith('@')) return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : null;
  return parts[0];
}

function walk(dir, files, max) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const entry of entries) {
    if (files.length >= max) return;
    if (entry.isDirectory()) {
      if (IGNORED_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
      walk(path.join(dir, entry.name), files, max);
    } else if (entry.isFile() && SOURCE_EXTENSIONS.has(path.extname(entry.name))) {
      files.push(path.join(dir, entry.name));
    }
  }
}

/**
 * @param {string} root          project root
 * @param {Set<string>} knownNames  package names from the resolved dependency tree
 * @returns {{ usage: Map<string,Set<string>>, filesScanned: number, truncated: boolean }}
 */
function mapCodebaseUsage(root, knownNames) {
  const files = [];
  walk(root, files, MAX_FILES);
  const truncated = files.length >= MAX_FILES;

  const usage = new Map(); // packageName -> Set(relative file paths)
  let filesScanned = 0;

  for (const file of files) {
    let stat;
    try { stat = fs.statSync(file); } catch { continue; }
    if (stat.size > MAX_FILE_BYTES) continue;
    let text;
    try { text = fs.readFileSync(file, 'utf8'); } catch { continue; }
    filesScanned++;

    IMPORT_RE.lastIndex = 0;
    let m;
    while ((m = IMPORT_RE.exec(text))) {
      const name = specifierToPackageName(m[1] || m[2] || m[3]);
      if (!name || !knownNames.has(name)) continue;
      if (!usage.has(name)) usage.set(name, new Set());
      usage.get(name).add(path.relative(root, file).split(path.sep).join('/'));
    }
  }

  return { usage, filesScanned, truncated };
}

module.exports = { mapCodebaseUsage };
