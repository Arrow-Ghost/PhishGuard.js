/**
 * Lockfile parsing -> a flat, de-duplicated list of installed packages.
 *
 * Every entry: { name, version, range, direct, dev, depth, resolved }
 *   - version  : concrete installed version (or best-effort from the range)
 *   - range    : the semver range requested by the parent(s), when known
 *   - direct   : appears in the root package.json dependencies/devDependencies
 *   - dev      : only reachable through devDependencies
 *   - depth    : 0 for the root project, 1 for direct deps, etc.
 *   - resolved : true when `version` came from a lockfile (not guessed)
 *
 * npm v2/v3, npm v1, yarn classic and pnpm are supported. When no lockfile is
 * present we fall back to the manifest ranges alone.
 */

const semver = require('semver');

function guessVersion(range) {
  if (!range || typeof range !== 'string') return null;
  const clean = range.trim();
  if (/^(latest|\*|x|)$/i.test(clean)) return null;
  if (semver.valid(clean)) return clean;
  try {
    const min = semver.minVersion(clean);
    return min ? min.version : null;
  } catch {
    return null;
  }
}

function directSets(manifest) {
  const prod = manifest.dependencies || {};
  const dev = manifest.devDependencies || {};
  const optional = manifest.optionalDependencies || {};
  return {
    prod: new Set(Object.keys(prod)),
    dev: new Set(Object.keys(dev)),
    optional: new Set(Object.keys(optional)),
    ranges: { ...optional, ...dev, ...prod },
  };
}

/* ------------------------------- npm v2 / v3 ------------------------------- */
function parseNpmModern(lock, direct) {
  const out = new Map();
  const packages = lock.packages || {};

  // Reverse edges: which packages declare X as a dependency. This is what lets
  // the attack-tree view show the real route from your app down to a
  // vulnerable transitive package instead of a flat "it's in there somewhere".
  const parentsByName = new Map();
  const addParent = (child, parent) => {
    if (!child || child === parent) return;
    if (!parentsByName.has(child)) parentsByName.set(child, new Set());
    parentsByName.get(child).add(parent);
  };
  for (const [pkgPath, meta] of Object.entries(packages)) {
    if (!meta) continue;
    const parentName = pkgPath === '' ? null : pkgPath.split('node_modules/').pop();
    const deps = {
      ...(meta.dependencies || {}),
      ...(meta.optionalDependencies || {}),
      ...(pkgPath === '' ? (meta.devDependencies || {}) : {}),
    };
    for (const depName of Object.keys(deps)) {
      addParent(depName, parentName); // null parent === the root project
    }
  }

  for (const [pkgPath, meta] of Object.entries(packages)) {
    if (pkgPath === '') continue; // the root project itself
    const name = pkgPath.split('node_modules/').pop();
    if (!name || !meta || !meta.version) continue;
    const depth = pkgPath.split('node_modules/').length - 1;
    const key = `${name}@${meta.version}`;
    const isDirect = direct.prod.has(name) || direct.dev.has(name) || direct.optional.has(name);
    const prev = out.get(key);
    const parents = [...(parentsByName.get(name) || new Set())]
      .filter(Boolean)          // drop the root marker; `direct` already encodes it
      .slice(0, 12);
    out.set(key, {
      name,
      version: meta.version,
      range: direct.ranges[name] || (prev && prev.range) || null,
      direct: isDirect || (prev && prev.direct) || false,
      dev: (meta.dev === true || direct.dev.has(name)) && !direct.prod.has(name)
        ? (prev ? prev.dev : true)
        : false,
      depth: prev ? Math.min(prev.depth, depth) : depth,
      parents: prev && prev.parents && prev.parents.length ? prev.parents : parents,
      resolved: true,
    });
  }
  return [...out.values()];
}

/* --------------------------------- npm v1 -------------------------------- */
function parseNpmLegacy(lock, direct) {
  const out = new Map();
  function walk(deps, depth, devBranch, parentName) {
    for (const [name, meta] of Object.entries(deps || {})) {
      if (!meta || !meta.version) continue;
      const key = `${name}@${meta.version}`;
      const isDirect = depth === 1;
      const dev = devBranch || (direct.dev.has(name) && !direct.prod.has(name));
      const prev = out.get(key);
      out.set(key, {
        name,
        version: meta.version,
        range: direct.ranges[name] || (prev && prev.range) || null,
        direct: isDirect || (prev && prev.direct) || false,
        dev: prev ? prev.dev && dev : dev,
        depth: prev ? Math.min(prev.depth, depth) : depth,
        parents: parentName
          ? [...new Set([...((prev && prev.parents) || []), parentName])].slice(0, 12)
          : ((prev && prev.parents) || []),
        resolved: true,
      });
      if (meta.dependencies) walk(meta.dependencies, depth + 1, dev, name);
    }
  }
  walk(lock.dependencies, 1, false, null);
  return [...out.values()];
}

/* -------------------------------- yarn v1 ------------------------------- */
function parseYarn(raw, direct) {
  const out = new Map();
  const blocks = raw.split(/\n(?=\S)/);
  for (const block of blocks) {
    const header = block.split('\n')[0];
    if (!header || header.startsWith('#') || header.startsWith('__metadata')) continue;
    const vMatch = block.match(/\n\s+version:?\s+"?([^"\n]+)"?/);
    if (!vMatch) continue;
    const version = vMatch[1].trim();
    // header looks like:  "name@range", "name@range":   or   name@range:
    const specs = header.replace(/:$/, '').split(',').map(s => s.trim().replace(/^"|"$/g, ''));
    for (const spec of specs) {
      const at = spec.lastIndexOf('@');
      if (at <= 0) continue;
      const name = spec.slice(0, at);
      const range = spec.slice(at + 1);
      const key = `${name}@${version}`;
      const isDirect = direct.prod.has(name) || direct.dev.has(name) || direct.optional.has(name);
      const prev = out.get(key);
      out.set(key, {
        name,
        version,
        range: direct.ranges[name] || range || (prev && prev.range) || null,
        direct: isDirect || (prev && prev.direct) || false,
        dev: (direct.dev.has(name) && !direct.prod.has(name)) ? (prev ? prev.dev : true) : false,
        depth: isDirect ? 1 : (prev ? prev.depth : 2),
        resolved: true,
      });
    }
  }
  return [...out.values()];
}

/* -------------------------------- pnpm -------------------------------- */
function parsePnpm(raw, direct) {
  const out = new Map();
  // Match keys in the `packages:` section: `  /name@1.2.3:` or `  name@1.2.3:`
  const re = /^\s{2}\/?((?:@[^/\s]+\/)?[^@\s/][^@\s]*)@([0-9][^:(\s]*)[:(]/gm;
  let m;
  while ((m = re.exec(raw)) !== null) {
    const name = m[1];
    const version = m[2].replace(/_.*$/, '');
    const key = `${name}@${version}`;
    const isDirect = direct.prod.has(name) || direct.dev.has(name) || direct.optional.has(name);
    if (out.has(key)) continue;
    out.set(key, {
      name,
      version,
      range: direct.ranges[name] || null,
      direct: isDirect,
      dev: direct.dev.has(name) && !direct.prod.has(name),
      depth: isDirect ? 1 : 2,
      resolved: true,
    });
  }
  return [...out.values()];
}

/* ------------------------------ manifest only ---------------------------- */
function parseManifestOnly(direct) {
  return Object.entries(direct.ranges).map(([name, range]) => ({
    name,
    version: guessVersion(range),
    range,
    direct: true,
    dev: direct.dev.has(name) && !direct.prod.has(name),
    depth: 1,
    resolved: false,
  }));
}

/**
 * @param {object} manifest  parsed root package.json
 * @param {object|null} lock  { kind, raw } from resolve.findLockfile(), or null
 * @param {object} opts       { includeDev }
 */
function parseLockfile(manifest, lock, opts = {}) {
  const includeDev = opts.includeDev !== false;
  const direct = directSets(manifest);
  let list;
  let source;

  try {
    if (!lock) {
      list = parseManifestOnly(direct);
      source = 'manifest';
    } else if (lock.kind === 'npm') {
      const parsed = JSON.parse(lock.raw);
      if (parsed.packages) {
        list = parseNpmModern(parsed, direct);
        source = `npm (lockfileVersion ${parsed.lockfileVersion || 2})`;
      } else {
        list = parseNpmLegacy(parsed, direct);
        source = 'npm (lockfileVersion 1)';
      }
    } else if (lock.kind === 'yarn') {
      list = parseYarn(lock.raw, direct);
      source = 'yarn';
    } else if (lock.kind === 'pnpm') {
      list = parsePnpm(lock.raw, direct);
      source = 'pnpm';
    } else {
      list = parseManifestOnly(direct);
      source = 'manifest';
    }
  } catch (err) {
    // Corrupt / unreadable lockfile - degrade to manifest ranges rather than crash.
    list = parseManifestOnly(direct);
    source = `manifest (${lock ? lock.name : 'no lockfile'} unparseable: ${err.message})`;
  }

  // A parser that produced nothing (unusual lockfile dialect) also falls back.
  if (!list || (list.length === 0 && Object.keys(direct.ranges).length > 0)) {
    list = parseManifestOnly(direct);
    if (!/manifest/.test(source)) source = `manifest (${source} yielded no packages)`;
  }

  // Merge any direct manifest deps the lockfile parser missed (edge cases).
  const seen = new Set(list.map(p => p.name));
  for (const [name, range] of Object.entries(direct.ranges)) {
    if (!seen.has(name)) {
      list.push({
        name,
        version: guessVersion(range),
        range,
        direct: true,
        dev: direct.dev.has(name) && !direct.prod.has(name),
        depth: 1,
        resolved: false,
      });
    }
  }

  if (!includeDev) list = list.filter(p => !p.dev);
  list = list.filter(p => p.name && !p.name.startsWith('node_modules'));
  list.sort((a, b) => a.name.localeCompare(b.name) || String(a.version).localeCompare(String(b.version)));

  return { packages: list, source };
}

module.exports = { parseLockfile, guessVersion };
