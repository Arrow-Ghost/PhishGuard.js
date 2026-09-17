/**
 * Tiny on-disk JSON cache under `<root>/.phishguard/cache/`.
 * Keyed by a namespace + arbitrary key; entries carry a timestamp so the
 * caller can enforce a TTL.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { cacheDir } = require('../util/paths');

function fileFor(root, namespace, key) {
  const hash = crypto.createHash('sha1').update(`${namespace}:${key}`).digest('hex');
  return path.join(cacheDir(root), `${namespace}-${hash}.json`);
}

function get(root, namespace, key, ttlMs) {
  try {
    const file = fileFor(root, namespace, key);
    if (!fs.existsSync(file)) return null;
    const entry = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (ttlMs != null && Date.now() - entry.at > ttlMs) return null;
    return entry.value;
  } catch {
    return null;
  }
}

function set(root, namespace, key, value) {
  try {
    const file = fileFor(root, namespace, key);
    fs.writeFileSync(file, JSON.stringify({ at: Date.now(), value }));
  } catch {
    /* cache is best-effort */
  }
}

module.exports = { get, set };
