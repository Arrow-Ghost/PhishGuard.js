/**
 * Locate the target project's manifest + lockfile and read the raw manifest.
 */

const fs = require('fs');
const path = require('path');

const LOCKFILES = [
  { file: 'package-lock.json', kind: 'npm' },
  { file: 'npm-shrinkwrap.json', kind: 'npm' },
  { file: 'yarn.lock', kind: 'yarn' },
  { file: 'pnpm-lock.yaml', kind: 'pnpm' },
];

function readManifest(root) {
  const file = path.join(root, 'package.json');
  if (!fs.existsSync(file)) {
    throw new Error(`No package.json found at ${root}`);
  }
  const manifest = JSON.parse(fs.readFileSync(file, 'utf8'));
  return { file, manifest };
}

function findLockfile(root) {
  for (const { file, kind } of LOCKFILES) {
    const full = path.join(root, file);
    if (fs.existsSync(full)) {
      return { file: full, name: file, kind, raw: fs.readFileSync(full, 'utf8') };
    }
  }
  return null;
}

module.exports = { readManifest, findLockfile };
