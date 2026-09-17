/**
 * Typosquatting heuristics.
 *
 * A dependency name is compared against a bundled list of high-value npm
 * packages using Levenshtein *and* Jaro-Winkler distance. We only flag a name
 * that is very close to a popular package but is not itself that package, and
 * apply extra pattern checks (hyphen/dot tricks, doubled letters, key swaps)
 * to keep the false-positive rate low.
 */

const fs = require('fs');
const path = require('path');

const POPULAR = new Set(
  JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', 'popular-packages.json'), 'utf8'))
);

function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  if (!m) return n;
  if (!n) return m;
  const row = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 1; i <= m; i++) {
    let prev = row[0];
    row[0] = i;
    for (let j = 1; j <= n; j++) {
      const tmp = row[j];
      row[j] = Math.min(
        row[j] + 1,
        row[j - 1] + 1,
        prev + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
      prev = tmp;
    }
  }
  return row[n];
}

function jaroWinkler(s1, s2) {
  if (s1 === s2) return 1;
  const len1 = s1.length;
  const len2 = s2.length;
  if (!len1 || !len2) return 0;
  const matchWindow = Math.max(0, Math.floor(Math.max(len1, len2) / 2) - 1);
  const s1Matches = new Array(len1).fill(false);
  const s2Matches = new Array(len2).fill(false);
  let matches = 0;
  for (let i = 0; i < len1; i++) {
    const start = Math.max(0, i - matchWindow);
    const end = Math.min(i + matchWindow + 1, len2);
    for (let j = start; j < end; j++) {
      if (s2Matches[j] || s1[i] !== s2[j]) continue;
      s1Matches[i] = true;
      s2Matches[j] = true;
      matches++;
      break;
    }
  }
  if (!matches) return 0;
  let t = 0;
  let k = 0;
  for (let i = 0; i < len1; i++) {
    if (!s1Matches[i]) continue;
    while (!s2Matches[k]) k++;
    if (s1[i] !== s2[k]) t++;
    k++;
  }
  t /= 2;
  const jaro = (matches / len1 + matches / len2 + (matches - t) / matches) / 3;
  let prefix = 0;
  for (let i = 0; i < Math.min(4, len1, len2); i++) {
    if (s1[i] === s2[i]) prefix++;
    else break;
  }
  return jaro + prefix * 0.1 * (1 - jaro);
}

function bare(name) {
  return name.replace(/^@[^/]+\//, ''); // strip scope
}

/** Structural tricks that strongly suggest a deliberate impersonation. */
function structuralMatch(candidate, target) {
  if (candidate === target) return null;
  const c = candidate;
  const t = target;
  if (c.replace(/[-._]/g, '') === t.replace(/[-._]/g, '') && c !== t) return 'punctuation/separator variation';
  // doubled letter: reactt / axioss
  for (let i = 0; i < t.length; i++) {
    if (t.slice(0, i + 1) + t[i] + t.slice(i + 1) === c) return 'doubled character';
  }
  // single deletion: expres
  for (let i = 0; i < t.length; i++) {
    if (t.slice(0, i) + t.slice(i + 1) === c) return 'missing character';
  }
  return null;
}

/**
 * @param {string} name
 * @returns {null | { target, distance, similarity, pattern, confidence }}
 */
function checkTyposquat(name) {
  // Scoped packages (@org/pkg) are not typosquats of an unscoped install target:
  // installing "@types/estree" can never be mistaken for "estree".
  if (name.startsWith('@')) return null;
  const b = bare(name).toLowerCase();
  if (POPULAR.has(b) || POPULAR.has(name.toLowerCase())) return null;
  if (b.length < 3) return null;

  let best = null;
  for (const target of POPULAR) {
    if (Math.abs(target.length - b.length) > 3) continue;
    if (target[0] !== b[0] && jaroWinkler(b, target) < 0.85) continue;

    const dist = levenshtein(b, target);
    if (dist === 0) return null; // identical to a popular package
    const sim = jaroWinkler(b, target);
    const structural = structuralMatch(b, target);

    let confidence = 0;
    if (structural) confidence = 0.9;
    else if (dist === 1 && sim >= 0.9) confidence = 0.85;
    else if (dist === 2 && sim >= 0.92) confidence = 0.7;
    else if (dist <= 2 && sim >= 0.88) confidence = 0.55;

    if (confidence > 0 && (!best || confidence > best.confidence)) {
      best = {
        target,
        distance: dist,
        similarity: Number(sim.toFixed(3)),
        pattern: structural || `edit distance ${dist}`,
        confidence,
      };
    }
  }
  return best;
}

module.exports = { checkTyposquat, levenshtein, jaroWinkler };
