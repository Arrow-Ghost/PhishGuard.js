/**
 * Package-reputation heuristic shared by the typosquat suppressor
 * (scanner.js) and the lifecycle-script severity classifier (lifecycle.js).
 */

/**
 * A package only "looks established" if it has enough history that a
 * name-similarity or install-script signal is unlikely to be a fluke -
 * freshly-minted, low-reputation packages get no benefit of the doubt.
 */
function looksEstablished(reg) {
  if (!reg || reg.unresolved) return false;
  if (reg.versionsCount != null && reg.versionsCount >= 4) return true;
  if (reg.daysSincePublish != null && reg.daysSincePublish >= 365) return true;
  if (reg.maintainers != null && reg.maintainers >= 2 && (reg.versionsCount ?? 0) >= 2) return true;
  return false;
}

module.exports = { looksEstablished };
