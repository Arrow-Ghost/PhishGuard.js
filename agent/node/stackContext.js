/**
 * Caller attribution for the Node runtime agent - same logic as
 * ../stackContext.js (kept as a separate CommonJS copy because this agent
 * runs directly under `require()` in a Node server, while the browser
 * agent's copy is ESM and gets bundled by a downstream/dashboard build).
 * Keep the two in sync if this logic changes.
 */
// Skip the shields' own frames by exact filename, not by a broad "phishguard"
// substring match - a real dependency legitimately named e.g.
// "phishguard-something" (or nested under node_modules/phishguard/node_modules/...)
// would otherwise be silently misattributed as "internal" and never flagged.
const INTERNAL_FILES = ['networkShield.js', 'processShield.js', 'fsShield.js', 'stackContext.js'];

function callerContext() {
  try {
    const lines = (new Error().stack || '').split('\n').slice(1);
    for (const l of lines) {
      if (INTERNAL_FILES.some(f => l.includes(f))) continue;
      const m = l.match(/(?:node_modules\/(?:\.pnpm\/)?((?:@[^/]+\/)?[^/@\s)]+))|\/((?:src|dist|assets)\/[^\s?):]+)/);
      if (m) return (m[1] ? `node_modules/${m[1]}` : m[2]);
      const u = l.match(/(https?:\/\/[^\s):]+)/);
      if (u) return u[1];
    }
  } catch { /* ignore */ }
  return 'unknown';
}

/** True when the immediate non-agent caller frame is inside node_modules. */
function isDependencyCaller() {
  return callerContext().startsWith('node_modules/');
}

module.exports = { callerContext, isDependencyCaller };
