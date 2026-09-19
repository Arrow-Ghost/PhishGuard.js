/**
 * Caller attribution for the browser interceptor: parses `new Error().stack`
 * to find the `node_modules/<pkg>` frame (or app source frame) that actually
 * triggered the intercepted call, so telemetry points at the offending
 * dependency instead of just "fetch was called somewhere."
 *
 * The Node runtime agent (agent/node/) needs the same logic but is plain
 * CommonJS (it runs directly under `require()`, unlike this ESM file which
 * this package's own dashboard build bundles) - see agent/node/stackContext.js.
 * Keep the two in sync if this logic changes.
 */
export function callerContext() {
  try {
    const lines = (new Error().stack || '').split('\n').slice(1);
    for (const l of lines) {
      if (l.includes('phishguard') || l.includes('interceptor.js') || l.includes('config.js')
        || l.includes('stackContext.js')) continue;
      const m = l.match(/(?:node_modules\/(?:\.pnpm\/)?((?:@[^/]+\/)?[^/@\s)]+))|\/((?:src|dist|assets)\/[^\s?):]+)/);
      if (m) return (m[1] ? `node_modules/${m[1]}` : m[2]);
      const u = l.match(/(https?:\/\/[^\s):]+)/);
      if (u) return u[1];
    }
  } catch { /* ignore */ }
  return 'unknown';
}
