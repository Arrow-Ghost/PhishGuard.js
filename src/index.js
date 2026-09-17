/**
 * PhishGuard programmatic API.
 *
 *   const pg = require('phishguard');
 *   const report = await pg.scan();                 // scan cwd's project
 *   const report = await pg.scan('/path/to/repo');  // scan another repo
 *   const { url, stop } = await pg.startDashboard(); // boot the SOC dashboard
 */

const { resolveTargetRoot } = require('./util/paths');
const { loadConfig } = require('./util/config');
const { scanProject, scanManifest } = require('./core/scanner');

async function scan(rootOrOpts, maybeOpts) {
  let root;
  let opts;
  if (typeof rootOrOpts === 'string') {
    root = resolveTargetRoot(rootOrOpts);
    opts = maybeOpts || {};
  } else {
    opts = rootOrOpts || {};
    root = resolveTargetRoot(opts.cwd);
  }
  const config = loadConfig(root);
  return scanProject(root, {
    includeDev: config.includeDev,
    offline: config.offline,
    cacheTtlHours: config.cacheTtlHours,
    ...opts,
  });
}

async function startDashboard(opts = {}) {
  const { startServer } = require('./server/server');
  return startServer(opts);
}

module.exports = {
  scan,
  scanManifest,
  startDashboard,
  resolveTargetRoot,
  loadConfig,
};
