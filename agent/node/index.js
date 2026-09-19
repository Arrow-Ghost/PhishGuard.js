/**
 * PhishGuard runtime agent - Node server entry point.
 *
 *   require('phishguard/agent/node');                    // auto-install
 *   const { installAgent } = require('phishguard/agent/node');
 *   installAgent({ hubUrl: 'http://localhost:4173', blockDomains: ['evil.com'] });
 *
 * Require this BEFORE anything else in your server's entrypoint, so the
 * hooks wrap the originals before any dependency gets a reference to them.
 * This is defence-in-depth telemetry for the dashboard, same framing as the
 * browser agent (agent/index.js) - not a sandbox. Monkey-patched functions
 * can be routed around by code that captured the original reference first.
 */

const { resolveAgentConfig } = require('./config');
const { installNetworkShield } = require('./networkShield');
const { installProcessShield } = require('./processShield');
const { installFsShield } = require('./fsShield');

function installAgent(userConfig = {}) {
  const config = resolveAgentConfig(userConfig);
  installNetworkShield(config);
  installProcessShield(config);
  installFsShield(config);
  if (config.reportRuntime) {
    console.info('[phishguard] node runtime agent active ->', config.hubUrl);
  }
  return config;
}

if (process.env.PHISHGUARD_DISABLE_AUTOINSTALL !== '1') {
  installAgent();
}

module.exports = { installAgent };
