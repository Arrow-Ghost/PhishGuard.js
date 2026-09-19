/**
 * Node runtime agent configuration resolution.
 *
 * Priority:
 *   1. explicit options passed to installAgent(opts)
 *   2. environment variables (PHISHGUARD_HUB_URL, PHISHGUARD_BLOCK_DOMAINS,
 *      PHISHGUARD_ALLOW_DOMAINS - comma separated)
 *   3. phishguard.config.json in process.cwd(), best-effort
 *   4. defaults (http://localhost:4173)
 */

function fromEnv() {
  const split = (v) => (v || '').split(',').map(s => s.trim()).filter(Boolean);
  return {
    hubUrl: process.env.PHISHGUARD_HUB_URL || undefined,
    blockDomains: split(process.env.PHISHGUARD_BLOCK_DOMAINS),
    allowDomains: split(process.env.PHISHGUARD_ALLOW_DOMAINS),
  };
}

function fromProjectConfig() {
  try {
    // Lazy require: this file ships inside node_modules/phishguard/agent/node,
    // so `../../src/util/config` resolves within the installed package
    // regardless of the host app's own module layout.
    const { loadConfig } = require('../../src/util/config');
    const cfg = loadConfig(process.cwd());
    return { blockDomains: cfg.blockDomains || [], allowDomains: cfg.allowDomains || [] };
  } catch {
    return { blockDomains: [], allowDomains: [] };
  }
}

function resolveAgentConfig(userConfig = {}) {
  const env = fromEnv();
  const project = fromProjectConfig();

  return {
    hubUrl: userConfig.hubUrl || env.hubUrl || 'http://localhost:4173',
    blockDomains: [
      ...(project.blockDomains || []),
      ...(env.blockDomains || []),
      ...(userConfig.blockDomains || []),
    ],
    allowDomains: [
      ...(project.allowDomains || []),
      ...(env.allowDomains || []),
      ...(userConfig.allowDomains || []),
    ],
    sensitivePaths: userConfig.sensitivePaths || null, // null = fsShield's built-in default list
    reportRuntime: userConfig.reportRuntime !== false,
  };
}

module.exports = { resolveAgentConfig };
