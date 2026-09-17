/**
 * Optional per-project configuration: `<root>/phishguard.config.json`.
 * All fields are optional; defaults below are used when the file is absent.
 */

const fs = require('fs');
const path = require('path');

const DEFAULTS = {
  /** Dashboard HTTP + WebSocket port. */
  port: 4173,
  /** CLI `scan` exits non-zero when a finding at or above this level exists. */
  failOn: 'critical', // 'critical' | 'high' | 'warning' | 'none'
  /** Include devDependencies in the scan. */
  includeDev: true,
  /** Never touch the network (OSV / npm registry); use bundled data only. */
  offline: false,
  /** Extra domains the runtime agent should always allow. */
  allowDomains: [],
  /** Extra domains the runtime agent should always block. */
  blockDomains: [],
  /** Hours before a cached OSV/registry response is considered stale. */
  cacheTtlHours: 24,
};

function loadConfig(root) {
  const file = path.join(root, 'phishguard.config.json');
  let fromFile = {};
  if (fs.existsSync(file)) {
    try {
      fromFile = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (err) {
      throw new Error(`Invalid phishguard.config.json: ${err.message}`);
    }
  }
  return { ...DEFAULTS, ...fromFile, __file: fs.existsSync(file) ? file : null };
}

module.exports = { loadConfig, DEFAULTS };
