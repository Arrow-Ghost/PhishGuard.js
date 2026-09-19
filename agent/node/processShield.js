/**
 * Node runtime process shield: wraps child_process.exec/execFile/spawn/fork
 * and their synchronous counterparts (execSync/execFileSync/spawnSync -
 * commonly used by exactly the kind of install/build tooling this needs to
 * watch, and easy to miss since they're separate exports, not options on the
 * async versions).
 *
 * Enforcement mirrors the network shield's posture - a denylist of
 * known-bad command *patterns* (remote-fetch-and-run, base64-decode-and-eval,
 * reverse-shell one-liners), not a blanket block of all subprocess activity.
 * Blocking every spawn the way the network shield blocks every request to an
 * unlisted domain would be far too disruptive - there's no equivalent of a
 * stable "allowed commands" list an app could maintain.
 *
 * Only dependency-triggered calls (attributed via the node_modules stack
 * frame) are watched at all; the host app's own child_process use is never
 * touched, matched or reported.
 */

const child_process = require('child_process');
const { callerContext, isDependencyCaller } = require('./stackContext');
const { sendTelemetry } = require('./transport');
const { SUSPICIOUS_PATTERN } = require('../../src/core/lifecycle');

let installed = false;

const SHELL_STRING_METHODS = new Set(['exec', 'execSync']);

function commandStringFor(method, args) {
  if (SHELL_STRING_METHODS.has(method)) return String(args[0] || '');
  // execFile/execFileSync/spawn/spawnSync/fork: (file, args[], options)
  const file = args[0];
  const extra = Array.isArray(args[1]) ? args[1] : [];
  return [file, ...extra].join(' ');
}

function installProcessShield(config) {
  if (installed) return;
  installed = true;

  function report(command, action, extra = {}) {
    sendTelemetry(config.hubUrl, {
      timestamp: new Date().toISOString(),
      callerContext: callerContext(),
      sourcePackage: callerContext(),
      action,
      target: command,
      callerUrl: command,
      details: extra.details || `Command: ${command}`,
      severity: extra.severity || 'warning',
      status: extra.status || 'FLAGGED',
      rule: extra.rule || null,
      enforcement: extra.enforcement || null,
      stack: new Error().stack || '',
      ...extra,
    });
  }

  for (const method of ['exec', 'execFile', 'spawn', 'fork', 'execSync', 'execFileSync', 'spawnSync']) {
    const original = child_process[method];
    if (!original || original.__pgWrapped) continue;
    const wrapped = function (...args) {
      if (!isDependencyCaller()) return original.apply(this, args); // app's own code - not our concern
      const command = commandStringFor(method, args);
      if (SUSPICIOUS_PATTERN.test(command)) {
        report(command, `Process ${method}`, {
          severity: 'critical',
          status: 'BLOCKED',
          rule: 'exfiltration/obfuscation pattern match',
          enforcement: `child_process.${method}() short-circuited - process never spawned`,
        });
        throw new Error(`PhishGuard: blocked a subprocess matching a known-malicious pattern (${command}).`);
      }
      report(command, `Process ${method}`, {
        severity: 'warning',
        status: 'FLAGGED',
        rule: 'child_process call from a dependency',
        enforcement: 'allowed to run, recorded for review',
      });
      return original.apply(this, args);
    };
    wrapped.__pgWrapped = true;
    child_process[method] = wrapped;
  }
}

module.exports = { installProcessShield };
