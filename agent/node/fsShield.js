/**
 * Node runtime filesystem shield: blocks reads of a short, explicit
 * sensitive-path denylist (.env, SSH keys, cloud credential files) from
 * dependency code. Deliberately narrow - general fs interception would be
 * both noisy (fs calls are extremely frequent) and easy to get wrong, unlike
 * a short list of paths that have no legitimate reason to be read by a
 * dependency instead of the app itself.
 */

const fs = require('fs');
const path = require('path');
const { callerContext, isDependencyCaller } = require('./stackContext');
const { sendTelemetry } = require('./transport');

let installed = false;

const DEFAULT_SENSITIVE_PATTERNS = [
  /(^|[\\/])\.env(\.|$)/i,
  /(^|[\\/])\.npmrc$/i,
  /(^|[\\/])\.ssh[\\/]/i,
  /(^|[\\/])\.aws[\\/]credentials$/i,
  /(^|[\\/])\.config[\\/]gcloud[\\/]/i,
];

function isSensitive(target, patterns) {
  let p;
  try {
    p = path.resolve(String(target));
  } catch {
    return false;
  }
  return patterns.some(re => re.test(p));
}

function installFsShield(config) {
  if (installed) return;
  installed = true;

  const patterns = config.sensitivePaths && config.sensitivePaths.length
    ? config.sensitivePaths.map(s => (s instanceof RegExp ? s : new RegExp(s, 'i')))
    : DEFAULT_SENSITIVE_PATTERNS;

  function report(target, action) {
    sendTelemetry(config.hubUrl, {
      timestamp: new Date().toISOString(),
      callerContext: callerContext(),
      sourcePackage: callerContext(),
      action,
      target,
      callerUrl: target,
      details: `Sensitive path read blocked: ${target}`,
      severity: 'critical',
      status: 'BLOCKED',
      rule: 'sensitive-path match',
      enforcement: `${action} short-circuited - the file was never opened`,
      stack: new Error().stack || '',
    });
  }

  const methods = [
    { obj: fs, name: 'readFileSync' },
    { obj: fs, name: 'readFile' },
    { obj: fs.promises, name: 'readFile' },
  ];

  for (const { obj, name } of methods) {
    if (!obj || !obj[name] || obj[name].__pgWrapped) continue;
    const original = obj[name];
    const wrapped = function (target, ...rest) {
      if (isDependencyCaller() && isSensitive(target, patterns)) {
        const action = `fs.${name}`;
        report(String(target), action);
        const err = new Error(`PhishGuard: blocked a read of a sensitive path (${target}).`);
        if (name === 'readFile' && obj === fs && typeof rest[rest.length - 1] === 'function') {
          const cb = rest[rest.length - 1];
          process.nextTick(() => cb(err));
          return;
        }
        if (name === 'readFile' && obj === fs.promises) return Promise.reject(err);
        throw err; // readFileSync
      }
      return original.call(this, target, ...rest);
    };
    wrapped.__pgWrapped = true;
    obj[name] = wrapped;
  }
}

module.exports = { installFsShield };
