/**
 * Node runtime network shield - the server-side counterpart to
 * agent/interceptor.js. Wraps http/https request methods and the global
 * fetch so an outbound call from *any* dependency is checked against the
 * same domain policy before it leaves the process.
 */

const http = require('http');
const https = require('https');
const { callerContext } = require('./stackContext');
const { sendTelemetry } = require('./transport');

let installed = false;

function extractUrl(firstArg, secondArg) {
  if (typeof firstArg === 'string') return firstArg;
  if (firstArg instanceof URL) return firstArg.href;
  const opts = (secondArg && typeof secondArg === 'object') ? secondArg : firstArg;
  if (opts && typeof opts === 'object') {
    const protocol = opts.protocol || 'http:';
    const host = opts.hostname || opts.host || 'localhost';
    const port = opts.port ? `:${opts.port}` : '';
    const path = opts.path || '/';
    return `${protocol}//${host}${port}${path}`;
  }
  return '';
}

function installNetworkShield(config) {
  if (installed) return;
  installed = true;

  const blockList = config.blockDomains;
  const allowList = config.allowDomains;

  function verdict(url) {
    if (!url) return null;
    const s = String(url);
    if (allowList.some(d => s.includes(d))) return null;
    return blockList.find(d => s.includes(d)) || null;
  }

  function report(url, action, extra = {}) {
    const stack = new Error().stack || '';
    sendTelemetry(config.hubUrl, {
      timestamp: new Date().toISOString(),
      callerContext: callerContext(),
      sourcePackage: callerContext(),
      action,
      target: url,
      callerUrl: url,
      details: extra.details || `Target: ${url}`,
      severity: 'critical',
      status: 'BLOCKED',
      rule: extra.rule || null,
      enforcement: extra.enforcement || null,
      stack,
      ...extra,
    });
  }

  function fakeBlockedRequest(url) {
    const { EventEmitter } = require('events');
    const req = new EventEmitter();
    req.write = () => true;
    req.end = () => {
      process.nextTick(() => req.emit('error', new Error(`PhishGuard: request to blocked domain was denied (${url}).`)));
    };
    req.destroy = () => {};
    req.setTimeout = () => req;
    req.abort = () => {};
    return req;
  }

  for (const [mod, name] of [[http, 'http'], [https, 'https']]) {
    for (const method of ['request', 'get']) {
      const original = mod[method];
      if (original.__pgWrapped) continue;
      const wrapped = function (...args) {
        const url = extractUrl(args[0], args[1]);
        const hit = verdict(url);
        if (hit) {
          report(url, `Network ${name}.${method} Request`, {
            rule: `deny-list match "${hit}"`,
            enforcement: `${name}.${method}() short-circuited - no socket was opened`,
          });
          const req = fakeBlockedRequest(url);
          if (method === 'get') req.end(); // http.get auto-calls end()
          return req;
        }
        return original.apply(this, args);
      };
      wrapped.__pgWrapped = true;
      mod[method] = wrapped;
    }
  }

  if (typeof globalThis.fetch === 'function' && !globalThis.fetch.__pgWrapped) {
    const original = globalThis.fetch;
    const wrapped = function (input, init) {
      const url = typeof input === 'string' ? input : (input && input.url) || '';
      const hit = verdict(url);
      if (hit) {
        report(url, 'Network fetch Request', {
          rule: `deny-list match "${hit}"`,
          enforcement: 'fetch() rejected before the request was dispatched',
        });
        return Promise.reject(new Error(`PhishGuard: request to blocked domain was denied (${url}).`));
      }
      return original.call(this, input, init);
    };
    wrapped.__pgWrapped = true;
    globalThis.fetch = wrapped;
  }
}

module.exports = { installNetworkShield };
