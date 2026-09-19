/**
 * PhishGuard runtime interceptor (browser).
 *
 * Wraps fetch / XMLHttpRequest / navigator.sendBeacon so that outbound requests
 * from *any* dependency are checked against a domain policy before they leave the
 * page. Blocked calls are rejected in-place and streamed to the SOC hub over a
 * WebSocket. This is defence-in-depth telemetry for the dashboard - the static
 * `phishguard scan` is the primary control.
 */
import { resolveAgentConfig } from './config.js';
import { callerContext } from './stackContext.js';

let installed = false;

export function installInterceptor(userConfig = {}) {
  if (installed || typeof window === 'undefined') return;
  installed = true;

  const config = { ...resolveAgentConfig(), ...userConfig };
  const blockList = [...config.blockDomains, ...config.demoBlock];
  const allowList = config.allowDomains;

  let ws = null;
  let queue = [];
  function connect() {
    try {
      ws = new WebSocket(config.hubUrl);
      ws.onopen = () => { queue.splice(0).forEach(m => ws.send(m)); };
      ws.onclose = () => { ws = null; setTimeout(connect, 3000); };
      ws.onerror = () => { try { ws.close(); } catch {} };
    } catch { setTimeout(connect, 5000); }
  }
  connect();

  function send(payload) {
    const msg = JSON.stringify(payload);
    if (ws && ws.readyState === 1) ws.send(msg);
    else {
      queue.push(msg);
      // also try the HTTP endpoint so a down socket doesn't lose the alert
      try {
        (window.fetch.__pgOriginal || window.fetch)(`${config.httpUrl.replace(/\/$/, '')}/api/telemetry`, {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            origin: 'browser',
            sourcePackage: payload.callerContext, callerUrl: payload.target,
            action: payload.action, details: payload.details, status: payload.status,
            severity: payload.severity, stack: payload.stack,
          }), keepalive: true,
        }).catch(() => {});
      } catch {}
    }
  }

  function verdict(url) {
    if (!url) return null;
    const s = String(url);
    if (allowList.some(d => s.includes(d))) return null;
    const hit = blockList.find(d => s.includes(d));
    return hit ? hit : null;
  }

  function report(url, action, extra = {}) {
    const stack = (new Error().stack || '');
    send({
      timestamp: new Date().toISOString(),
      origin: 'browser',
      callerContext: callerContext(),
      action,
      target: url,
      details: extra.details || `Target: ${url}`,
      severity: 'critical',
      status: 'BLOCKED',
      // What matched and what the agent actually did about it. The console
      // renders these as the enforcement chain, so they must describe the real
      // action taken - not a label.
      rule: extra.rule || null,
      enforcement: extra.enforcement || null,
      latencyMs: extra.latencyMs != null ? extra.latencyMs : null,
      stackFrames: stack.split('\n').filter(l => /\S/.test(l)).length,
      stack,
      ...extra,
    });
  }

  /* ------------------------------- fetch -------------------------------- */
  if (window.fetch && !window.fetch.__pgWrapped) {
    const original = window.fetch;
    const proxy = new Proxy(original, {
      apply(target, thisArg, args) {
        const res = args[0];
        const url = typeof res === 'string' ? res : (res && res.url) || '';
        const t0 = performance.now();
        const hit = verdict(url);
        if (hit) {
          report(url, 'Network FETCH Request', {
            rule: `deny-list match "${hit}"`,
            enforcement: 'fetch() rejected before the socket was opened - no bytes left the browser',
            latencyMs: Number((performance.now() - t0).toFixed(4)),
          });
          return Promise.reject(new Error('PhishGuard: request to blocked domain was denied.'));
        }
        return Reflect.apply(target, thisArg, args);
      },
    });
    proxy.__pgWrapped = true;
    proxy.__pgOriginal = original;
    window.fetch = proxy;
  }

  /* --------------------------- XMLHttpRequest --------------------------- */
  if (window.XMLHttpRequest && !window.XMLHttpRequest.prototype.__pgWrapped) {
    const open = window.XMLHttpRequest.prototype.open;
    const sendM = window.XMLHttpRequest.prototype.send;
    window.XMLHttpRequest.prototype.open = function (method, url, ...rest) {
      this.__pgUrl = url;
      return open.call(this, method, url, ...rest);
    };
    window.XMLHttpRequest.prototype.send = function (body) {
      const t0 = performance.now();
      const hit = verdict(this.__pgUrl);
      if (hit) {
        report(this.__pgUrl, 'Network XHR Request', {
          details: `XHR blocked → ${this.__pgUrl}`,
          rule: `deny-list match "${hit}"`,
          enforcement: 'XMLHttpRequest.send() threw before dispatch - request never issued',
          latencyMs: Number((performance.now() - t0).toFixed(4)),
        });
        throw new Error('PhishGuard: XHR to blocked domain was denied.');
      }
      return sendM.call(this, body);
    };
    window.XMLHttpRequest.prototype.__pgWrapped = true;
  }

  /* --------------------------- sendBeacon ------------------------------ */
  if (navigator && typeof navigator.sendBeacon === 'function' && !navigator.sendBeacon.__pgWrapped) {
    const beacon = navigator.sendBeacon.bind(navigator);
    const wrapped = (url, data) => {
      const t0 = performance.now();
      const hit = verdict(url);
      if (hit) {
        report(url, 'Network sendBeacon', {
          details: `Beacon blocked → ${url}`,
          rule: `deny-list match "${hit}"`,
          enforcement: 'navigator.sendBeacon() returned false - payload discarded',
          latencyMs: Number((performance.now() - t0).toFixed(4)),
        });
        return false;
      }
      return beacon(url, data);
    };
    wrapped.__pgWrapped = true;
    try { navigator.sendBeacon = wrapped; } catch {}
  }

  if (config.reportRuntime) {
    // eslint-disable-next-line no-console
    console.info('[phishguard] runtime interceptor active →', config.hubUrl);
  }
}
