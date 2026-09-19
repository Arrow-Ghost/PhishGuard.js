/**
 * PhishGuard DOM shield (browser).
 *
 * A MutationObserver (plus a light appendChild guard) that blocks dynamically
 * injected <script> elements pointing at un-vetted origins, and flags inline
 * scripts that look obfuscated. Telemetry is POSTed to the SOC hub.
 */
import { resolveAgentConfig } from './config.js';

let installed = false;

export function installDomShield(userConfig = {}) {
  if (installed || typeof document === 'undefined') return;
  installed = true;

  const config = { ...resolveAgentConfig(), ...userConfig };
  const blocked = [...config.blockDomains, ...config.demoBlock];
  const approvedCdn = [
    'https://cdnjs.cloudflare.com', 'https://cdn.jsdelivr.net',
    'https://unpkg.com', 'https://esm.run', 'https://esm.sh',
    ...config.allowDomains,
  ];
  const reportUrl = `${config.httpUrl.replace(/\/$/, '')}/api/telemetry`;

  function post(body) {
    const raw = (window.fetch && window.fetch.__pgOriginal) || window.fetch;
    try {
      raw(reportUrl, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body), keepalive: true,
      }).catch(() => {});
    } catch {}
  }

  function evaluate(node) {
    if (!node || node.tagName !== 'SCRIPT') return;
    const src = node.getAttribute('src') || '';
    const content = node.textContent || '';
    let status = 'ALLOWED';
    let severity = 'info';
    let details;
    let rule = null;
    let enforcement = null;
    const t0 = performance.now();
    const action = src ? 'Load Dynamic Script' : 'Execute Inline Script';

    if (src) {
      details = `Source: ${src}`;
      const hit = blocked.find(d => src.includes(d));
      if (hit) {
        status = 'BLOCKED'; severity = 'critical';
        details += ' — matches blocked-origin policy';
        rule = `blocked-origin match "${hit}"`;
        enforcement = 'script type rewritten to text/pg-blocked and node removed before the browser could fetch it';
      } else {
        const sameOrigin = src.startsWith('/') || src.startsWith(location.origin);
        const okCdn = approvedCdn.some(p => src.startsWith(p));
        if (!sameOrigin && !okCdn) {
          status = 'FLAGGED'; severity = 'warning';
          details += ' — third-party origin not on the CDN allowlist';
          rule = 'CDN allowlist miss';
          enforcement = 'allowed to load, recorded for review (origin is not on the approved CDN list)';
        }
      }
    } else {
      const snippet = content.slice(0, 120);
      details = `Inline: ${snippet}${content.length > 120 ? '…' : ''}`;
      const obf = /eval\(|atob\(|Function\(["'`]|_0x[a-f0-9]{4}|\\x[0-9a-f]{2}\\x[0-9a-f]{2}/i.test(content);
      if (obf) {
        status = 'FLAGGED'; severity = 'warning';
        details += ' — obfuscation signature';
        rule = 'inline obfuscation signature (eval/atob/hex-escape)';
        enforcement = 'inline script allowed to run, flagged for review';
      }
    }

    post({
      timestamp: new Date().toISOString(),
      origin: 'browser',
      sourcePackage: 'DOM Shield',
      callerUrl: location.href,
      action, details, status, severity, rule, enforcement,
      latencyMs: Number((performance.now() - t0).toFixed(4)),
      stack: new Error().stack || '',
    });

    if (status === 'BLOCKED') {
      node.type = 'text/pg-blocked';
      node.remove();
      // eslint-disable-next-line no-console
      console.error('[phishguard] blocked dynamic script:', src);
    }
  }

  // appendChild / insertBefore guard (covers the synchronous-execution race)
  for (const method of ['appendChild', 'insertBefore']) {
    const orig = Node.prototype[method];
    if (orig.__pgWrapped) continue;
    const wrapped = function (node, ...rest) {
      try {
        if (node && node.tagName === 'SCRIPT') {
          const src = node.getAttribute && node.getAttribute('src');
          if (src && blocked.some(d => src.includes(d))) {
            post({
              timestamp: new Date().toISOString(), origin: 'browser', sourcePackage: 'DOM Shield',
              callerUrl: location.href, action: 'Load Dynamic Script',
              details: `Source: ${src} — blocked before insertion`, status: 'BLOCKED', severity: 'critical',
              rule: `blocked-origin match "${blocked.find(d => src.includes(d))}"`,
              enforcement: 'Node.appendChild() threw - the script element never entered the DOM',
              stack: new Error().stack || '',
            });
            throw new Error('PhishGuard: blocked dynamic script injection.');
          }
        }
      } catch (e) {
        if (e.message.startsWith('PhishGuard')) throw e;
      }
      return orig.call(this, node, ...rest);
    };
    wrapped.__pgWrapped = true;
    Node.prototype[method] = wrapped;
  }

  const observer = new MutationObserver((list) => {
    for (const m of list) {
      if (m.type !== 'childList') continue;
      m.addedNodes.forEach((n) => {
        if (n.tagName === 'SCRIPT') evaluate(n);
        if (n.getElementsByTagName) {
          for (const s of n.getElementsByTagName('script')) evaluate(s);
        }
      });
    }
  });

  const start = () => observer.observe(document.documentElement, { childList: true, subtree: true });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
}
