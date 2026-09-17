/**
 * Runtime agent configuration resolution (browser side).
 *
 * Priority:
 *   1. window.__PHISHGUARD_CONFIG__ (set inline before the agent loads)
 *   2. <script data-phishguard-hub="..." data-phishguard-block="a,b"> attributes
 *   3. same-origin as the page (works when the SOC dashboard serves the app)
 *   4. ws://localhost:4173  (default PhishGuard dashboard port)
 */
export function resolveAgentConfig() {
  const w = typeof window !== 'undefined' ? window : {};
  const fromGlobal = w.__PHISHGUARD_CONFIG__ || {};

  let fromScript = {};
  try {
    const el = document.currentScript
      || [...document.querySelectorAll('script[data-phishguard-hub]')].pop();
    if (el) {
      fromScript = {
        hubUrl: el.getAttribute('data-phishguard-hub') || undefined,
        blockDomains: (el.getAttribute('data-phishguard-block') || '').split(',').map(s => s.trim()).filter(Boolean),
        allowDomains: (el.getAttribute('data-phishguard-allow') || '').split(',').map(s => s.trim()).filter(Boolean),
      };
    }
  } catch { /* not in a DOM */ }

  const loc = w.location || { protocol: 'http:', host: 'localhost:4173', origin: 'http://localhost:4173', port: '4173' };
  const sameOriginWs = `${loc.protocol === 'https:' ? 'wss' : 'ws'}://${loc.host}`;
  // The Vite dev server runs the UI on :3000 but the hub (API+WS) is on :4173.
  // Anywhere else, assume the hub serves the page (same origin).
  const devVite = loc.port === '3000';

  const cfg = {
    hubUrl: fromGlobal.hubUrl || fromScript.hubUrl || (devVite ? 'ws://localhost:4173' : sameOriginWs),
    httpUrl: null,
    blockDomains: [
      ...(fromGlobal.blockDomains || []),
      ...(fromScript.blockDomains || []),
    ],
    allowDomains: [
      ...(fromGlobal.allowDomains || []),
      ...(fromScript.allowDomains || []),
    ],
    // demo endpoints used by the dashboard Sandbox page; harmless to keep blocked
    demoBlock: [
      'malicious-domain.com', 'attacker.com', 'eval-server.cc',
      'untrusted-analytics-tracker.cc', 'suspicious-scripts.biz',
      'raw.githubusercontent.com', 'pastebin.com', 'temp-hosting.net',
    ],
    reportRuntime: fromGlobal.reportRuntime !== false,
  };
  cfg.httpUrl = cfg.hubUrl.replace(/^ws/, 'http');
  return cfg;
}
