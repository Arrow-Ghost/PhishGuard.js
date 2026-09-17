/**
 * PhishGuard runtime agent - browser entry point.
 *
 *   import 'phishguard/agent';                       // auto-install, config from globals
 *   import { installAgent } from 'phishguard/agent'; // manual
 *   installAgent({ hubUrl: 'ws://localhost:4173', blockDomains: ['evil.com'] });
 *
 * Import this BEFORE your framework bootstraps so the hooks wrap the originals.
 */
import { installInterceptor } from './interceptor.js';
import { installDomShield } from './domShield.js';

export function installAgent(config = {}) {
  installInterceptor(config);
  installDomShield(config);
}

// auto-install unless explicitly disabled
if (typeof window !== 'undefined' && window.__PHISHGUARD_DISABLE_AUTOINSTALL__ !== true) {
  installAgent(window.__PHISHGUARD_CONFIG__ || {});
}

export { installInterceptor, installDomShield };
