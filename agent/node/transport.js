/**
 * Fire-and-forget telemetry reporting for the Node runtime agent.
 *
 * HTTP POST only, deliberately - no persistent WebSocket. A production
 * server process shouldn't carry a reconnect/backoff state machine just to
 * stream telemetry, and the dashboard's live view updates the same way
 * regardless of how the hub received the event (it broadcasts to dashboard
 * clients server-side either way). See agent/interceptor.js for the
 * browser agent's WS-first approach, which exists for that page's own
 * real-time connection, not because the hub needs it.
 */

function sendTelemetry(hubUrl, payload) {
  const url = `${String(hubUrl).replace(/\/$/, '')}/api/telemetry`;
  try {
    fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ origin: 'node', ...payload }),
    }).catch(() => { /* never let a reporting failure affect the host app */ });
  } catch { /* fetch not available / synchronous throw - ignore */ }
}

module.exports = { sendTelemetry };
