/**
 * Minimal JSON-over-HTTPS helper built on the global fetch (Node >= 18).
 * Adds a timeout and a couple of retries so a flaky network degrades to the
 * offline fallback instead of throwing.
 */

async function requestJson(url, { method = 'GET', body, headers = {}, timeoutMs = 12000, retries = 2 } = {}) {
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetch(url, {
        method,
        headers: {
          'accept': 'application/json',
          'user-agent': 'phishguard-scanner',
          ...(body ? { 'content-type': 'application/json' } : {}),
          ...headers,
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: ctrl.signal,
      });
      clearTimeout(timer);
      if (res.status === 404) return { ok: true, status: 404, data: null };
      if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
      const data = await res.json();
      return { ok: true, status: res.status, data };
    } catch (err) {
      clearTimeout(timer);
      lastErr = err;
      if (attempt < retries) await new Promise(r => setTimeout(r, 300 * (attempt + 1)));
    }
  }
  return { ok: false, error: lastErr };
}

/** Run async `fn` over `items` with a bounded concurrency pool. */
async function pool(items, concurrency, fn) {
  const results = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      results[idx] = await fn(items[idx], idx);
    }
  });
  await Promise.all(workers);
  return results;
}

module.exports = { requestJson, pool };
