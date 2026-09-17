# 🛡️ PhishGuard

**Zero-trust dependency & supply-chain security scanner with a self-hosted SOC dashboard.**

Install it into any repo. It resolves that repo's dependency tree, checks every
package against **live OSV.dev advisories** (with real `semver` range matching),
flags **deprecated** packages and **typosquats**, scores the project's security
**posture**, and keeps a **history** so you can see the trend over time — all
stored locally in the repo under `.phishguard/`.

Nothing about it is specific to one project: one global install serves every
repo you point it at.

---

## Install

```bash
npm install --save-dev phishguard
```

or run it without installing:

```bash
npx phishguard scan
```

Requires Node ≥ 18. `sqlite3` is a native dependency (prebuilt binaries for
common platforms).

---

## Commands

### `phishguard scan`

Scans the current repo and prints a report. Non-zero exit when findings meet the
threshold — drop it straight into CI.

```bash
phishguard scan                      # pretty report, exits 1 on any critical
phishguard scan --fail-on high       # also fail on high-severity vulns
phishguard scan --fail-on none       # never change the exit code
phishguard scan --json > report.json # full report as JSON (exit gating still applies)
phishguard scan --offline            # bundled advisory data only, no network
phishguard scan --no-dev             # skip devDependencies
phishguard scan --cwd ../other-repo  # scan a different project
phishguard scan --no-save            # don't append to .phishguard history
```

What it checks per package:

| Check | Source |
| --- | --- |
| Known vulnerabilities | `POST https://api.osv.dev/v1/querybatch` → per-advisory detail, cached in `.phishguard/cache/`. Falls back to a small bundled set (`src/data/offline-advisories.json`) when offline. |
| Affected-range matching | the real [`semver`](https://www.npmjs.com/package/semver) package, applied to the concrete version from your lockfile |
| Deprecation | the npm registry `deprecated` field for the installed version (or `dist-tags.latest`) |
| Typosquatting | Levenshtein + Jaro-Winkler vs a bundled list of high-value packages, **gated** by a registry-reputation check so established packages aren't flagged |
| Known-malicious names | bundled list |

Lockfiles understood: `package-lock.json` (v1/v2/v3), `npm-shrinkwrap.json`,
`yarn.lock`, `pnpm-lock.yaml`. With no lockfile it falls back to the manifest
ranges (versions become best-effort and each package gets an `unresolved` note).

### `phishguard dashboard`

Boots the SOC dashboard + telemetry hub for the current repo and opens a browser.

```bash
phishguard dashboard                 # scan + serve on http://localhost:4173
phishguard dashboard --port 8080
phishguard dashboard --no-scan       # serve the last saved scan, don't re-scan
phishguard dashboard --no-open
```

The dashboard has: posture score & trend, findings by type, the full dependency
tree as a force-directed graph (risk-coloured from real findings), a package
trust matrix, an advisory feed for **your** packages, a live SQL console over the
`.phishguard` database, a runtime telemetry stream, and a forensics view of
critical findings + blocked runtime events.

### `phishguard init`

Writes `phishguard.config.json`, adds `.phishguard/` to `.gitignore`, and prints
the runtime-agent snippet.

---

## Configuration — `phishguard.config.json`

All optional:

```json
{
  "port": 4173,
  "failOn": "critical",        // critical | high | moderate | warning | none
  "includeDev": true,
  "offline": false,
  "allowDomains": [],          // runtime agent: always allow
  "blockDomains": [],          // runtime agent: always block
  "cacheTtlHours": 24
}
```

---

## Optional: runtime agent (browser apps)

For front-end apps, the agent hooks `fetch` / `XMLHttpRequest` / `sendBeacon` and
watches the DOM for injected `<script>` tags, streaming blocked events to the
dashboard's telemetry stream. Import it **first**, before your framework boots:

```js
import 'phishguard/agent';           // auto-installs; talks to ws://localhost:4173 by default
```

```js
// or configure it
import { installAgent } from 'phishguard/agent';
installAgent({ hubUrl: 'ws://localhost:4173', blockDomains: ['evil.example'] });
```

This is defence-in-depth telemetry for the dashboard — `phishguard scan` is the
primary control.

---

## Programmatic API

```js
const pg = require('phishguard');

const report = await pg.scan();               // scan process.cwd()'s project
const report = await pg.scan('/path/to/repo');
const { url, stop, runScan } = await pg.startDashboard({ port: 4173 });
```

`scan()` returns the full report object (`project`, `counts`, `score`, `grade`,
`status`, `packages[]`, `findings[]`).

---

## Data & storage

Everything lives in `<repo>/.phishguard/`:

```
.phishguard/
├── phishguard.db     SQLite: scans, scan_packages, scan_findings,
│                     posture_snapshots, security_logs, quarantine
└── cache/            OSV + npm-registry response cache
```

Add `.phishguard/` to `.gitignore` (or run `phishguard init`).

---

## Project layout

```
bin/phishguard.js         CLI
src/index.js              programmatic API
src/core/                 scanner: resolve → lockfile → osv → registry → typosquat → score
src/server/               Express + WebSocket hub, SQLite layer, REST API
src/data/                 bundled popular-packages list + offline advisory fallback
agent/                    browser runtime agent (fetch/XHR/DOM hooks)
dashboard/                React SOC UI (built to dashboard/dist, served by the hub)
```

Dashboard development: `npm run dev:dashboard` (Vite on :3000, proxies API/WS to
a `phishguard dashboard` hub on :4173). Rebuild the shipped UI with
`npm run build:dashboard`.

---

## Notes on accuracy

- Vulnerability and deprecation data are **real** (OSV.dev + npm registry).
- Typosquatting is a **heuristic** — it can miss and it can (rarely) false-positive; it's gated by a reputation check to keep noise down.
- The "posture projection" chart is a plain linear regression over your scan history.
- The intrusion radar and global attack map are **visual only** and labelled as such in the UI.
- The threat "analysis" panel is rule-based, not an LLM.

## License

MIT
