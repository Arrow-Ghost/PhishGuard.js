/**
 * Attack-impact modelling.
 *
 * Turns a scan finding into a structured "what would actually happen" model:
 * the attack vector, the kill chain, the CIA impact, the blast radius and the
 * concrete system effects. Derived from the advisory's CWE classification,
 * severity, and where the package sits in the dependency tree - not canned text.
 */

/* CWE -> vector taxonomy. Keys are the numeric part of the CWE id. */
const CWE_TABLE = {
  79:   { vector: 'Cross-Site Scripting', goal: 'Execute attacker JavaScript in a victim\'s session',
          cia: { c: 'high', i: 'high', a: 'low' }, surface: 'browser',
          effects: ['Session cookie / token theft', 'DOM rewriting and UI spoofing', 'Keystroke and form capture'] },
  94:   { vector: 'Code Injection', goal: 'Run arbitrary code inside your process',
          cia: { c: 'high', i: 'high', a: 'high' }, surface: 'server',
          effects: ['Arbitrary code execution in the Node process', 'Secret and env-var disclosure', 'Lateral movement from the host'] },
  95:   { vector: 'Eval Injection', goal: 'Run arbitrary code via dynamic evaluation',
          cia: { c: 'high', i: 'high', a: 'high' }, surface: 'server',
          effects: ['Arbitrary code execution', 'Process takeover', 'Persistence via written files'] },
  78:   { vector: 'OS Command Injection', goal: 'Run shell commands on the host',
          cia: { c: 'high', i: 'high', a: 'high' }, surface: 'server',
          effects: ['Shell access as the app user', 'Credential file exfiltration', 'CI/CD runner compromise'] },
  1321: { vector: 'Prototype Pollution', goal: 'Corrupt Object.prototype to change program logic',
          cia: { c: 'medium', i: 'high', a: 'medium' }, surface: 'both',
          effects: ['Authorisation checks silently bypassed', 'Downstream gadget chains to RCE', 'Unpredictable app-wide behaviour'] },
  400:  { vector: 'Resource Exhaustion (DoS)', goal: 'Exhaust CPU/memory to take the service down',
          cia: { c: 'none', i: 'none', a: 'high' }, surface: 'server',
          effects: ['Event loop stalls, requests time out', 'Container OOM-kill / restart loop', 'Cascading failure to dependents'] },
  1333: { vector: 'Regular Expression DoS', goal: 'Hang the event loop with catastrophic backtracking',
          cia: { c: 'none', i: 'none', a: 'high' }, surface: 'server',
          effects: ['Single crafted input pins a CPU core', 'Request queue backs up', 'Health checks fail, instance cycles'] },
  770:  { vector: 'Unbounded Allocation', goal: 'Force unbounded memory allocation',
          cia: { c: 'none', i: 'none', a: 'high' }, surface: 'server',
          effects: ['Memory exhaustion', 'Process crash', 'Denial of service to all tenants on the host'] },
  22:   { vector: 'Path Traversal', goal: 'Read or write files outside the intended directory',
          cia: { c: 'high', i: 'high', a: 'medium' }, surface: 'server',
          effects: ['Arbitrary file read (.env, keys, /etc/passwd)', 'Arbitrary file overwrite', 'Code execution via written startup files'] },
  59:   { vector: 'Link Following / Symlink Attack', goal: 'Escape an extraction directory via links',
          cia: { c: 'high', i: 'high', a: 'medium' }, surface: 'server',
          effects: ['Files written outside the target directory', 'Overwrite of build or config artefacts', 'Supply-chain persistence in CI'] },
  918:  { vector: 'Server-Side Request Forgery', goal: 'Make your server issue attacker-chosen requests',
          cia: { c: 'high', i: 'medium', a: 'low' }, surface: 'server',
          effects: ['Cloud metadata (IMDS) credential theft', 'Internal service enumeration', 'Firewall bypass via your own host'] },
  502:  { vector: 'Unsafe Deserialization', goal: 'Instantiate attacker-controlled objects',
          cia: { c: 'high', i: 'high', a: 'high' }, surface: 'server',
          effects: ['Gadget-chain remote code execution', 'Application state corruption', 'Privilege escalation'] },
  287:  { vector: 'Improper Authentication', goal: 'Act as another user without credentials',
          cia: { c: 'high', i: 'high', a: 'none' }, surface: 'server',
          effects: ['Account takeover', 'Unauthorised data access', 'Audit trail attributed to the wrong user'] },
  306:  { vector: 'Missing Authentication', goal: 'Reach a privileged function with no credentials',
          cia: { c: 'high', i: 'high', a: 'medium' }, surface: 'server',
          effects: ['Unauthenticated access to admin functionality', 'Mass data extraction', 'Configuration tampering'] },
  862:  { vector: 'Missing Authorization', goal: 'Access resources belonging to other users',
          cia: { c: 'high', i: 'medium', a: 'none' }, surface: 'server',
          effects: ['Horizontal privilege escalation / IDOR', 'Cross-tenant data leakage'] },
  863:  { vector: 'Incorrect Authorization', goal: 'Bypass an authorisation decision',
          cia: { c: 'high', i: 'medium', a: 'none' }, surface: 'server',
          effects: ['Privilege escalation', 'Access to restricted endpoints'] },
  200:  { vector: 'Information Disclosure', goal: 'Read data that should not be exposed',
          cia: { c: 'high', i: 'none', a: 'none' }, surface: 'both',
          effects: ['Secrets or PII exposed in responses/logs', 'Recon data for a follow-up attack'] },
  209:  { vector: 'Error-Message Information Leak', goal: 'Harvest internals from error output',
          cia: { c: 'medium', i: 'none', a: 'none' }, surface: 'server',
          effects: ['Stack traces reveal paths and versions', 'Easier targeting of known exploits'] },
  352:  { vector: 'Cross-Site Request Forgery', goal: 'Make a logged-in user perform an unwanted action',
          cia: { c: 'low', i: 'high', a: 'none' }, surface: 'browser',
          effects: ['State-changing actions performed as the victim', 'Account settings or funds manipulated'] },
  601:  { vector: 'Open Redirect', goal: 'Bounce users to an attacker-controlled site',
          cia: { c: 'medium', i: 'low', a: 'none' }, surface: 'browser',
          effects: ['Credible phishing from your own domain', 'OAuth token leakage via redirect_uri'] },
  327:  { vector: 'Broken Cryptography', goal: 'Break confidentiality of protected data',
          cia: { c: 'high', i: 'medium', a: 'none' }, surface: 'both',
          effects: ['Encrypted data recoverable', 'Signature/token forgery'] },
  330:  { vector: 'Insufficiently Random Values', goal: 'Predict tokens or identifiers',
          cia: { c: 'high', i: 'high', a: 'none' }, surface: 'both',
          effects: ['Session/reset-token prediction', 'Account takeover without credentials'] },
  915:  { vector: 'Mass Assignment', goal: 'Set fields the user should not control',
          cia: { c: 'medium', i: 'high', a: 'none' }, surface: 'server',
          effects: ['Privilege fields (isAdmin) overwritten', 'Business-logic bypass'] },
  471:  { vector: 'Object Attribute Modification', goal: 'Mutate internal object state',
          cia: { c: 'medium', i: 'high', a: 'medium' }, surface: 'both',
          effects: ['Logic corruption', 'Security checks skipped'] },
  116:  { vector: 'Improper Output Encoding', goal: 'Break out of the intended output context',
          cia: { c: 'medium', i: 'high', a: 'none' }, surface: 'browser',
          effects: ['Injection into HTML/JS/SQL sinks', 'Downstream XSS'] },
  407:  { vector: 'Algorithmic Complexity Attack', goal: 'Trigger worst-case algorithmic behaviour',
          cia: { c: 'none', i: 'none', a: 'high' }, surface: 'server',
          effects: ['Quadratic/exponential CPU burn on small input', 'Service unavailability'] },
};

const GENERIC = {
  vector: 'Known Vulnerability', goal: 'Abuse a defect in this dependency',
  cia: { c: 'medium', i: 'medium', a: 'medium' }, surface: 'both',
  effects: ['Behaviour outside the library\'s security guarantees', 'Depends on how your code calls this package'],
};

const MALWARE = {
  vector: 'Malicious Package', goal: 'Steal secrets and establish persistence on install',
  cia: { c: 'high', i: 'high', a: 'high' }, surface: 'both',
  effects: [
    'Install-time script runs with your user privileges',
    'Environment variables, .npmrc and SSH keys harvested',
    'Outbound beacon to attacker infrastructure',
    'CI/CD tokens exfiltrated from the build runner',
  ],
};

const TYPOSQUAT = {
  vector: 'Name-Confusion / Typosquat', goal: 'Get installed in place of the package you meant',
  cia: { c: 'high', i: 'high', a: 'medium' }, surface: 'both',
  effects: [
    'Unknown author\'s code in your dependency tree',
    'Install hooks execute before any of your code runs',
    'Silent substitution survives lockfile commits',
  ],
};

const DEPRECATED = {
  vector: 'Unmaintained Dependency', goal: 'Wait for an unpatched defect to be discovered',
  cia: { c: 'low', i: 'low', a: 'low' }, surface: 'both',
  effects: [
    'No upstream fixes for future advisories',
    'Growing distance from a supported upgrade path',
    'Transitive pin blocks other packages from updating',
  ],
};

function cweNumbers(cwes) {
  return (cwes || [])
    .map(c => {
      const m = String(c).match(/(\d+)/);
      return m ? Number(m[1]) : null;
    })
    .filter(Boolean);
}

/** Guess a vector from the advisory text when no CWE is attached. */
function vectorFromText(text) {
  const t = String(text || '').toLowerCase();
  const probe = [
    [/prototype pollution/, 1321], [/regular expression denial|redos|backtrack/, 1333],
    [/command injection/, 78], [/code injection|arbitrary code|rce|remote code execution/, 94],
    [/cross[- ]site scripting|xss/, 79], [/path traversal|directory traversal/, 22],
    [/symlink|hardlink|link following/, 59], [/ssrf|server[- ]side request/, 918],
    [/deserializ/, 502], [/denial of service|dos|resource exhaustion|infinite loop|uncontrolled recursion/, 400],
    [/authorization|authorisation|access control/, 863], [/authentication/, 287],
    [/information (disclosure|exposure)|leak/, 200], [/csrf|request forgery/, 352],
    [/open redirect/, 601], [/quadratic|complexity/, 407],
  ];
  for (const [re, cwe] of probe) if (re.test(t)) return cwe;
  return null;
}

function severityToLikelihood(severity, kevHit, direct) {
  // The top label is reserved for CISA-KEV confirmation - severity alone never
  // earns it, otherwise the verdict contradicts the preconditions list.
  if (kevHit) return 'Active in the wild';
  let base = { critical: 4, high: 3, moderate: 2, low: 1 }[severity] ?? 2;
  if (direct) base = Math.min(4, base + 1);
  return ['—', 'Rare', 'Unlikely', 'Possible', 'Likely'][base];
}

function blastRadius(finding, pkg) {
  if (finding.type === 'malicious' || finding.type === 'typosquat') {
    return 'Whole machine + CI: install scripts run before any sandboxing applies.';
  }
  if (pkg && pkg.direct) {
    return 'Directly imported by your code - every call site is a potential entry point.';
  }
  return `Transitive (depth ${pkg ? pkg.depth : '?'}) - reachable only through the parent package's use of it.`;
}

/** Build the kill-chain nodes the Sandbox renders. */
function killChain(profile, finding, pkg) {
  const name = finding.packageName;
  const isMal = finding.type === 'malicious' || finding.type === 'typosquat';
  if (isMal) {
    return [
      { id: 'install', label: 'Install', detail: `npm install pulls ${name}`, phase: 'delivery' },
      { id: 'hook', label: 'Lifecycle hook', detail: 'preinstall/postinstall script executes', phase: 'execution' },
      { id: 'harvest', label: 'Harvest', detail: 'env vars, .npmrc, SSH keys, CI tokens read', phase: 'collection' },
      { id: 'beacon', label: 'Exfiltrate', detail: 'outbound POST to attacker host', phase: 'exfiltration' },
      { id: 'blocked', label: 'PhishGuard', detail: 'runtime agent blocks the outbound call', phase: 'mitigation' },
    ];
  }
  const entry = profile.surface === 'browser'
    ? { id: 'entry', label: 'Untrusted input', detail: 'attacker-controlled value reaches the page', phase: 'delivery' }
    : { id: 'entry', label: 'Untrusted input', detail: 'attacker-controlled value reaches your handler', phase: 'delivery' };
  return [
    entry,
    { id: 'reach', label: 'Reaches sink', detail: `passed into ${name}${pkg && !pkg.direct ? ' via its parent' : ''}`, phase: 'reconnaissance' },
    { id: 'trigger', label: profile.vector, detail: finding.title || profile.goal, phase: 'exploitation' },
    { id: 'effect', label: 'Impact', detail: profile.effects[0], phase: 'impact' },
    { id: 'blocked', label: 'Mitigation', detail: finding.fixedVersion ? `patched in ${finding.fixedVersion}` : 'no patch published - mitigate in code', phase: 'mitigation' },
  ];
}

/**
 * @param {object} finding  a flat finding from the scan report
 * @param {object} pkg      the package record it belongs to (optional)
 * @param {Set}    kevSet   CISA KEV CVE ids (optional)
 */
function modelImpact(finding, pkg, kevSet) {
  let profile;
  if (finding.type === 'malicious') profile = MALWARE;
  else if (finding.type === 'typosquat') profile = TYPOSQUAT;
  else if (finding.type === 'deprecated') profile = DEPRECATED;
  else {
    const nums = cweNumbers(finding.cwes);
    const hit = nums.find(n => CWE_TABLE[n]);
    const guessed = hit || vectorFromText(`${finding.title} ${finding.description}`);
    profile = (guessed && CWE_TABLE[guessed]) || GENERIC;
  }

  const kevHit = !!(kevSet && finding.identifier && kevSet.has(String(finding.identifier).toUpperCase()));
  const direct = !!(pkg ? pkg.direct : finding.direct);

  return {
    vector: profile.vector,
    attackerGoal: profile.goal,
    surface: profile.surface,
    confidentiality: profile.cia.c,
    integrity: profile.cia.i,
    availability: profile.cia.a,
    likelihood: severityToLikelihood(finding.severity, kevHit, direct),
    knownExploited: kevHit,
    blastRadius: blastRadius(finding, pkg),
    systemEffects: profile.effects,
    exploitConditions: [
      direct ? 'Package is imported directly by your code' : 'Requires the parent package to pass attacker input through',
      finding.fixedVersion ? `Affected below ${finding.fixedVersion}` : 'No fixed version published yet',
      kevHit ? 'Listed on CISA KEV - exploitation confirmed in the wild' : 'No confirmed in-the-wild exploitation',
    ],
    remediation: finding.fixedVersion
      ? `Upgrade ${finding.packageName} to ${finding.fixedVersion} or later.`
      : finding.type === 'malicious' || finding.type === 'typosquat'
        ? `Remove ${finding.packageName} immediately and rotate every secret the install had access to.`
        : `No patch available. Constrain input at the call site, or replace ${finding.packageName}.`,
    chain: killChain(profile, finding, pkg),
  };
}

/* ============================ attack tree ================================= */

/**
 * Walk the real dependency graph backwards from a package to the repo root,
 * producing the shortest route: [directDep, ..., vulnerablePkg].
 * Falls back to just the package itself when parent data is unavailable.
 */
function dependencyRoute(pkgName, packagesByName, maxHops = 5) {
  const start = packagesByName.get(pkgName);
  if (!start) return [pkgName];
  if (start.direct) return [pkgName];

  // BFS over parent edges until we reach a direct dependency
  const seen = new Set([pkgName]);
  let frontier = [[pkgName]];
  for (let hop = 0; hop < maxHops; hop++) {
    const next = [];
    for (const path of frontier) {
      const head = path[0];
      const node = packagesByName.get(head);
      for (const parent of (node && node.parents) || []) {
        if (seen.has(parent)) continue;
        const p = packagesByName.get(parent);
        const newPath = [parent, ...path];
        if (p && p.direct) return newPath;       // reached your package.json
        seen.add(parent);
        next.push(newPath);
      }
    }
    if (!next.length) break;
    frontier = next;
  }
  // no direct ancestor found - return the deepest route we did find
  return frontier[0] || [pkgName];
}

/** Consequence branches: one node per distinct system effect. */
function impactBranches(profile, finding) {
  return profile.effects.slice(0, 3).map((text, i) => ({
    id: `impact-${i}`,
    label: text.length > 46 ? text.slice(0, 44) + '…' : text,
    detail: text,
    phase: 'impact',
    kind: 'impact',
  }));
}

/**
 * A branching attack tree rooted at the repository.
 *
 *   repo → direct dep → … → vulnerable package → exploit → [impacts…] → PhishGuard
 *
 * Every node carries a `depth` so the UI can light the tree up one level at a
 * time, and the terminal mitigation node is what stops the propagation.
 *
 * @param {object} finding
 * @param {object|null} pkg
 * @param {Map} packagesByName   name -> package record (for parent edges)
 * @param {object} meta          { projectName, kevSet }
 */
function buildAttackTree(finding, pkg, packagesByName, meta = {}) {
  const projectName = meta.projectName || 'your app';
  const kevSet = meta.kevSet;
  const isMal = finding.type === 'malicious' || finding.type === 'typosquat';

  let profile;
  if (finding.type === 'malicious') profile = MALWARE;
  else if (finding.type === 'typosquat') profile = TYPOSQUAT;
  else if (finding.type === 'deprecated') profile = DEPRECATED;
  else {
    const nums = cweNumbers(finding.cwes);
    const hit = nums.find(n => CWE_TABLE[n]);
    const guessed = hit || vectorFromText(`${finding.title} ${finding.description}`);
    profile = (guessed && CWE_TABLE[guessed]) || GENERIC;
  }

  const nodes = [];
  const push = (n) => { nodes.push(n); return n.id; };

  // ---- 0. the repository root
  const rootId = push({
    id: 'root', parent: null, depth: 0, kind: 'repo', phase: 'entry',
    label: projectName,
    detail: isMal ? 'npm install runs here' : 'attacker-controlled input enters your app',
  });

  // ---- 1..n. the real dependency route
  const route = dependencyRoute(finding.packageName, packagesByName);
  let parent = rootId;
  let depth = 0;
  route.forEach((name, i) => {
    const rec = packagesByName.get(name);
    const isTarget = i === route.length - 1;
    depth += 1;
    parent = push({
      id: `dep-${name}`,
      parent,
      depth,
      kind: isTarget ? 'sink' : 'dependency',
      phase: i === 0 ? 'delivery' : 'reconnaissance',
      label: name,
      version: rec ? rec.version : (isTarget ? finding.packageVersion : null),
      detail: i === 0
        ? (rec && rec.direct ? 'direct dependency in package.json' : 'entry point into the tree')
        : `pulled in by ${route[i - 1]}`,
      vulnerable: isTarget,
      severity: isTarget ? finding.severity : null,
    });
  });

  // ---- exploitation
  depth += 1;
  const exploitId = push({
    id: 'exploit',
    parent,
    depth,
    kind: 'exploit',
    phase: isMal ? 'execution' : 'exploitation',
    label: profile.vector,
    detail: finding.title || profile.goal,
    severity: finding.severity,
    identifier: finding.identifier || null,
    knownExploited: !!(kevSet && finding.identifier && kevSet.has(String(finding.identifier).toUpperCase())),
  });

  // ---- consequence branches (this is where the tree fans out)
  depth += 1;
  const impactDepth = depth;
  const impactIds = impactBranches(profile, finding).map(b =>
    push({ ...b, parent: exploitId, depth: impactDepth })
  );

  // ---- PhishGuard terminates every branch
  const mitigationDepth = impactDepth + 1;
  push({
    id: 'mitigation',
    parent: impactIds,                 // converges: many parents, one terminal
    depth: mitigationDepth,
    kind: 'mitigation',
    phase: 'mitigation',
    label: 'PhishGuard',
    detail: finding.fixedVersion
      ? `upgrade ${finding.packageName} → ${finding.fixedVersion}`
      : isMal
        ? `remove ${finding.packageName} and rotate secrets`
        : 'no patch — constrain input at the call site',
    remediation: true,
  });

  return {
    nodes,
    maxDepth: mitigationDepth,
    route,
    vector: profile.vector,
    branching: impactIds.length,
  };
}

module.exports = { modelImpact, buildAttackTree, dependencyRoute, CWE_TABLE };
