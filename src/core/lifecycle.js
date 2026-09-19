/**
 * npm lifecycle-script ("preinstall" / "install" / "postinstall") risk
 * classification. This is the check that would have caught event-stream,
 * ua-parser-js and the node-ipc/chalk maintainer-account compromises: those
 * attacks ran during `npm install`, before any static scan of the installed
 * code or any runtime agent was in the picture.
 *
 * Used by both `scanner.js` (registry-sourced scripts, for the packages it
 * already fetches metadata for) and `installGate.js` (disk-sourced scripts,
 * full tree coverage at install time). Same classifier either way so the
 * finding shape and severity model never disagree between the two paths.
 */

const LIFECYCLE_KEYS = ['preinstall', 'install', 'postinstall'];

// Signatures that indicate the script is doing something a lifecycle script
// has no legitimate reason to do: fetching and running remote code, decoding
// an opaque payload, or a raw shell-out to a network client.
const SUSPICIOUS_PATTERN = /(curl\s|wget\s|Invoke-WebRequest|\|\s*(sh|bash)\b|base64\s+(-d|--decode)|eval\(|atob\(|Function\(["'`]|_0x[a-f0-9]{4}|nc\s+-e)/i;

// Command prefixes that are common and legitimate for native addons, git
// hooks and tooling that ships prebuilt binaries. A match here only
// suppresses the finding when the package also looks established (see
// reputation.js) - a fresh, low-reputation package claiming to be a
// node-gyp build is still worth a look.
const KNOWN_BENIGN_PATTERN = /^(node-gyp\b|prebuild-install\b|husky\b|is-ci\s*\|\|\s*husky|patch-package\b|electron-builder\b|opencollective-postinstall\b|node\s+(install|postinstall|scripts\/(install|postinstall))\.js\s*($|--\S)|playwright\s+install|esbuild\/install\.js)/i;

function extractLifecycleScripts(scripts) {
  if (!scripts || typeof scripts !== 'object') return null;
  const out = {};
  let any = false;
  for (const key of LIFECYCLE_KEYS) {
    if (typeof scripts[key] === 'string' && scripts[key].trim()) {
      out[key] = scripts[key].trim();
      any = true;
    }
  }
  return any ? out : null;
}

/**
 * @param {object} opts { scripts: {preinstall?,install?,postinstall?}|null, established: boolean }
 * @returns {Array} zero or one finding, shaped like scanner.js's other finding types
 */
function classifyLifecycleScripts({ scripts, established }) {
  const found = extractLifecycleScripts(scripts);
  if (!found) return [];

  const entries = Object.entries(found);
  const combined = entries.map(([, v]) => v).join(' && ');
  const suspicious = SUSPICIOUS_PATTERN.test(combined);
  const benign = KNOWN_BENIGN_PATTERN.test(combined.trim());

  let severity;
  if (suspicious) {
    severity = 'critical';
  } else if (benign && established) {
    return []; // established package, recognised build/tooling script - not worth a finding
  } else if (benign) {
    severity = 'low';
  } else if (established) {
    severity = 'moderate';
  } else {
    severity = 'high';
  }

  const which = entries.map(([k]) => k).join(', ');
  return [{
    type: 'lifecycle-script',
    severity,
    title: suspicious
      ? `${which} script matches a known exfiltration/obfuscation pattern`
      : `Runs a ${which} script during install`,
    description: suspicious
      ? `This package's ${which} script contains a pattern consistent with fetching or executing remote/obfuscated code during install: "${combined.slice(0, 200)}${combined.length > 200 ? '…' : ''}"`
      : `This package runs code during \`npm install\` via ${which}${established ? ", and the script doesn't match a recognised build/tooling pattern" : ', and the package does not look established (few versions, few maintainers, or recently published)'}. Lifecycle scripts run with full OS access before any application code executes.`,
    identifier: null,
    url: null,
    fixedVersion: null,
  }];
}

module.exports = { classifyLifecycleScripts, extractLifecycleScripts, LIFECYCLE_KEYS, SUSPICIOUS_PATTERN };
