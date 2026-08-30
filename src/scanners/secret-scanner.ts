import { ResolvedServer } from '../types/config.js';
import { Finding } from '../types/scan-result.js';
import { SECRET_PATTERNS } from '../data/secret-patterns.js';

// Entropy-detection calibration: values at least this long are checked,
// and only flagged above this Shannon bits-per-character.
const MIN_ENTROPY_VALUE_LENGTH = 20;
const MIN_ENTROPY_BITS_PER_CHAR = 4.5;

// Substrings that mark a matched value as a placeholder/template/vendor-doc
// example rather than a real credential. Checked case-insensitively against
// the value that matched a SECRET_PATTERNS regex. Deliberately narrow
// (e.g. 'test123' not bare 'test') so real fake-but-random test fixtures
// used elsewhere in this repo's own test suite (sequential alphabets,
// repeated letters) don't collide with it.
const PLACEHOLDER_TOKENS = [
  'changeme', 'change_me', 'change-me', 'changeit', 'changethis',
  'your-api-key', 'your_api_key', 'yourapikey',
  'placeholder', 'dummy', 'redacted', 'test123', 'example', 'foobar',
  'insertkeyhere', 'replacewithkey',
];

// Exact-match placeholders for DB-URL username/password fields. Substring
// matching is too loose here (real passwords legitimately contain
// "password" as part of a longer random string), so this list requires the
// whole credential field to equal one of these words.
const WEAK_CREDENTIAL_WORDS = new Set([
  'changeme', 'change_me', 'change-me', 'changeit', 'changethis',
  'password', 'pass', 'admin', 'root', 'test', 'guest', 'secret',
  '123456', 'letmein', 'qwerty', 'user', 'demo', 'sample', 'default',
  'foo', 'bar', 'postgres', 'mysql',
]);

// Hosts that indicate a local/dev/template config rather than a reachable
// live database. Combined with a weak credential field below, this is what
// tells "postgres://user:changeme@localhost/db" apart from a real leaked
// connection string.
const DEV_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1', 'host', 'hostname', 'db', 'database']);

// Path fragments that suggest a config is a test fixture, template, or
// documentation sample rather than a real deployed config. This LOWERS
// confidence (severity is downgraded one notch) but never grants immunity —
// a real credential committed under examples/ still fires CRITICAL.
const FIXTURE_PATH_REGEX = /(^|[\\/])(tests?|fixtures?|examples?|docs)([\\/]|$)|\.(template|sample|example|disabled)(\.|$)/i;

function isPlaceholderValue(text: string): boolean {
  const lower = text.toLowerCase();
  if (PLACEHOLDER_TOKENS.some(token => lower.includes(token))) return true;
  if (/x{4,}/i.test(text)) return true;
  if (/<[a-z0-9_ -]{1,40}>/i.test(text)) return true;
  return false;
}

/**
 * Extracts user/password/host from a "scheme://user:pass@host" value, if
 * present. Mirrors the shape of the 'Database URL with Credentials' pattern
 * but with capture groups, since SECRET_PATTERNS only stores a bare regex.
 */
function extractDbCredentials(value: string): { user: string; password: string; host: string } | null {
  const match = value.match(/[a-zA-Z][a-zA-Z0-9+.-]*:\/\/([^:@/\s]+):([^@/\s]+)@([^/\s]+)/);
  if (!match) return null;
  return { user: match[1], password: match[2], host: match[3] };
}

function isWeakDbCredential(host: string, password: string, user: string): boolean {
  const hostname = host.split(':')[0].toLowerCase();
  const isDevHost = DEV_HOSTS.has(hostname) || hostname.endsWith('.local');
  const isWeakPassword = WEAK_CREDENTIAL_WORDS.has(password.toLowerCase()) || password.length < 12;
  if (isDevHost && isWeakPassword) return true;
  // A placeholder-shaped password or username is weak regardless of host
  // (e.g. "your-api-key" on a real-looking prod hostname is still a template).
  if (isPlaceholderValue(password) || isPlaceholderValue(user)) return true;
  return false;
}

/**
 * Calculates the Shannon entropy of a string.
 * @param str The string to calculate entropy for.
 * @returns The entropy in bits per character.
 */
function calculateEntropy(str: string): number {
  if (!str) return 0;
  const frequencies: Record<string, number> = {};
  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Checks if a string looks like a UUID or other common high-entropy non-secrets.
 */
function isExemptFromEntropy(str: string): boolean {
  // UUID pattern
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (uuidRegex.test(str)) return true;
  
  // Base64 padded short strings often have high entropy but might not be secrets
  // We already have a length check (20+), so this is less of an issue.
  
  return false;
}

export function scanSecrets(server: ResolvedServer): Finding[] {
  const findings: Finding[] = [];
  
  const scanValue = (value: unknown, source: string, key?: string) => {
    // Config files can carry non-string values (numbers, booleans, objects);
    // a single malformed entry must not abort the whole scan.
    if (typeof value !== 'string') return;
    if (value.length === 0) return;

    // 1. Check for environment variable references (e.g., ${VAR} or $VAR or %VAR%)
    const windowsEnvRef = value.match(/^%([A-Z0-9_]+)%$/i);
    if (windowsEnvRef) {
      const varName = windowsEnvRef[1];
      if (!(varName in process.env) && !(varName.toUpperCase() in process.env)) {
        findings.push({
          id: 'missing-referenced-env-var',
          severity: 'MEDIUM',
          description: `Windows-style environment variable reference '%${varName}%' found in ${source}${key ? ` '${key}'` : ''}, but it is not set in the system.`,
          fixRecommendation: `Ensure '${varName}' is set in your environment before running the AI tool.`,
        });
      }
      return;
    }

    const envRefMatch = value.match(/^\$\{([A-Z0-9_]+)\}$|^\$([A-Z0-9_]+)$/i);
    if (envRefMatch) {
      const varName = envRefMatch[1] || envRefMatch[2];
      if (!(varName in process.env) && !(varName.toUpperCase() in process.env)) {
        findings.push({
          id: 'missing-referenced-env-var',
          severity: 'MEDIUM',
          description: `Environment variable reference '${varName}' found in ${source}${key ? ` '${key}'` : ''}, but it is not set in the system.`,
          fixRecommendation: `Ensure '${varName}' is set in your environment before running the AI tool.`,
        });
      }
      return;
    }

    // Also match against the percent-decoded form so %XX-obfuscated keys
    // are still caught (e.g. sk%5Ftest%5F...).
    let decoded: string | null = null;
    try {
      decoded = decodeURIComponent(value);
    } catch (_e) {
      decoded = null;
    }

    // 2. Check for hardcoded secret patterns
    let foundPattern = false;
    for (const pattern of SECRET_PATTERNS) {
      if (pattern.keyContext) {
        // Prefix-less formats need a credential-ish key name to be credible;
        // args have no key, so bare formats are never matched there.
        if (!key || !pattern.keyContext.test(key)) continue;
      }
      if (pattern.regex.test(value) || (decoded !== null && pattern.regex.test(decoded))) {
        // The 'Database URL with Credentials' pattern only checks structural
        // shape (scheme://user:pass@host); it says nothing about whether the
        // credential is real. Extract the fields and require the password to
        // look like an actual secret before treating this as CRITICAL.
        if (pattern.name === 'Database URL with Credentials') {
          const creds = extractDbCredentials(value) || (decoded !== null ? extractDbCredentials(decoded) : null);
          if (creds && isWeakDbCredential(creds.host, creds.password, creds.user)) {
            foundPattern = true; // matched shape, but confirmed placeholder: don't fall through to entropy either
            break;
          }
        } else if (isPlaceholderValue(value) || (decoded !== null && isPlaceholderValue(decoded))) {
          // Vendor doc examples (AWS's AKIA...EXAMPLE) and fabricated test
          // tokens (ghp_test123...) match the format regex but are not real.
          foundPattern = true;
          break;
        }

        const inFixturePath = FIXTURE_PATH_REGEX.test(server.configPath || '');
        findings.push({
          id: 'exposed-secret',
          severity: inFixturePath ? 'HIGH' : 'CRITICAL',
          description: `Exposed ${pattern.name} in ${source}${key ? ` '${key}'` : ''}.${inFixturePath ? ' Path suggests this may be a test fixture or example — verify before treating as a live credential.' : ''}`,
          fixRecommendation: `Move the secret to a secure environment variable and reference it instead (e.g., \${${key || 'VAR_NAME'}}).`,
          fixable: true,
          remediationConfidence: inFixturePath ? 60 : 99
        });
        foundPattern = true;
        break;
      }
    }

    // 3. Entropy-based detection (if no pattern matched)
    if (!foundPattern && value.length >= MIN_ENTROPY_VALUE_LENGTH) {
      const entropy = calculateEntropy(value);
      if (entropy > MIN_ENTROPY_BITS_PER_CHAR && !isExemptFromEntropy(value)) {
        findings.push({
          id: 'high-entropy-value',
          severity: 'MEDIUM',
          description: `High-entropy string (${entropy.toFixed(2)} bits/char) detected in ${source}${key ? ` '${key}'` : ''}. This might be an undocumented secret.`,
          fixRecommendation: 'Check whether this value is a sensitive credential. If so, move it to an environment variable.'
        });
      }
    }
  };

  // Scan environment variables
  if (server.env) {
    for (const [key, value] of Object.entries(server.env)) {
      scanValue(value, 'environment variable', key);
    }
  }

  // Scan URL credentials (e.g. https://user:pass@host) when present
  if (server.url) {
    scanValue(server.url, 'server url');
  }

  // Scan arguments
  if (server.args) {
    const argsArray = Array.isArray(server.args) ? server.args : Object.values(server.args);
    for (const arg of argsArray) {
      if (typeof arg === 'string') {
        scanValue(arg, 'argument');
      }
    }
  }

  return findings;
}
