import { ResolvedServer } from '../types/config.js';
import { Finding } from '../types/scan-result.js';
import { SECRET_PATTERNS } from '../data/secret-patterns.js';

// Entropy-detection calibration: values at least this long are checked,
// and only flagged above this Shannon bits-per-character.
const MIN_ENTROPY_VALUE_LENGTH = 20;
const MIN_ENTROPY_BITS_PER_CHAR = 4.5;

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
        findings.push({
          id: 'exposed-secret',
          severity: 'CRITICAL',
          description: `Exposed ${pattern.name} in ${source}${key ? ` '${key}'` : ''}.`,
          fixRecommendation: `Move the secret to a secure environment variable and reference it instead (e.g., \${${key || 'VAR_NAME'}}).`,
          fixable: true,
          remediationConfidence: 99
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
