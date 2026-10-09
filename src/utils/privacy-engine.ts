import { PII_PATTERNS } from '../data/pii-patterns.js';

export interface PrivacyOptions {
  enabledPatterns?: string[]; // Names of patterns to enable. If empty/undefined, all are enabled.
  disabledPatterns?: string[]; // Names of patterns to explicitly disable.
}

/**
 * Masks PII in a given string.
 */
export function maskString(str: string, options?: PrivacyOptions): string {
  if (typeof str !== 'string') return str;

  let maskedStr = str;
  for (const pattern of PII_PATTERNS) {
    if (options?.enabledPatterns && options.enabledPatterns.length > 0) {
      if (!options.enabledPatterns.includes(pattern.name)) continue;
    }
    if (options?.disabledPatterns && options.disabledPatterns.includes(pattern.name)) {
      continue;
    }

    // Patterns are stored without the /g flag so detectors never hit the
    // stateful lastIndex trap; masking needs global replace, so clone.
    const globalRegex = new RegExp(pattern.regex.source, pattern.regex.flags.replace('g', '') + 'g');
    maskedStr = maskedStr.replace(globalRegex, pattern.mask);
  }
  return maskedStr;
}

const MAX_MASK_DEPTH = 100;

// Protocol keys are never renamed, whatever the detectors say.
const ENVELOPE_KEYS = new Set(['jsonrpc', 'id', 'method', 'params', 'result', 'error']);

/**
 * Recursively masks PII in an object, array, or string.
 * Pass deepClone=true to avoid mutating the original (useful in scan pipelines).
 * Throws if the data nests deeper than MAX_MASK_DEPTH; it never returns data it did not mask.
 */
export function maskPii(data: any, options?: PrivacyOptions, deepClone = false, depth = 0): any {
  // Fail closed: past the limit we can't vouch for what is below, so the
  // caller must drop the message rather than forward it unmasked.
  if (depth > MAX_MASK_DEPTH) throw new Error(`privacy masking depth limit (${MAX_MASK_DEPTH}) exceeded`);
  if (deepClone && data != null && typeof data === 'object') {
    data = JSON.parse(JSON.stringify(data));
  }
  if (data == null) return data;

  if (typeof data === 'string') {
    return maskString(data, options);
  }

  if (Array.isArray(data)) {
    for (let i = 0; i < data.length; i++) {
      data[i] = maskPii(data[i], options, false, depth + 1);
    }
    return data;
  }

  if (typeof data === 'object') {
    const keys = Object.keys(data);
    const renamed = keys.map(k => (ENVELOPE_KEYS.has(k) ? k : maskString(k, options)));
    if (renamed.every((k, i) => k === keys[i])) {
      for (const key of keys) data[key] = maskPii(data[key], options, false, depth + 1);
      return data;
    }
    // PII used as a key is masked like a value. Two keys can mask to the
    // same text, so later ones get _2, _3... and none is dropped; a literal
    // key that was already safe keeps its name.
    const taken = new Set(keys.filter((k, i) => renamed[i] === k));
    const out: Record<string, unknown> = {};
    keys.forEach((key, i) => {
      let name = renamed[i];
      if (name !== key) {
        const base = name;
        for (let n = 2; taken.has(name); n++) {
          name = base.endsWith(']') ? `${base.slice(0, -1)}_${n}]` : `${base}_${n}`;
        }
        taken.add(name);
      }
      // defineProperty so a key named __proto__ stays a plain entry.
      Object.defineProperty(out, name, { value: maskPii(data[key], options, false, depth + 1), enumerable: true, writable: true, configurable: true });
    });
    return out;
  }

  return data;
}
