import { PII_PATTERNS } from '../data/pii-patterns.js';

export interface PrivacyOptions {
  enabledPatterns?: string[]; // Names of patterns to enable. If empty/undefined, all are enabled.
  disabledPatterns?: string[]; // Names of patterns to explicitly disable.
}

// Patterns are stored without the /g flag so detectors never hit the
// stateful lastIndex trap; masking needs a global replace, so compile that
// once per pattern. String.replace resets lastIndex, so reuse is safe.
const COMPILED = PII_PATTERNS.map(p => ({
  name: p.name,
  mask: p.mask,
  regex: new RegExp(p.regex.source, p.regex.flags.replace('g', '') + 'g'),
}));

// The option filter is the same for every string in a message, so resolve
// it once per distinct option set.
const ACTIVE = new Map<string, typeof COMPILED>();
function activePatterns(options?: PrivacyOptions): typeof COMPILED {
  if (!options) return COMPILED;
  const key = JSON.stringify([options.enabledPatterns ?? null, options.disabledPatterns ?? null]);
  let list = ACTIVE.get(key);
  if (!list) {
    const { enabledPatterns, disabledPatterns } = options;
    list = COMPILED.filter(p =>
      !(enabledPatterns && enabledPatterns.length > 0 && !enabledPatterns.includes(p.name)) &&
      !(disabledPatterns && disabledPatterns.includes(p.name)));
    ACTIVE.set(key, list);
  }
  return list;
}

/**
 * Masks PII in a given string.
 */
export function maskString(str: string, options?: PrivacyOptions): string {
  if (typeof str !== 'string') return str;

  let maskedStr = str;
  for (const pattern of activePatterns(options)) {
    maskedStr = maskedStr.replace(pattern.regex, pattern.mask);
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
 * The `id` of a top-level JSON-RPC message (each element's, for a batch) is a correlation
 * token and is passed through as is: masking it would stop replies matching.
 */
export function maskPii(data: any, options?: PrivacyOptions, deepClone = false, depth = 0): any {
  if (deepClone && data != null && typeof data === 'object') {
    data = JSON.parse(JSON.stringify(data));
  }
  return walk(data, options, depth, depth === 0);
}

function walk(data: any, options: PrivacyOptions | undefined, depth: number, envelope: boolean): any {
  // Fail closed: past the limit we can't vouch for what is below, so the
  // caller must drop the message rather than forward it unmasked.
  if (depth > MAX_MASK_DEPTH) throw new Error(`privacy masking depth limit (${MAX_MASK_DEPTH}) exceeded`);
  if (data == null) return data;

  if (typeof data === 'string') {
    return maskString(data, options);
  }

  if (Array.isArray(data)) {
    for (let i = 0; i < data.length; i++) {
      // only a top-level batch's direct elements are envelopes
      data[i] = walk(data[i], options, depth + 1, envelope && depth === 0);
    }
    return data;
  }

  if (typeof data === 'object') {
    const keys = Object.keys(data);
    const renamed = keys.map(k => (ENVELOPE_KEYS.has(k) ? k : maskString(k, options)));
    // The id VALUE stays as the sender wrote it (strings and numbers only).
    // Only a real JSON-RPC message qualifies: a bare {"id": ...} is data.
    const isMessage = envelope && data.jsonrpc === '2.0' && ('method' in data || 'result' in data || 'error' in data);
    const keepId = (k: string) => isMessage && k === 'id' && (typeof data[k] === 'string' || typeof data[k] === 'number');
    const value = (k: string) => (keepId(k) ? data[k] : walk(data[k], options, depth + 1, false));
    if (renamed.every((k, i) => k === keys[i])) {
      for (const key of keys) data[key] = value(key);
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
      Object.defineProperty(out, name, { value: value(key), enumerable: true, writable: true, configurable: true });
    });
    return out;
  }

  return data;
}
