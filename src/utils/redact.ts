import { SECRET_PATTERNS } from '../data/secret-patterns.js';

// Structural redaction for anything that leaves the MCP server. Scanners
// interpolate raw args, URLs and env-derived strings into descriptions, and
// a deny-list of vendor token formats cannot cover an opaque credential, so
// the control is the shape of the text, with the deny-list as a last pass.

const REDACTED = '[REDACTED]';

const URL_RE = /[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\s"'<>`)]+/g;
const SENSITIVE_WORD = '(?:key|token|secret|auth|passw(?:or)?d|credential|cookie|signature|sig)';
const RUN_RE = /[A-Za-z0-9_\-+/\\=.]{20,}/g;
// Opaque lowercase tokens look like words to segmentSafe, so any long
// lowercase-alphanumeric run is redacted outright. Over-redaction is fine;
// normal package names are far shorter.
const LOWER_TOKEN_RE = /\b[a-z0-9]{24,}\b/g;

// Drops userinfo, query string and fragment. The path is kept for context;
// long opaque path segments are caught by the run pass.
export function sanitizeUrl(url: string): string {
  const m = url.match(/^([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)([^/?#]*)([^?#]*)(\?[^#]*)?(#.*)?$/);
  if (!m) return url;
  const host = m[2].includes('@') ? m[2].slice(m[2].lastIndexOf('@') + 1) : m[2];
  return `${m[1]}${host}${m[3]}${m[4] ? `?${REDACTED}` : ''}`;
}

const partSafe = (p: string): boolean =>
  /^[a-z]{1,24}$/.test(p) || /^[a-z0-9]{1,12}$/.test(p);

// Lowercase words, short hostnames and dotted/dashed package names pass.
// Env var names (GITHUB_PERSONAL_ACCESS_TOKEN) are identifiers, not values.
function segmentSafe(seg: string): boolean {
  if (/^[A-Z][A-Z0-9]{0,11}(?:_[A-Z0-9]{1,12})+$/.test(seg)) return true;
  return seg.split(/[-_.]/).every(partSafe);
}

function redactRun(run: string): string {
  // Windows paths (C:\Users\...) split on the backslash and read like paths.
  const pathLike = /^(?:\/|\.\.?\/)/.test(run) || run.includes('\\');
  const parts = run.split(/([\\/])/);
  if (pathLike) {
    return parts.map(p => (p.length >= 20 && !segmentSafe(p) ? REDACTED : p)).join('');
  }
  return parts.filter((_, i) => i % 2 === 0).every(segmentSafe) ? run : REDACTED;
}

const DENY_REGEXES = SECRET_PATTERNS.map(p =>
  new RegExp(p.regex.source, p.regex.flags.includes('g') ? p.regex.flags : p.regex.flags + 'g'));

export function redactText(input: string): string {
  let s = input;

  s = s.replace(URL_RE, u => sanitizeUrl(u));

  // Authorization-style headers and bare Bearer/Basic credentials.
  s = s.replace(/\b(Proxy-Authorization|Authorization)\b\s*[:=]\s*(?:(?:Bearer|Basic|Token|Digest)\s+)?[^\s"',;]+/gi, `$1: ${REDACTED}`);
  s = s.replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{6,}/g, `$1 ${REDACTED}`);
  // Header-shaped pairs such as "X-Api-Key: value".
  s = s.replace(new RegExp(`\\b([A-Za-z][\\w-]*${SENSITIVE_WORD}[\\w-]*)\\s*:\\s*(?!\\[REDACTED\\])[^\\s"',;]+`, 'gi'), `$1: ${REDACTED}`);
  // JSON pairs whose key names a credential.
  s = s.replace(new RegExp(`"([^"\\n]*${SENSITIVE_WORD}[^"\\n]*)"\\s*:\\s*"[^"]*"`, 'gi'), `"$1":"${REDACTED}"`);
  // key=value and --flag=value, quoted or bare.
  s = s.replace(/(?<![\w-])(--?[A-Za-z][\w.-]*|[A-Za-z_][\w.-]*)=("[^"]*"|'[^']*'|[^\s,;]+)/g, (full, k: string, v: string) =>
    v.includes(REDACTED) ? full : `${k}=${REDACTED}`);

  s = s.replace(RUN_RE, redactRun);
  s = s.replace(LOWER_TOKEN_RE, REDACTED);

  for (const re of DENY_REGEXES) s = s.replace(re, REDACTED);
  return s;
}

// Applies redactText to every string in a JSON-like value, keys excluded.
export function redactDeep<T>(value: T): T {
  if (typeof value === 'string') return redactText(value) as unknown as T;
  if (Array.isArray(value)) return value.map(redactDeep) as unknown as T;
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = redactDeep(v);
    return out as T;
  }
  return value;
}
