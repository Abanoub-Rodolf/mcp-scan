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

// A token chunked by dashes into 12-char pieces passes segmentSafe, so a long
// digit-heavy piece is treated as a token, not a name.
const tokenLike = (s: string): boolean => s.length >= 24 && (s.match(/[0-9]/g) || []).length >= 6;

function redactRun(run: string): string {
  // Windows paths (C:\Users\...) split on the backslash and read like paths.
  const pathLike = /^(?:\/|\.\.?\/)/.test(run) || run.includes('\\');
  const parts = run.split(/([\\/])/);
  if (pathLike) {
    return parts.map(p => (p.length >= 20 && (!segmentSafe(p) || tokenLike(p)) ? REDACTED : p)).join('');
  }
  const segs = parts.filter((_, i) => i % 2 === 0);
  if (segs.some(tokenLike) || tokenLike(run)) return REDACTED;
  return segs.every(segmentSafe) ? run : REDACTED;
}

const toGlobal = (re: RegExp) => new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
const DENY_REGEXES = SECRET_PATTERNS.map(p => toGlobal(p.regex));
// Context-gated patterns (bare 40-char or UUID shapes) hit ordinary path
// segments, so identifier fields only get the prefix-anchored ones.
const DENY_REGEXES_STRICT = SECRET_PATTERNS.filter(p => !p.keyContext).map(p => toGlobal(p.regex));

// Untrusted configs can carry multi-MB args; the regex passes below bound
// what they see so a hostile config cannot stall the stdio server.
const MAX_REDACT_CHARS = 2048;

// Cut, then drop the trailing partial token: half a credential would dodge
// every pattern and survive into the output.
function bound(input: string): string {
  if (input.length <= MAX_REDACT_CHARS) return input;
  return `${input.slice(0, MAX_REDACT_CHARS).replace(/\S*$/, '')}...`;
}

// Quantifiers are capped so a long token-token-token chain cannot go
// quadratic if MAX_REDACT_CHARS is ever raised.
function structural(input: string): string {
  let s = input.replace(URL_RE, u => sanitizeUrl(u));

  // Authorization-style headers and bare Bearer/Basic credentials.
  s = s.replace(/\b(Proxy-Authorization|Authorization)\b\s*[:=]\s*(?:(?:Bearer|Basic|Token|Digest)\s+)?[^\s"',;]+/gi, `$1: ${REDACTED}`);
  s = s.replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{6,}/g, `$1 ${REDACTED}`);
  // Scheme-less userinfo (user:pass@host.io).
  s = s.replace(/(?<![\w.-])[\w.-]{1,64}:[^\s@/:]{1,128}@(?=[\w-]+\.[a-z]{2,})/gi, `${REDACTED}@`);
  // Header-shaped pairs such as "X-Api-Key: value".
  s = s.replace(new RegExp(`(?<![\\w-])([A-Za-z][\\w-]{0,64}?${SENSITIVE_WORD}[\\w-]{0,64})\\s*:\\s*(?!\\[REDACTED\\])[^\\s"',;]+`, 'gi'), `$1: ${REDACTED}`);
  // JSON pairs whose key names a credential.
  s = s.replace(new RegExp(`"([^"\\n]{0,128}${SENSITIVE_WORD}[^"\\n]{0,128})"\\s*:\\s*"[^"]*"`, 'gi'), `"$1":"${REDACTED}"`);
  // key=value and --flag=value, quoted or bare.
  s = s.replace(/(?<![\w-])(--?[A-Za-z][\w.-]{0,64}|[A-Za-z_][\w.-]{0,64})=("[^"]*"|'[^']*'|[^\s,;]+)/g, (full, k: string, v: string) =>
    v.includes(REDACTED) ? full : `${k}=${REDACTED}`);
  return s;
}

// Paths and names are identifiers the caller feeds back in, so the run and
// lowercase-token passes (which mangle "Application Support/Claude/...") do
// not apply. Everything credential-shaped still does.
export function redactIdentifier(input: string): string {
  let s = structural(bound(input));
  for (const re of DENY_REGEXES_STRICT) s = s.replace(re, REDACTED);
  return s;
}

export function redactText(input: string): string {
  let s = structural(bound(input));
  s = s.replace(RUN_RE, redactRun);
  s = s.replace(LOWER_TOKEN_RE, REDACTED);
  for (const re of DENY_REGEXES) s = s.replace(re, REDACTED);
  return s;
}

// Applies redactText to every string in a JSON-like value, keys excluded.
const IDENTIFIER_KEYS = new Set(['configPath', 'server', 'client']);

export function redactDeep<T>(value: T, key?: string): T {
  if (typeof value === 'string') {
    return (key && IDENTIFIER_KEYS.has(key) ? redactIdentifier(value) : redactText(value)) as unknown as T;
  }
  if (Array.isArray(value)) return value.map(v => redactDeep(v, key)) as unknown as T;
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = redactDeep(v, k);
    return out as T;
  }
  return value;
}
