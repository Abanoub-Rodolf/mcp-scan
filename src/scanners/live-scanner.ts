import { Finding } from '../types/scan-result.js';
import { Severity } from '../types/severity.js';
import { LiveCatalog } from '../utils/mcp-client.js';
import { findEncodedInstruction } from '../utils/encoded-text.js';

// Checks on what a running server actually sends the model. Unlike the config
// scanners, these see the real tool, prompt and resource text, and they judge
// each item on its own so a finding names the tool that carries the payload.
// Patterns are phrased to need an instruction aimed at the model: a bare
// word like 'run' or 'system' in a schema is ordinary vocabulary.

const MAX_SCAN = 20000;      // chars of one item inspected; more is itself a finding
const OVERSIZE = 8000;       // well past the longest honest descriptions seen (about 6k)

type Item = { kind: 'tool' | 'prompt' | 'resource' | 'instructions'; name: string; text: string; params: Array<{ name: string; text: string }>; capped?: boolean };

const WALK_DEPTH = 32;
const WALK_WIDTH = 5000;
// Set when a walk dropped something: the caller reports it instead of passing silently.
let walkCapped = false;

// Text from the server lands in findings, which reach a terminal: no control
// or escape characters survive.
export const clean = (s: string) => s.replace(/[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u2028\u2029\u202A-\u202E\u2066-\u2069]/g, '');
// One line, for names and labels: no newlines or tabs either.
export const oneLine = (s: string) => clean(s).replace(/\s+/g, ' ').trim();
const clip = (s: string, n = 80) => {
  const one = clean(s).replace(/\s+/g, ' ').trim();
  return one.length > n ? one.slice(0, n - 3) + '...' : one;
};

// JSON Schema vocabulary. A key outside this set is a name somebody chose (a
// property, a $defs entry) and the model reads it, so it is scanned like text.
const KEYWORDS = new Set(['type', 'description', 'properties', 'items', 'required', 'enum', 'default', 'additionalProperties', 'title', 'format', 'minimum', 'maximum', 'minLength', 'maxLength', 'pattern', 'oneOf', 'anyOf', 'allOf', 'not', 'const', 'examples', 'nullable', 'deprecated', 'readOnly', 'writeOnly', 'uniqueItems', 'minItems', 'maxItems', 'patternProperties', '$ref', '$id', '$comment', '$schema', '$defs', 'definitions', 'annotations', 'exclusiveMinimum', 'exclusiveMaximum', 'multipleOf', 'if', 'then', 'else', 'contains', 'propertyNames', 'unevaluatedProperties', 'additionalItems', 'dependentRequired', 'dependentSchemas', 'content', 'mimeType', 'name', 'uri', 'arguments', 'inputSchema', 'outputSchema', 'readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint']);
const TYPE_NAMES = new Set(['string', 'number', 'integer', 'boolean', 'object', 'array', 'null']);

// Every string the model can read: description, titles, and nested schema
// descriptions, enums, defaults, examples, and the names used as keys.
function strings(value: unknown, out: string[], depth = 0): void {
  if (value == null) return;
  if (depth > WALK_DEPTH) { walkCapped = true; return; }
  if (typeof value === 'string') { out.push(value); return; }
  if (Array.isArray(value)) {
    if (value.length > WALK_WIDTH) walkCapped = true;
    for (const v of value.slice(0, WALK_WIDTH)) strings(v, out, depth + 1);
    return;
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length > WALK_WIDTH) walkCapped = true;
    for (const [k, v] of entries.slice(0, WALK_WIDTH)) {
      if (!KEYWORDS.has(k)) out.push(k);
      // 'type' / '$schema' hold a plain type name or URL in honest schemas; anything else is text.
      if ((k === 'type' || k === '$schema') && typeof v === 'string' && (TYPE_NAMES.has(v) || /^https?:\/\/json-schema\.org\//.test(v))) continue;
      if (k === 'type' && Array.isArray(v) && v.every(x => typeof x === 'string' && TYPE_NAMES.has(x))) continue;
      strings(v, out, depth + 1);
    }
  }
}

function paramsOf(schema: unknown): Array<{ name: string; text: string }> {
  const props = (schema as { properties?: Record<string, unknown> } | undefined)?.properties;
  if (!props || typeof props !== 'object') return [];
  const all = Object.entries(props);
  if (all.length > WALK_WIDTH) walkCapped = true;
  return all.slice(0, WALK_WIDTH).map(([name, def]) => {
    const parts: string[] = [];
    strings(def, parts);
    return { name, text: parts.join('\n') };
  });
}

export function itemsOf(c: LiveCatalog): Item[] {
  const items: Item[] = [];
  walkCapped = false;
  const text = (o: Record<string, unknown>, skip: string[]) => {
    const parts: string[] = [];
    for (const [k, v] of Object.entries(o)) if (!skip.includes(k)) strings(v, parts);
    return parts.join('\n');
  };
  // Schemas are scanned whole (every nested description, enum and default), not
  // only the top-level description: that is where full-schema poisoning hides.
  for (const t of c.tools) items.push({ kind: 'tool', name: String(t.name), text: text(t, ['name', '_meta']) + '\n' + paramsOf(t.inputSchema).map(p => p.name).join('\n'), params: paramsOf(t.inputSchema) });
  for (const p of c.prompts) items.push({ kind: 'prompt', name: String(p.name), text: text(p, ['name', '_meta']), params: [] });
  for (const r of c.resources) items.push({ kind: 'resource', name: String(r.name ?? r.uri), text: text(r, ['name', 'uri', '_meta']), params: [] });
  for (const r of c.resourceTemplates) items.push({ kind: 'resource', name: String(r.name ?? r.uriTemplate), text: text(r, ['name', 'uriTemplate', '_meta']), params: [] });
  if (c.instructions) items.push({ kind: 'instructions', name: 'server instructions', text: c.instructions, params: [] });
  return items;
}

// Locations no tool description has a reason to send the model to.
const STRONG_PATH = /(?:~\/\.(?:ssh|aws|gnupg|kube|docker)\b|\/\.ssh\/|\.aws\/credentials|\bid_(?:rsa|ed25519|ecdsa)\b|\bmcp\.json\b|claude_desktop_config|\.cursor\/mcp|\/etc\/(?:passwd|shadow)|\bwallet\.dat\b)/i;
// Ordinary words in many honest tools (a dotenv loader, a keychain helper):
// only a finding when paired with a directive or a transfer.
const WEAK_PATH = /(?:\.env\b|\.npmrc|\.netrc|\bcredentials?\.json\b|\bkeychain\b)/i;
// "Never read ~/.ssh/id_rsa" is documentation, not an instruction. Two words or more
// between the negation and the verb ("do not forget to read") stay flagged.
const NEGATED = /\b(?:never|(?:do|does|must|should|will|can)(?:\s+not|n't)|won't)\s+(?:\w+\s+){0,1}(?:read|open|access|cat|send|upload|copy|print|load|fetch|include)\b[^.\n]{0,40}$/i;
const READ_VERB = /\b(?:read_?file|call|invoke|read|open|cat|load|access|fetch|include|send|upload|copy|print|attach|append|pass|provide|supply|add|embed|post|forward|submit|paste)\b[^.\n]{0,60}$/i;
const DIRECTIVE = /\b(?:before (?:using|calling|running)|prior to (?:using|calling)|you must|you should|first,? (?:you )?(?:must|should))\b/i;
// Hiding the tool's own behavior from the user. "Never show API keys to the user" is
// a safety rule about data, not an instruction to conceal the call, so the object
// has to be the action itself.
const CONCEAL = [
  /\b(?:do not|don't|never)\s+(?:mention|tell|inform|reveal|disclose|let)\b[^.\n]{0,40}\b(?:user|human)\b[^.\n]{0,40}\b(?:this|that you|these|your (?:action|read|call)|about (?:this|it|the (?:file|tool|call|request|instruction)))/i,
  /\b(?:do not|don't|never)\s+(?:mention|tell|reveal|disclose)\s+(?:this|that|it|these)\b[^.\n]{0,30}\b(?:user|human|anyone)\b/i,
  /\bwithout\s+(?:telling|informing|notifying|alerting)\s+the\s+(?:user|human)\b/i,
  /\bkeep\s+(?:this|it|that)\s+(?:secret|hidden|confidential)\b/i,
  /\b(?:user|human)\s+(?:must not|should not|cannot|can't)\s+(?:know|see|be told)\b/i,
];
const INJECTION: Array<[RegExp, string]> = [
  [/\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|rules?|prompts?)\b/i, 'ignore previous instructions'],
  [/\bdisregard\s+(?:all\s+)?(?:previous|prior|your|the)\b[^.\n]{0,30}\b(?:instructions?|rules?|guidelines?)\b/i, 'disregard instructions'],
  [/\boverride\s+(?:your|the)\s+(?:instructions?|rules?|system prompt|safety)\b/i, 'override instructions'],
  [/\byou\s+are\s+now\s+(?:an?|the|my)\s+(?:\w+\s+)?(?:assistant|ai|dan|unrestricted|jailbroken|uncensored|evil|developer|admin|root|different|new)\b/i, 'you are now'],
  [/\bnew\s+(?:system\s+)?instructions?\s*:\s*(?:you|ignore|always|never|do\b|from now|forget|disregard)/i, 'new instructions'],
  [/\b(?:reveal|print|output|repeat)\s+(?:your|the)\s+system\s+prompt\b/i, 'reveal system prompt'],
  [/\b(?:disable|bypass|turn off)\s+(?:your\s+)?(?:safety|guardrails?|content (?:filter|policy))\b/i, 'bypass safety'],
];
const FAKE_TAG = /<\s*\/?\s*(?:important|system|instructions?|secret|hidden|admin|override)\s*>|\[\s*(?:system|important|admin)\s*\]/i;
const SHADOW: Array<[RegExp, string]> = [
  [/\b(?:when|whenever|if)\b[^.\n]{0,80}\b(?:is|are)\s+(?:available|present|loaded|installed|connected)\b[^.\n]{0,120}\b(?:must|always|never)\b/i, 'conditions on other tools being present'],
  [/\b(?:instead of|rather than|in place of)\s+(?:the\s+)?`?[\w-]+`?\s+tool\b/i, 'replaces another tool'],
  [/\b(?:this tool|it)\s+(?:has|takes)\s+(?:priority|precedence)\b/i, 'claims priority over other tools'],
  [/\b(?:all|any|every)\s+(?:other\s+)?(?:email|message|file|request)s?\b[^.\n]{0,40}\b(?:must|should)\s+(?:be\s+)?(?:sent|routed|forwarded|redirected)\s+to\b/i, 'redirects other tools\' output'],
];
// The target must be a URL or the classic smuggling parameter: "pass the id as the id parameter" is ordinary.
// Data that is private by nature, sent to a URL or the classic smuggling parameter: a finding alone.
const EXFIL = /\b(?:send|forward|post|upload|transmit|exfiltrate|email|include|append|attach|pass)\b[^.\n]{0,60}\b(?:conversation|chat history|history|transcript|system prompt|private keys?)\b[^.\n]{0,60}\b(?:to|in|into|as)\b[^.\n]{0,40}(?:https?:\/\/|\bside_?note\b)/i;
// Generic data nouns (files, contents, output) are routine in upload tools: only with an order attached.
const EXFIL_GENERIC = /\b(?:send|forward|post|upload|transmit|exfiltrate|email|include|append|attach|pass)\b[^.\n]{0,60}\b(?:credentials?|secrets?|passwords?|api keys?|tokens?|contents?|files?|data|everything|outputs?|messages?)\b[^.\n]{0,60}\b(?:to|in|into|as)\b[^.\n]{0,40}(?:https?:\/\/|\bside_?note\b)/i;
// The same thing aimed at one of the tool's own parameters.
// The smuggling parameter itself is the tell: nothing honest is passed through a "sidenote".
const EXFIL_SIDE = /\b(?:send|forward|post|upload|append|attach|pass|include|add|put|write)\b[^.\n]{0,60}\b(?:credentials?|secrets?|passwords?|api[_ ]?keys?|tokens?|keys?|contents?)\b[^.\n]{0,60}\b(?:to|in|into|as)\b[^.\n]{0,30}side_?note/i;
const EXFIL_PARAM = /\b(?:include|pass|put|append|attach|add|provide|supply)\b[^.\n]{0,40}\b(?:conversation|chat history|history|transcript|system prompt)\b[^.\n]{0,60}\b(?:argument|parameter|field)\b/i;
const CHANNEL_NAME = /^(?:side_?note|notes?|memo|context|extra|metadata|feedback|reason|explanation|comment|remarks?|thoughts?|scratchpad|debug|trace|info)$/i;
const CHANNEL_DESC = /\b(?:conversation|chat history|transcript|system prompt|private keys?|credentials?|secrets?|api keys?|passwords?|file contents?|contents of)\b/i;
const TAG_CHARS = /[\u{E0000}-\u{E007F}]/u;
// ZWJ/ZWNJ and the soft hyphen are ordinary in emoji and Indic/Persian text: not flagged.
const VARIATION_SUPP = /[\u{E0100}-\u{E01EF}]/u; // variation selectors supplement: smuggling, never emoji
const INVISIBLE = /[\u200B\u2060-\u2064\u202A-\u202E\u2066-\u2069\u180E\uFEFF]/;
// Padding that pushes text out of view: a long run on one line, or a very long
// blank stretch. Template-literal indentation (newline, 24 spaces, newline) is neither.
const PADDING = /[ \t\u00A0]{80,}|[ \t\r\n\u00A0]{200,}/g;

function decodeTags(s: string): string {
  let out = '';
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if (cp >= 0xE0020 && cp <= 0xE007E) out += String.fromCharCode(cp - 0xE0000);
  }
  return out;
}

function checkText(who: string, text: string, rawPush: (sev: Severity, id: string, desc: string, fix: string) => void) {
  let highs = 0;
  const push: typeof rawPush = (sev, ...rest) => { if (sev === 'HIGH') highs++; rawPush(sev, ...rest); };
  const body = text.length > MAX_SCAN ? text.slice(0, MAX_SCAN) : text;
  if (text.length > MAX_SCAN) {
    push('MEDIUM', 'live-oversize-description', `${who} carries ${text.length} characters of text; only the first ${MAX_SCAN} were inspected.`, 'Text this long is not documentation. Read it in full before trusting the server.');
  } else if (text.length > OVERSIZE) {
    push('LOW', 'live-oversize-description', `${who} carries ${text.length} characters of text, far more than a description needs.`, 'Read it in full: long descriptions are where injected instructions hide.');
  }

  // Linear character-class checks run on the whole text, not just the clipped part.
  // Subdivision flag emoji (England, Scotland, Wales, US states) are a black flag plus tag letters; short
  // codes are not payloads. Anything longer, or tags outside that shape, still counts.
  const unflagged = text.replace(/\u{1F3F4}([\u{E0061}-\u{E007A}\u{E0030}-\u{E0039}]{2,6})\u{E007F}/gu, '');
  if (TAG_CHARS.test(unflagged) || VARIATION_SUPP.test(text)) {
    const hidden = decodeTags(unflagged);
    push('HIGH', 'live-hidden-text', `${who} contains invisible Unicode tag characters${hidden ? ` that spell: "${clip(hidden)}"` : ''}.`, 'Text the user cannot see but the model can read is an attack, not formatting. Do not use this server.');
  } else if (INVISIBLE.test(text)) {
    push('HIGH', 'live-hidden-text', `${who} contains zero-width or direction-control characters.`, 'Remove them or stop using the server: they hide text from the person reviewing the tool.');
  }

  PADDING.lastIndex = 0;
  let pad: RegExpExecArray | null;
  while ((pad = PADDING.exec(body)) !== null) {
    const after = body.slice(pad.index + pad[0].length, pad.index + pad[0].length + 400);
    if (/\b(?:ignore|must|should|do not|don't|secret|send|read|instruction)/i.test(after)) {
      push('HIGH', 'live-hidden-text', `${who} pushes instructions off-screen behind ${pad[0].length} characters of whitespace: "${clip(after.trim())}".`, 'Whitespace padding hides text from a reviewer. Do not use this server.');
      break;
    }
  }

  for (const rx of CONCEAL) {
    const m = rx.exec(body);
    if (m) { push('HIGH', 'live-tool-poisoning', `${who} tells the model to hide something from the user: "${clip(m[0])}".`, 'A legitimate tool never needs the model to conceal its behavior from the user.'); break; }
  }
  for (const [rx, label] of INJECTION) {
    if (rx.test(body)) push('HIGH', 'live-tool-poisoning', `${who} contains an instruction-override phrase (${label}).`, 'Review the full text of this tool; instruction overrides do not belong in tool metadata.');
  }
  const directiveNear = (m: RegExpExecArray) => DIRECTIVE.test(body.slice(Math.max(0, m.index - 100), m.index + 100));
  // The data-moving rules fire only when the order sits next to the data, not anywhere in the text.
  const concealed = CONCEAL.some(rx => rx.test(body));
  // Ordinary phrases ("you must provide a path") are not an order to move data: the order has to be the
  // attack's own ("before using this tool", "first") or come with concealment.
  const BEFORE = /\b(?:before|prior to) (?:using|calling|running|invoking)\b/i;
  const exfilGeneric = (() => { const m = EXFIL_GENERIC.exec(body); return !!m && (concealed || BEFORE.test(body.slice(Math.max(0, m.index - 100), m.index + 100))); })();
  const exfilParam = (() => { const m = EXFIL_PARAM.exec(body); return !!m && directiveNear(m); })();
  const strong = STRONG_PATH.exec(body);
  const weak = WEAK_PATH.exec(body);
  const before = (m: RegExpExecArray) => body.slice(Math.max(0, m.index - 80), m.index);
  // A prohibition only counts when nothing after the path turns it around ("never read X, instead ...").
  const negated = (m: RegExpExecArray) => NEGATED.test(before(m)) && !/\b(?:instead|but|then|except|unless|however)\b/i.test(body.slice(m.index, m.index + 80));
  const near = (m: RegExpExecArray) => READ_VERB.test(before(m)) && !negated(m);
  if (strong && (near(strong) || EXFIL.test(body))) {
    // Reading a private location is HIGH once an order, a transfer or concealment comes with it;
    // alone it is how ssh and config tools describe themselves.
    const sev: Severity = EXFIL.test(body) || exfilGeneric || directiveNear(strong) || concealed ? 'HIGH' : 'MEDIUM';
    push(sev, 'live-tool-poisoning', `${who} directs the model to a sensitive location (${clip(strong[0])}).`, 'Tool descriptions have no reason to reference SSH keys, cloud credentials or other tools\' config. Review it; remove the server if it is not meant to.');
  } else if (weak && (directiveNear(weak) || EXFIL.test(body)) && near(weak)) {
    push('HIGH', 'live-tool-poisoning', `${who} directs the model to read ${clip(weak[0])} and act on it.`, 'Review what the instruction does with that file.');
  } else if (EXFIL.test(body) || EXFIL_SIDE.test(body) || exfilGeneric || exfilParam) {
    push('HIGH', 'live-tool-poisoning', `${who} tells the model to move data into a parameter or URL: "${clip((EXFIL.exec(body) ?? EXFIL_SIDE.exec(body) ?? EXFIL_GENERIC.exec(body) ?? EXFIL_PARAM.exec(body))![0])}".`, 'Review what data the instruction moves and where it goes.');
  }
  for (const [rx, label] of SHADOW) {
    if (rx.test(body)) push('MEDIUM', 'live-tool-shadowing', `${who} tries to steer how other tools behave (${label}).`, 'A tool that rewrites how the model uses other tools is the shadowing attack. Review before trusting.');
  }
  if (findEncodedInstruction(body).length > 0) {
    push('HIGH', 'live-tool-poisoning', `${who} contains a long encoded string that decodes to readable text.`, 'Decode and review it; encoded blobs in tool text hide instructions from reviewers.');
  }

  // <IMPORTANT> is the canonical poisoning wrapper and honest tools do not use it. Other
  // markup (<system>, [Admin]) is ordinary prompt structure unless something else here is already wrong.
  const tag = FAKE_TAG.exec(body);
  if (tag && (/important/i.test(tag[0]) || highs > 0)) {
    push('HIGH', 'live-tool-poisoning', `${who} uses a fake ${tag[0]} marker to address the model.`, 'Tool metadata has no authority to issue system-level instructions. Review the full text.');
  }
}

const BUDGET = 4 * 1024 * 1024; // chars of item text analyzed per server

export function scanLive(catalog: LiveCatalog): Finding[] {
  const findings: Finding[] = [];
  const items = itemsOf(catalog);
  if (walkCapped) findings.push({ id: 'live-incomplete', severity: 'MEDIUM', description: 'A tool schema is wider or deeper than the scan walks (more than 5000 entries or 32 levels), so part of it was not checked.', fixRecommendation: 'Schemas this large or nested are not typical. Review the server by hand.' });
  let spent = 0;
  const names = new Set<string>();
  for (const t of catalog.tools) {
    const n = String(t.name);
    if (names.has(n)) findings.push({ id: 'live-tool-shadowing', severity: 'MEDIUM', description: `Tool '${oneLine(n).slice(0, 80)}' is listed twice by the same server. Only one definition can be baselined, so a swap between them would go unseen.`, fixRecommendation: 'Duplicate names in one catalog are a bug or an attempt to hide a definition. Review both.' });
    names.add(n);
  }
  const toolNames = catalog.tools.map(t => String(t.name));
  const seen = new Set<string>();

  for (const item of items) {
    spent += item.text.length;
    if (spent > BUDGET) {
      findings.push({ id: 'live-incomplete', severity: 'MEDIUM', description: 'The server serves more tool text than the scan analyzes (4 MB); the rest was not checked.', fixRecommendation: 'Review this server by hand.' });
      break;
    }
    const who = item.kind === 'instructions' ? 'The server instructions' : `${item.kind[0].toUpperCase()}${item.kind.slice(1)} '${oneLine(item.name).slice(0, 80)}'`;
    const push = (severity: Severity, id: string, description: string, fixRecommendation: string) => {
      const key = `${id}|${description}`;
      if (seen.has(key)) return;
      seen.add(key);
      findings.push({ id, severity, description, fixRecommendation });
    };

    checkText(who, [item.name, item.text].join('\n'), push);

    // Cross-reference: a description that names a sibling tool and gives it an order.
    // Bounded: clipped text, a cheap substring test before any regex, first 200 siblings.
    if (item.kind === 'tool') {
      const hay = item.text.slice(0, MAX_SCAN);
      const lower = hay.toLowerCase();
      for (const other of toolNames.slice(0, 200)) {
        if (other === item.name || other.length < 4 || !lower.includes(other.toLowerCase())) continue;
        const e = other.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        // 'search' or 'read' alone is plain vocabulary; a compound name, a quoted
        // name or "the X tool" is a reference.
        const ref = /^[a-z0-9]+$/i.test(other) ? `(?:[\`"']${e}[\`"']|\\b${e}\\s+tool\\b)` : `\\b${e}\\b`;
        const rx = new RegExp(`${ref}[^.\\n]{0,60}\\b(?:must|should|always)\\b|\\b(?:must|should|always|then|first)\\b[^.\\n]{0,60}${ref}`, 'i');
        const hit = rx.exec(hay);
        // Naming a sibling is normal ("prefer this over 'click'"); redirecting it is not.
        if (hit && /\b(?:instead|replace|override|ignore|redirect|route|forward|send|rather than|(?:before|after) (?:calling|using))\b/i.test(hit[0])) {
          push('MEDIUM', 'live-tool-shadowing', `${who} gives instructions about another tool of this server ('${oneLine(other).slice(0, 80)}').`, 'Cross-tool directives in a description are how one tool hijacks another. Review them.');
          break;
        }
      }
      // A free-text parameter whose description asks for sensitive content is a side channel.
      for (const p of item.params) {
        if (CHANNEL_NAME.test(p.name) && CHANNEL_DESC.test(p.text)) {
          push('HIGH', 'live-tool-poisoning', `${who} has a free-text parameter '${p.name}' described as taking sensitive content: "${clip(p.text)}".`, 'A side-channel parameter lets a poisoned description smuggle data out through a normal call.');
        }
      }
    }
  }
  return findings;
}

// The same tool name served by two different servers: the model picks one by
// description, which is the cross-server shadowing setup.
export function crossServerShadows(catalogs: Array<{ id: string; name: string; launch: string; tools: string[] }>): Map<string, Finding[]> {
  const owners = new Map<string, Array<{ id: string; name: string; launch: string }>>();
  for (const c of catalogs) for (const t of new Set(c.tools)) owners.set(t, [...(owners.get(t) ?? []), { id: c.id, name: c.name, launch: c.launch }]);
  const out = new Map<string, Finding[]>();
  for (const [tool, servers] of owners) {
    // Two entries of the same package (different env, different tenant) share names by design.
    const distinct = servers.filter(x => servers.some(y => y.launch !== x.launch));
    if (distinct.length < 1 || new Set(servers.map(x => x.launch)).size < 2) continue;
    for (const s of servers) {
      const others = servers.filter(x => x.launch !== s.launch).map(x => `'${oneLine(x.name).slice(0, 80)}'`).join(', ');
      if (!others) continue;
      out.set(s.id, [...(out.get(s.id) ?? []), {
        id: 'live-tool-shadowing',
        severity: 'MEDIUM',
        description: `Tool '${oneLine(tool).slice(0, 80)}' on server '${oneLine(s.name).slice(0, 80)}' has the same name as a tool on ${others}. The model chooses between them by description.`,
        fixRecommendation: 'Duplicate tool names across servers let one server shadow another. Remove one server or confirm both are yours.',
      }]);
    }
  }
  return out;
}
