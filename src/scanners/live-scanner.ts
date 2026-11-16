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
const OVERSIZE = 4000;       // a description this long is not documentation

type Item = { kind: 'tool' | 'prompt' | 'resource' | 'instructions'; name: string; text: string; params: Array<{ name: string; text: string }> };

const clip = (s: string, n = 80) => {
  const one = s.replace(/\s+/g, ' ').trim();
  return one.length > n ? one.slice(0, n - 3) + '...' : one;
};

// Every string the model can read: description, titles, and nested schema
// descriptions, enums, defaults, examples. Property names are collected apart.
function strings(value: unknown, out: string[], depth = 0): void {
  if (depth > 12 || value == null) return;
  if (typeof value === 'string') { out.push(value); return; }
  if (Array.isArray(value)) { for (const v of value.slice(0, 200)) strings(v, out, depth + 1); return; }
  if (typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>).slice(0, 200)) {
      if (k === 'type' || k === 'required' || k === '$schema') continue;
      strings(v, out, depth + 1);
    }
  }
}

function paramsOf(schema: unknown): Array<{ name: string; text: string }> {
  const props = (schema as { properties?: Record<string, unknown> } | undefined)?.properties;
  if (!props || typeof props !== 'object') return [];
  return Object.entries(props).slice(0, 200).map(([name, def]) => {
    const parts: string[] = [];
    strings(def, parts);
    return { name, text: parts.join('\n') };
  });
}

export function itemsOf(c: LiveCatalog): Item[] {
  const items: Item[] = [];
  const text = (o: Record<string, unknown>, skip: string[]) => {
    const parts: string[] = [];
    for (const [k, v] of Object.entries(o)) if (!skip.includes(k)) strings(v, parts);
    return parts.join('\n');
  };
  for (const t of c.tools) items.push({ kind: 'tool', name: String(t.name), text: text(t, ['name', 'inputSchema', 'outputSchema', '_meta']), params: paramsOf(t.inputSchema) });
  for (const p of c.prompts) items.push({ kind: 'prompt', name: String(p.name), text: text(p, ['name', '_meta']), params: [] });
  for (const r of c.resources) items.push({ kind: 'resource', name: String(r.name ?? r.uri), text: text(r, ['name', 'uri', '_meta']), params: [] });
  for (const r of c.resourceTemplates) items.push({ kind: 'resource', name: String(r.name ?? r.uriTemplate), text: text(r, ['name', 'uriTemplate', '_meta']), params: [] });
  if (c.instructions) items.push({ kind: 'instructions', name: 'server instructions', text: c.instructions, params: [] });
  return items;
}

const SENSITIVE_PATH = /(?:~\/\.(?:ssh|aws|gnupg|kube|docker)\b|\bid_(?:rsa|ed25519|ecdsa)\b|\.env\b|\bmcp\.json\b|claude_desktop_config|\.cursor\/mcp|\/etc\/(?:passwd|shadow)|\.npmrc|\.netrc|\bcredentials?\.json\b|\bkeychain\b|\bwallet\.dat\b)/i;
const DIRECTIVE = /\b(?:before (?:using|calling|running)|prior to (?:using|calling)|you must|you should|always|first,? (?:you )?(?:must|should)?)\b/i;
const CONCEAL = [
  /\b(?:do not|don't|never)\s+(?:mention|tell|reveal|disclose|inform|show|let)\b[^.\n]{0,60}\b(?:user|human|anyone)\b/i,
  /\bwithout\s+(?:telling|informing|notifying|alerting)\s+the\s+user\b/i,
  /\bkeep\s+(?:this|it|that)\s+(?:secret|hidden|confidential)\b/i,
  /\b(?:user|human)\s+(?:must not|should not|cannot|can't)\s+(?:know|see|be told)\b/i,
];
const INJECTION: Array<[RegExp, string]> = [
  [/\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|rules?|prompts?)\b/i, 'ignore previous instructions'],
  [/\bdisregard\s+(?:all\s+)?(?:previous|prior|your|the)\b[^.\n]{0,30}\b(?:instructions?|rules?|guidelines?)\b/i, 'disregard instructions'],
  [/\boverride\s+(?:your|the)\s+(?:instructions?|rules?|system prompt|safety)\b/i, 'override instructions'],
  [/\byou\s+are\s+now\b/i, 'you are now'],
  [/\bnew\s+(?:system\s+)?instructions?\s*:/i, 'new instructions'],
  [/\b(?:reveal|print|output|repeat)\s+(?:your|the)\s+system\s+prompt\b/i, 'reveal system prompt'],
  [/\b(?:disable|bypass|turn off)\s+(?:your\s+)?(?:safety|guardrails?|content (?:filter|policy))\b/i, 'bypass safety'],
];
const FAKE_TAG = /<\s*\/?\s*(?:important|system|instructions?|secret|hidden|admin|override)\s*>|\[\s*(?:system|important|admin)\s*\]/i;
const SHADOW: Array<[RegExp, string]> = [
  [/\b(?:when|whenever|if)\b[^.\n]{0,80}\b(?:is|are)\s+(?:available|present|loaded|installed|connected)\b[^.\n]{0,120}\b(?:must|should|always|never)\b/i, 'conditions on other tools being present'],
  [/\b(?:instead of|rather than|in place of)\s+(?:the\s+)?`?[\w-]+`?\s+tool\b/i, 'replaces another tool'],
  [/\b(?:this tool|it)\s+(?:has|takes)\s+(?:priority|precedence)\b/i, 'claims priority over other tools'],
  [/\b(?:all|any|every)\s+(?:other\s+)?(?:email|message|file|request)s?\b[^.\n]{0,40}\b(?:must|should)\s+(?:be\s+)?(?:sent|routed|forwarded|redirected)\s+to\b/i, 'redirects other tools\' output'],
];
const EXFIL = /\b(?:send|forward|post|upload|transmit|exfiltrate|email|include|append|attach|pass)\b[^.\n]{0,60}\b(?:to|in|into|as)\b[^.\n]{0,40}(?:https?:\/\/|\bsidenote\b|\bparameter\b|\bargument\b)/i;
const CHANNEL_NAME = /^(?:side_?note|notes?|memo|context|extra|metadata|feedback|reason|explanation|comment|remarks?|thoughts?|scratchpad|debug|trace|info)$/i;
const CHANNEL_DESC = /\b(?:contents?|output|history|conversation|transcript|system prompt|private key|credentials?|secrets?|tokens?|api keys?|passwords?)\b/i;
const TAG_CHARS = /[\u{E0000}-\u{E007F}]/u;
const INVISIBLE = /[​-‏‪-‮⁠-⁤⁦-⁩᠎﻿­]/;
const PADDING = /[ \t\r\n ]{50,}/g;

function decodeTags(s: string): string {
  let out = '';
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if (cp >= 0xE0020 && cp <= 0xE007E) out += String.fromCharCode(cp - 0xE0000);
  }
  return out;
}

function checkText(who: string, text: string, push: (sev: Severity, id: string, desc: string, fix: string) => void) {
  const body = text.length > MAX_SCAN ? text.slice(0, MAX_SCAN) : text;
  if (text.length > MAX_SCAN) {
    push('MEDIUM', 'live-oversize-description', `${who} carries ${text.length} characters of text; only the first ${MAX_SCAN} were inspected.`, 'Text this long is not documentation. Read it in full before trusting the server.');
  } else if (text.length > OVERSIZE) {
    push('LOW', 'live-oversize-description', `${who} carries ${text.length} characters of text, far more than a description needs.`, 'Read it in full: long descriptions are where injected instructions hide.');
  }

  if (TAG_CHARS.test(body)) {
    const hidden = decodeTags(body);
    push('HIGH', 'live-hidden-text', `${who} contains invisible Unicode tag characters${hidden ? ` that spell: "${clip(hidden)}"` : ''}.`, 'Text the user cannot see but the model can read is an attack, not formatting. Do not use this server.');
  } else if (INVISIBLE.test(body)) {
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

  const tag = FAKE_TAG.exec(body);
  if (tag) {
    push('HIGH', 'live-tool-poisoning', `${who} uses a fake ${tag[0]} marker to address the model.`, 'Tool metadata has no authority to issue system-level instructions. Review the full text.');
  }
  for (const rx of CONCEAL) {
    const m = rx.exec(body);
    if (m) { push('HIGH', 'live-tool-poisoning', `${who} tells the model to hide something from the user: "${clip(m[0])}".`, 'A legitimate tool never needs the model to conceal its behavior from the user.'); break; }
  }
  for (const [rx, label] of INJECTION) {
    if (rx.test(body)) push('HIGH', 'live-tool-poisoning', `${who} contains an instruction-override phrase (${label}).`, 'Review the full text of this tool; instruction overrides do not belong in tool metadata.');
  }
  const path = SENSITIVE_PATH.exec(body);
  if (path && (DIRECTIVE.test(body) || EXFIL.test(body) || /\b(?:read|open|cat|load|access|fetch|include)\b/i.test(body))) {
    push('HIGH', 'live-tool-poisoning', `${who} directs the model to a sensitive location (${clip(path[0])}).`, 'Tool descriptions have no reason to reference SSH keys, credentials or other tools\' config. Remove the server.');
  } else if (EXFIL.test(body) && DIRECTIVE.test(body)) {
    push('HIGH', 'live-tool-poisoning', `${who} tells the model to move data into a parameter or URL: "${clip(EXFIL.exec(body)![0])}".`, 'Review what data the instruction moves and where it goes.');
  }
  for (const [rx, label] of SHADOW) {
    if (rx.test(body)) push('MEDIUM', 'live-tool-shadowing', `${who} tries to steer how other tools behave (${label}).`, 'A tool that rewrites how the model uses other tools is the shadowing attack. Review before trusting.');
  }
  if (findEncodedInstruction(body).length > 0) {
    push('HIGH', 'live-tool-poisoning', `${who} contains a long encoded string that decodes to readable text.`, 'Decode and review it; encoded blobs in tool text hide instructions from reviewers.');
  }
}

export function scanLive(catalog: LiveCatalog): Finding[] {
  const findings: Finding[] = [];
  const items = itemsOf(catalog);
  const toolNames = catalog.tools.map(t => String(t.name));
  const seen = new Set<string>();

  for (const item of items) {
    const who = item.kind === 'instructions' ? 'The server instructions' : `${item.kind[0].toUpperCase()}${item.kind.slice(1)} '${item.name}'`;
    const push = (severity: Severity, id: string, description: string, fixRecommendation: string) => {
      const key = `${id}|${description}`;
      if (seen.has(key)) return;
      seen.add(key);
      findings.push({ id, severity, description, fixRecommendation });
    };

    checkText(who, [item.name, item.text].join('\n'), push);

    // Cross-reference: a description that names a sibling tool and gives it an order.
    if (item.kind === 'tool') {
      for (const other of toolNames) {
        if (other === item.name || other.length < 4) continue;
        const rx = new RegExp(`\\b${other.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b[^.\\n]{0,60}\\b(?:must|should|always)\\b|\\b(?:must|should|always|then|first)\\b[^.\\n]{0,60}\\b${other.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
        if (rx.test(item.text)) {
          push('MEDIUM', 'live-tool-shadowing', `${who} gives instructions about another tool of this server ('${other}').`, 'Cross-tool directives in a description are how one tool hijacks another. Review them.');
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
export function crossServerShadows(catalogs: Array<{ id: string; name: string; tools: string[] }>): Map<string, Finding[]> {
  const owners = new Map<string, Array<{ id: string; name: string }>>();
  for (const c of catalogs) for (const t of new Set(c.tools)) owners.set(t, [...(owners.get(t) ?? []), { id: c.id, name: c.name }]);
  const out = new Map<string, Finding[]>();
  for (const [tool, servers] of owners) {
    if (servers.length < 2) continue;
    for (const s of servers) {
      const others = servers.filter(x => x.id !== s.id).map(x => `'${x.name}'`).join(', ');
      out.set(s.id, [...(out.get(s.id) ?? []), {
        id: 'live-tool-shadowing',
        severity: 'MEDIUM',
        description: `Tool '${tool}' on server '${s.name}' has the same name as a tool on ${others}. The model chooses between them by description.`,
        fixRecommendation: 'Duplicate tool names across servers let one server shadow another. Remove one server or confirm both are yours.',
      }]);
    }
  }
  return out;
}
