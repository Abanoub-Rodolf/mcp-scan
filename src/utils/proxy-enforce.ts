import { AuditChain, macOf } from './audit-chain.js';
import { stable } from './live-snapshot.js';

// Decides which `tools/call` requests the proxy lets through, and records every
// decision in the hash-chained log. Names match exactly, or by a trailing `*`.
// A deny entry wins over an allow entry; with an allow list, anything not on it is refused.

export interface EnforceOptions { allow?: string[]; deny?: string[] }

const matches = (list: string[], name: string) => list.some(p => (p.endsWith('*') ? name.startsWith(p.slice(0, -1)) : p === name));
// A server may fold case or Unicode forms when it looks a tool up, so a deny rule is tested against those forms too.
const fold = (n: string) => n.normalize('NFKC').replace(/[\p{Cf}\p{Cc}]/gu, '').trim().toLowerCase();
const denied = (list: string[], name: string) => matches(list, name) || matches(list.map(fold), fold(name));
// Two parsers can read a message with look-alike keys differently ("name" and "NAME", "Method"), so such a message is refused outright.
const ambiguous = (o: unknown, exact: string[]): boolean => {
  if (!o || typeof o !== 'object' || Array.isArray(o)) return false;
  const keys = Object.keys(o);
  if (new Set(keys.map(k => k.toLowerCase())).size !== keys.length) return true;
  return keys.some(k => !exact.includes(k) && exact.includes(k.toLowerCase()));
};

export class Enforcer {
  constructor(private opts: EnforceOptions, private chain: AuditChain) {}

  decide(tool: string): { allowed: boolean; reason: string } {
    if (this.opts.deny && denied(this.opts.deny, tool)) return { allowed: false, reason: 'on the deny list' };
    if (this.opts.allow && !matches(this.opts.allow, tool)) return { allowed: false, reason: 'not on the allow list' };
    return { allowed: true, reason: this.opts.allow ? 'on the allow list' : 'no rule against it' };
  }

  // Takes one parsed client message (or batch). Returns what to forward and
  // the refused requests, each as the id the client used and the reason.
  screen(json: unknown): { forward: unknown | null; refused: { id: string | number; tool: string; reason: string }[] } {
    const batch = Array.isArray(json);
    const kept: unknown[] = [];
    const refused: { id: string | number; tool: string; reason: string }[] = [];
    for (const m of (batch ? json as unknown[] : [json])) {
      const msg = m as { method?: unknown; id?: unknown; params?: { name?: unknown; arguments?: unknown } } | null;
      const bad = ambiguous(msg, ['method', 'params', 'id', 'jsonrpc']) || ambiguous(msg?.params, ['name', 'arguments', '_meta']);
      if (!msg || typeof msg !== 'object' || (msg.method !== 'tools/call' && !bad)) { kept.push(m); continue; }
      // a name that is not a string cannot match any rule, so it is refused rather than guessed at
      const tool = typeof msg.params?.name === 'string' ? msg.params.name : '';
      const d = bad ? { allowed: false, reason: 'refused: the message has look-alike keys that parsers may read differently' } : tool ? this.decide(tool) : { allowed: false, reason: 'the call has no tool name' };
      let argKeys: string[] = [];
      let argsSha = '';
      try {
        const a = msg.params?.arguments;
        if (a && typeof a === 'object') argKeys = Object.keys(a as object).slice(0, 50).map(k => k.slice(0, 64));
        argsSha = macOf(stable(a ?? null), true);
      } catch (_e) { argsSha = 'unhashable'; }
      this.chain.append({ type: 'tools/call', tool: tool.slice(0, 200), id: typeof msg.id === 'string' ? msg.id.slice(0, 64) : typeof msg.id === 'number' ? msg.id : null, decision: d.allowed ? 'allowed' : 'refused', reason: d.reason, argKeys, argsHmac: argsSha });
      if (d.allowed) kept.push(m);
      else if (typeof msg.id === 'string' || typeof msg.id === 'number') refused.push({ id: msg.id, tool, reason: d.reason });
    }
    if (kept.length === 0) return { forward: null, refused };
    return { forward: batch ? kept : kept[0], refused };
  }
}
