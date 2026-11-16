import crypto from 'crypto';
import { AuditChain } from './audit-chain.js';
import { stable } from './live-snapshot.js';

// Decides which `tools/call` requests the proxy lets through, and records every
// decision in the hash-chained log. Names match exactly, or by a trailing `*`.
// A deny entry wins over an allow entry; with an allow list, anything not on it is refused.

export interface EnforceOptions { allow?: string[]; deny?: string[] }

const matches = (list: string[], name: string) => list.some(p => (p.endsWith('*') ? name.startsWith(p.slice(0, -1)) : p === name));

export class Enforcer {
  constructor(private opts: EnforceOptions, private chain: AuditChain) {}

  decide(tool: string): { allowed: boolean; reason: string } {
    if (this.opts.deny && matches(this.opts.deny, tool)) return { allowed: false, reason: 'on the deny list' };
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
      if (!msg || typeof msg !== 'object' || msg.method !== 'tools/call') { kept.push(m); continue; }
      // a name that is not a string cannot match any rule, so it is refused rather than guessed at
      const tool = typeof msg.params?.name === 'string' ? msg.params.name : '';
      const d = tool ? this.decide(tool) : { allowed: false, reason: 'the call has no tool name' };
      let argKeys: string[] = [];
      let argsSha = '';
      try {
        const a = msg.params?.arguments;
        if (a && typeof a === 'object') argKeys = Object.keys(a as object).slice(0, 50);
        argsSha = crypto.createHash('sha256').update(stable(a ?? null)).digest('hex');
      } catch (_e) { argsSha = 'unhashable'; }
      this.chain.append({ type: 'tools/call', tool: tool.slice(0, 200), id: typeof msg.id === 'string' || typeof msg.id === 'number' ? msg.id : null, decision: d.allowed ? 'allowed' : 'refused', reason: d.reason, argKeys, argsSha256: argsSha });
      if (d.allowed) kept.push(m);
      else if (typeof msg.id === 'string' || typeof msg.id === 'number') refused.push({ id: msg.id, tool, reason: d.reason });
    }
    if (kept.length === 0) return { forward: null, refused };
    return { forward: batch ? kept : kept[0], refused };
  }
}
