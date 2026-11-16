import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { Finding } from '../types/scan-result.js';
import { LiveCatalog } from './mcp-client.js';
import { auditDir, baselineHmac } from './audit-logger.js';
import { atomicWriteConfig } from '../config/writer.js';

// Rug-pull detection for `scan --live`: one hash per tool, prompt, resource
// and the server's instructions, recorded the first time a server is seen.
// A later scan that gets a different definition reports it, and keeps
// reporting it until the change is accepted (--accept-tool-changes): a
// baseline that re-learns on its own would flag a rug pull exactly once.

const SCHEMA = 'mcp-scan/tool-snapshots/1';
const TEXT_CAP = 4000;

export interface SnapshotItem { hash: string; text: string }
export interface ServerSnapshot { capturedAt: string; items: Record<string, SnapshotItem> }
interface StoreBody { schema: string; servers: Record<string, ServerSnapshot> }

export type LoadedStore =
  | { status: 'ok'; servers: Record<string, ServerSnapshot> }
  | { status: 'missing'; servers: Record<string, ServerSnapshot> }
  | { status: 'tampered'; reason: string; servers: Record<string, ServerSnapshot> };

export function snapshotFile(): string {
  return path.join(auditDir(), 'tool-snapshots.json');
}

// Sorted keys at every level so the same definition always hashes the same.
export function stable(value: unknown): string {
  if (Array.isArray(value)) return '[' + value.map(stable).join(',') + ']';
  if (value && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    return '{' + Object.keys(obj).sort().filter(k => obj[k] !== undefined).map(k => JSON.stringify(k) + ':' + stable(obj[k])).join(',') + '}';
  }
  return JSON.stringify(value ?? null);
}

const pick = (o: Record<string, unknown>, keys: string[]) => Object.fromEntries(keys.filter(k => o[k] !== undefined).map(k => [k, o[k]]));

// Only the fields the model reads or that change what a call does. _meta and
// icons churn without changing behavior and are left out.
export function catalogItems(c: LiveCatalog): Record<string, Record<string, unknown>> {
  const items: Record<string, Record<string, unknown>> = {};
  for (const t of c.tools) items[`tool:${String(t.name)}`] = pick(t, ['name', 'title', 'description', 'inputSchema', 'outputSchema', 'annotations']);
  for (const p of c.prompts) items[`prompt:${String(p.name)}`] = pick(p, ['name', 'title', 'description', 'arguments']);
  for (const r of c.resources) items[`resource:${String(r.uri)}`] = pick(r, ['uri', 'name', 'title', 'description', 'mimeType']);
  for (const r of c.resourceTemplates) items[`template:${String(r.uriTemplate)}`] = pick(r, ['uriTemplate', 'name', 'title', 'description', 'mimeType']);
  if (c.instructions) items['instructions'] = { instructions: c.instructions };
  return items;
}

export function snapshotOf(c: LiveCatalog, now = new Date()): ServerSnapshot {
  const items: Record<string, SnapshotItem> = {};
  for (const [k, def] of Object.entries(catalogItems(c))) {
    const text = stable(def);
    items[k] = { hash: crypto.createHash('sha256').update(text).digest('hex'), text: text.slice(0, TEXT_CAP) };
  }
  return { capturedAt: now.toISOString(), items };
}

const label = (key: string) => {
  const i = key.indexOf(':');
  return i === -1 ? 'Server instructions' : `${key[0].toUpperCase()}${key.slice(1, i)} '${key.slice(i + 1)}'`;
};
const clip = (s: string) => (s.length > 160 ? s.slice(0, 157) + '...' : s);

// Names the first top-level field that differs, with both values, so the
// finding says what moved without dumping two whole schemas.
function whatChanged(oldText: string, newText: string): string {
  let a: Record<string, unknown> = {};
  let b: Record<string, unknown> = {};
  try { a = JSON.parse(oldText); b = JSON.parse(newText); } catch (_e) { return 'definition changed'; }
  const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort();
  const fields = keys.filter(k => stable(a[k]) !== stable(b[k]));
  if (fields.length === 0) return 'definition changed';
  const show = (v: unknown) => (v === undefined ? '(absent)' : typeof v === 'string' ? JSON.stringify(clip(v)) : clip(stable(v)));
  const first = fields[0];
  const more = fields.length > 1 ? ` (also: ${fields.slice(1).join(', ')})` : '';
  return `${first}: ${show(a[first])} -> ${show(b[first])}${more}`;
}

export function diffSnapshots(serverName: string, prev: ServerSnapshot, cur: ServerSnapshot): Finding[] {
  const findings: Finding[] = [];
  const since = prev.capturedAt.slice(0, 10);
  const accept = 'If you expected this change (you upgraded the server), review it and run mcp-scan --live --accept-tool-changes to make it the new baseline.';
  for (const [key, item] of Object.entries(cur.items)) {
    const before = prev.items[key];
    if (!before) {
      findings.push({
        id: 'tool-added',
        severity: key.startsWith('tool:') ? 'MEDIUM' : 'LOW',
        description: `${label(key)} on server '${serverName}' is new since the snapshot of ${since}.`,
        fixRecommendation: `Review what it tells the model. ${accept}`,
      });
    } else if (before.hash !== item.hash) {
      findings.push({
        id: 'tool-definition-changed',
        severity: key.startsWith('tool:') || key === 'instructions' ? 'HIGH' : 'MEDIUM',
        description: `${label(key)} on server '${serverName}' changed since the snapshot of ${since} (possible rug pull): ${whatChanged(before.text, item.text)}.`,
        fixRecommendation: `A server that rewrites its tool text after it was approved is the rug-pull pattern. ${accept}`,
      });
    }
  }
  for (const key of Object.keys(prev.items)) {
    if (!cur.items[key]) {
      findings.push({
        id: 'tool-removed',
        severity: 'LOW',
        description: `${label(key)} on server '${serverName}' is gone since the snapshot of ${since}.`,
        fixRecommendation: accept,
      });
    }
  }
  return findings;
}

const isSnap = (v: unknown): v is ServerSnapshot => {
  if (!v || typeof v !== 'object') return false;
  const s = v as ServerSnapshot;
  return typeof s.capturedAt === 'string' && !!s.items && typeof s.items === 'object'
    && Object.values(s.items).every(i => i && typeof i.hash === 'string' && typeof i.text === 'string');
};

// everSaved: the audit log says an earlier scan kept snapshots. A store that
// is missing after that was deleted, which would otherwise re-baseline every
// server silently.
export function loadSnapshots(everSaved: boolean): LoadedStore {
  let raw: string;
  try {
    raw = fs.readFileSync(snapshotFile(), 'utf8');
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') {
      return everSaved
        ? { status: 'tampered', reason: 'the snapshot store went missing although earlier --live scans recorded one', servers: {} }
        : { status: 'missing', servers: {} };
    }
    return { status: 'tampered', reason: `unreadable (${(e as Error).message})`, servers: {} };
  }
  let parsed: any;
  try { parsed = JSON.parse(raw); } catch (_e) { return { status: 'tampered', reason: 'not valid JSON', servers: {} }; }
  if (!parsed || parsed.schema !== SCHEMA || !parsed.servers || typeof parsed.servers !== 'object'
    || !Object.values(parsed.servers).every(isSnap)) {
    return { status: 'tampered', reason: 'not a snapshot store this version understands', servers: {} };
  }
  const body: StoreBody = { schema: SCHEMA, servers: parsed.servers };
  const mac = baselineHmac(stable(body), false);
  if (mac.status !== 'ok') return { status: 'tampered', reason: mac.status === 'missing' ? 'signed store but the baseline key is gone' : `baseline key unreadable (${mac.reason})`, servers: parsed.servers };
  const have = typeof parsed.sig === 'string' && /^[0-9a-f]{64}$/.test(parsed.sig) ? Buffer.from(parsed.sig, 'hex') : null;
  if (!have || !crypto.timingSafeEqual(have, Buffer.from(mac.mac, 'hex'))) {
    return { status: 'tampered', reason: 'signature does not match', servers: parsed.servers };
  }
  return { status: 'ok', servers: parsed.servers };
}

export function saveSnapshots(servers: Record<string, ServerSnapshot>): boolean {
  try {
    const body: StoreBody = { schema: SCHEMA, servers };
    const mac = baselineHmac(stable(body), true);
    if (mac.status !== 'ok') return false;
    atomicWriteConfig(snapshotFile(), JSON.stringify({ ...body, sig: mac.mac }, null, 2), { keepBackups: 3 });
    return true;
  } catch (_e) {
    return false;
  }
}
