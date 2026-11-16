import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { baselineHmac } from './audit-logger.js';
import { stable } from './live-snapshot.js';

// Tamper-evident log for the enforcing proxy. Each entry carries the hash of
// the one before it, so editing or removing an entry breaks every later link,
// and an HMAC under the per-install baseline key, so someone who can write the
// file but not the key cannot rebuild a valid chain. A small head file records
// the last entry, which catches a tail that was cut off. Arguments are never
// stored, only their keys and a hash: the log must be safe to hand to an auditor.

const GENESIS = '0'.repeat(64);
const sha = (s: string) => crypto.createHash('sha256').update(s).digest('hex');

export interface ChainEntry { seq: number; ts: string; event: Record<string, unknown>; prev: string; hash: string; mac: string }
interface Head { seq: number; hash: string; mac: string }

export class ChainError extends Error {}

const bodyOf = (seq: number, ts: string, event: Record<string, unknown>, prev: string) => stable({ seq, ts, event, prev });
export const macOf = (hash: string, create: boolean): string => {
  const m = baselineHmac(hash, create);
  if (m.status === 'ok') return m.mac;
  throw new ChainError(m.status === 'missing' ? 'the baseline key is missing' : `the baseline key is unusable (${m.reason})`);
};

export class AuditChain {
  private constructor(private file: string) {}

  // Opens or continues a chain. A chain that does not verify is never extended:
  // appending to a broken log would launder it.
  static open(file: string): AuditChain {
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    const c = new AuditChain(file);
    if (fs.existsSync(file) && fs.statSync(file).size > 0) {
      const v = verifyChain(file);
      if (!v.ok) throw new ChainError(`${file} does not verify (${v.reason} at entry ${v.at}); move it aside to start a new chain`);
    } else if (fs.existsSync(file + '.head')) {
      throw new ChainError(`${file} is empty or missing but its head file exists: the log was removed`);
    }
    macOf(GENESIS, true); // fail now, not on the first call, if there is no usable key
    return c;
  }

  // Several proxies may share one log (a client config wrapping two servers). Each append takes a
  // lock and continues from the file's own last entry, not from what this process remembers.
  append(event: Record<string, unknown>): ChainEntry {
    const lock = this.file + '.lock';
    const token = crypto.randomBytes(16).toString('hex');
    for (let i = 0; ; i++) {
      try { fs.writeFileSync(lock, token, { flag: 'wx', mode: 0o600 }); break; } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
        // A lock older than 10 seconds belongs to a process that died. Renaming it away is atomic, so
        // only one waiter takes it over, and nobody deletes a lock that a new owner just created.
        try {
          if (Date.now() - fs.statSync(lock).mtimeMs > 10000) {
            const gone = `${lock}.stale-${token}`;
            fs.renameSync(lock, gone);
            fs.rmSync(gone, { force: true });
          }
        } catch (_e) { /* someone else took it over first */ }
        if (i > 1300) throw new ChainError('the log is locked by another process');
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
      }
    }
    try {
      const tail = lastEntry(this.file);
      const seq = (tail?.seq ?? 0) + 1;
      const prev = tail?.hash ?? GENESIS;
      const ts = new Date().toISOString();
      const hash = sha(prev + '\n' + bodyOf(seq, ts, event, prev));
      const entry: ChainEntry = { seq, ts, event, prev, hash, mac: macOf(hash, true) };
      fs.appendFileSync(this.file, JSON.stringify(entry) + '\n', { mode: 0o600 });
      // temp file then rename: a reader never sees half a head
      const tmp = `${this.file}.head.${token}`;
      fs.writeFileSync(tmp, JSON.stringify({ seq, hash, mac: macOf(`head:${seq}:${hash}`, true) } satisfies Head), { mode: 0o600 });
      fs.renameSync(tmp, this.file + '.head');
      return entry;
    } finally {
      try { if (fs.readFileSync(lock, 'utf8') === token) fs.rmSync(lock, { force: true }); } catch (_e) { /* already gone */ }
    }
  }
}

// Reads only the end of the file: a log grows for as long as the proxy runs.
function lastEntry(file: string): ChainEntry | null {
  let fd: number;
  try { fd = fs.openSync(file, 'r'); } catch (_e) { return null; }
  try {
    const size = fs.fstatSync(fd).size;
    if (size === 0) return null;
    const len = Math.min(size, 262144);
    const buf = Buffer.alloc(len);
    fs.readSync(fd, buf, 0, len, size - len);
    const lines = buf.toString('utf8').split('\n').filter(l => l.trim());
    const e = JSON.parse(lines[lines.length - 1]);
    if (!e || typeof e.seq !== 'number' || typeof e.hash !== 'string') throw new Error('bad tail');
    return e;
  } catch (_e) {
    throw new ChainError('the last entry of the log cannot be read');
  } finally {
    fs.closeSync(fd);
  }
}

const sameHex = (have: unknown, want: string) => typeof have === 'string' && /^[0-9a-f]{64}$/.test(have) && crypto.timingSafeEqual(Buffer.from(have, 'hex'), Buffer.from(want, 'hex'));

export type Verdict = { ok: true; entries: number; head: string } | { ok: false; at: number; reason: string };

export function verifyChain(file: string): Verdict {
  try { return verifyChainUnsafe(file); } catch (_e) { return { ok: false, at: 0, reason: 'the log is malformed' }; }
}

function verifyChainUnsafe(file: string): Verdict {
  let raw: string;
  try { raw = fs.readFileSync(file, 'utf8'); } catch (e) { return { ok: false, at: 0, reason: `cannot read the log (${(e as Error).message})` }; }
  const lines = raw.split('\n').filter(l => l.trim());
  let prev = GENESIS;
  for (let i = 0; i < lines.length; i++) {
    const at = i + 1;
    let e: ChainEntry;
    try { e = JSON.parse(lines[i]); } catch (_e) { return { ok: false, at, reason: 'not valid JSON' }; }
    if (!e || typeof e !== 'object' || Array.isArray(e)) return { ok: false, at, reason: 'entry is not an object' };
    if (e.seq !== at) return { ok: false, at, reason: `sequence is ${e.seq}, expected ${at}` };
    if (e.prev !== prev) return { ok: false, at, reason: 'the link to the previous entry is broken' };
    let hash: string;
    try { hash = sha(prev + '\n' + bodyOf(e.seq, e.ts, e.event, e.prev)); } catch (_e) { return { ok: false, at, reason: 'entry is malformed' }; }
    if (hash !== e.hash) return { ok: false, at, reason: 'the entry was changed' };
    let mac: string;
    try { mac = macOf(hash, false); } catch (err) { return { ok: false, at, reason: (err as Error).message }; }
    if (!sameHex(e.mac, mac)) return { ok: false, at, reason: 'the signature does not match' };
    prev = hash;
  }
  let head: Head | null = null;
  try { head = JSON.parse(fs.readFileSync(file + '.head', 'utf8')); } catch (_e) { /* checked below */ }
  if (!head || typeof head !== 'object') return { ok: false, at: lines.length, reason: 'the head file is missing or unreadable, so a cut-off tail cannot be ruled out' };
  let headMac: string;
  try { headMac = macOf(`head:${head.seq}:${head.hash}`, false); } catch (err) { return { ok: false, at: lines.length, reason: (err as Error).message }; }
  if (!sameHex(head.mac, headMac)) return { ok: false, at: lines.length, reason: 'the head file is not signed by this install' };
  if (head.seq !== lines.length || head.hash !== prev) return { ok: false, at: lines.length, reason: `the log ends at entry ${lines.length} but the head file records entry ${head.seq}` };
  return { ok: true, entries: lines.length, head: prev };
}
