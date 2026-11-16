import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { JsonRpcInterceptor } from '../../src/commands/proxy.js';
import { AuditChain, verifyChain, ChainError } from '../../src/utils/audit-chain.js';
import { Enforcer } from '../../src/utils/proxy-enforce.js';

let dir: string;
let file: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'enforce-'));
  process.env.MCP_SCAN_HOME = path.join(dir, 'home');
  file = path.join(dir, 'chain.jsonl');
});
afterEach(() => { delete process.env.MCP_SCAN_HOME; fs.rmSync(dir, { recursive: true, force: true }); });

const lines = () => fs.readFileSync(file, 'utf8').trim().split('\n');

describe('hash-chained decision log', () => {
  it('verifies, and keeps verifying across reopen', () => {
    let c = AuditChain.open(file);
    c.append({ n: 1 }); c.append({ n: 2 });
    c = AuditChain.open(file);
    c.append({ n: 3 });
    expect(verifyChain(file)).toMatchObject({ ok: true, entries: 3 });
  });

  it('detects an edited entry', () => {
    const c = AuditChain.open(file);
    c.append({ tool: 'a', decision: 'refused' }); c.append({ n: 2 });
    const l = lines();
    l[0] = l[0].replace('refused', 'allowed');
    fs.writeFileSync(file, l.join('\n') + '\n');
    expect(verifyChain(file)).toMatchObject({ ok: false, at: 1, reason: 'the entry was changed' });
  });

  it('detects a removed middle entry and a cut-off tail', () => {
    const c = AuditChain.open(file);
    for (let i = 0; i < 4; i++) c.append({ n: i });
    const l = lines();
    fs.writeFileSync(file, [l[0], l[2], l[3]].join('\n') + '\n');
    expect(verifyChain(file).ok).toBe(false);
    fs.writeFileSync(file, l.slice(0, 3).join('\n') + '\n');
    const v = verifyChain(file);
    expect(v.ok).toBe(false);
    expect(v.ok === false && v.reason).toMatch(/head file records entry 4/);
  });

  it('two writers on one log keep one chain', () => {
    const a = AuditChain.open(file);
    const b = AuditChain.open(file);
    a.append({ w: 'a' }); b.append({ w: 'b' }); a.append({ w: 'a' }); b.append({ w: 'b' });
    expect(verifyChain(file)).toMatchObject({ ok: true, entries: 4 });
  });

  it('reports a malformed log instead of throwing', () => {
    const c = AuditChain.open(file);
    c.append({ n: 1 });
    fs.writeFileSync(file, 'null\n');
    expect(verifyChain(file).ok).toBe(false);
    fs.writeFileSync(file, JSON.stringify({ seq: 1, mac: '\u00e9'.repeat(64), event: {}, prev: '', hash: '' }) + '\n');
    expect(verifyChain(file).ok).toBe(false);
  });

  it('rejects a head file that was forged to match a truncated log', () => {
    const c = AuditChain.open(file);
    c.append({ n: 1 }); c.append({ n: 2 });
    const l = lines();
    fs.writeFileSync(file, l[0] + '\n');
    const e = JSON.parse(l[0]);
    fs.writeFileSync(file + '.head', JSON.stringify({ seq: 1, hash: e.hash, mac: e.mac }));
    expect(verifyChain(file)).toMatchObject({ ok: false, reason: 'the head file is not signed by this install' });
  });

  it('rejects a chain rebuilt without the key (hashes right, signature wrong)', () => {
    const c = AuditChain.open(file);
    c.append({ n: 1 });
    const e = JSON.parse(lines()[0]);
    e.mac = '0'.repeat(64);
    fs.writeFileSync(file, JSON.stringify(e) + '\n');
    expect(verifyChain(file)).toMatchObject({ ok: false, reason: 'the signature does not match' });
  });

  it('will not extend a broken chain, or one whose log was deleted', () => {
    const c = AuditChain.open(file);
    c.append({ n: 1 });
    fs.writeFileSync(file, lines()[0].replace('"n":1', '"n":9') + '\n');
    expect(() => AuditChain.open(file)).toThrow(ChainError);
    fs.rmSync(file);
    expect(() => AuditChain.open(file)).toThrow(/removed/);
  });
});

describe('enforcing proxy', () => {
  const call = (id: number, name: string, args: unknown = { path: '/etc/passwd' }) => JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } }) + '\n';
  const setup = (opts: { allow?: string[]; deny?: string[] }) => {
    const replies: string[] = [];
    const ic = new JsonRpcInterceptor('CLIENT -> SERVER', null, undefined, undefined, l => replies.push(l));
    ic.enforcer = new Enforcer(opts, AuditChain.open(file));
    const out: string[] = [];
    ic.on('data', d => out.push(String(d)));
    return { ic, out, replies };
  };

  it('refuses a denied tool with a JSON-RPC error and forwards the rest untouched', () => {
    const { ic, out, replies } = setup({ deny: ['delete_*'] });
    ic.write(call(1, 'delete_all') + call(2, 'read_file'));
    expect(out).toHaveLength(1);
    expect(JSON.parse(out[0]).params.name).toBe('read_file');
    const r = JSON.parse(replies[0]);
    expect(r).toMatchObject({ id: 1, error: { code: -32001 } });
    expect(r.error.message).toMatch(/Blocked by mcp-scan policy/);
  });

  it('with an allow list, refuses anything not on it, and deny wins over allow', () => {
    const { ic, out, replies } = setup({ allow: ['read_file', 'write_file'], deny: ['write_file'] });
    ic.write(call(1, 'read_file') + call(2, 'write_file') + call(3, 'shell'));
    expect(out.map(o => JSON.parse(o).id)).toEqual([1]);
    expect(replies.map(r => JSON.parse(r).id)).toEqual([2, 3]);
  });

  it('answers only the refused member of a batch and forwards the others', () => {
    const { ic, out, replies } = setup({ deny: ['shell'] });
    ic.write(JSON.stringify([
      { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'shell', arguments: {} } },
      { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'read_file', arguments: {} } },
    ]) + '\n');
    expect(JSON.parse(out[0])).toHaveLength(1);
    expect(JSON.parse(out[0])[0].id).toBe(2);
    expect(JSON.parse(replies[0])).toEqual([expect.objectContaining({ id: 1 })]);
  });

  it('refuses a tools/call with no usable tool name, and passes other methods through', () => {
    const { ic, out, replies } = setup({ deny: ['x'] });
    ic.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: { evil: 1 } } }) + '\n' + JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }) + '\n');
    expect(replies).toHaveLength(1);
    expect(JSON.parse(out[0]).method).toBe('tools/list');
  });

  it('drops a line that is not valid JSON instead of forwarding it', () => {
    const { ic, out } = setup({ deny: ['shell'] });
    ic.write('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell"},}\n');
    expect(out).toHaveLength(0);
  });

  it('forwards the screened JSON, so duplicate keys cannot be read two ways', () => {
    const { ic, out } = setup({ deny: ['shell'] });
    ic.write('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell"},"params":{"name":"read_file"}}\n');
    expect(JSON.parse(out[0]).params.name).toBe('read_file');
    expect(out[0]).not.toContain('shell');
  });

  it('does not forward a refused call that has no usable id (a notification)', () => {
    const { ic, out, replies } = setup({ deny: ['shell'] });
    ic.write('{"jsonrpc":"2.0","method":"tools/call","params":{"name":"shell"}}\n{"jsonrpc":"2.0","id":null,"method":"tools/call","params":{"name":"shell"}}\n');
    expect(out).toHaveLength(0);
    expect(replies).toHaveLength(0);
  });

  it('refuses look-alike keys and case or unicode variants of a denied name', () => {
    const { ic, out, replies } = setup({ deny: ['shell'] });
    ic.write('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","NAME":"shell"}}\n');
    ic.write('{"jsonrpc":"2.0","id":2,"Method":"tools/call","params":{"name":"shell"}}\n');
    ic.write(call(3, 'Shell') + call(4, ' shell\u200b'.trim()) + call(5, '\uFF53hell'));
    expect(out).toHaveLength(0);
    expect(replies.map(r => JSON.parse(r).id)).toEqual([1, 2, 3, 4, 5]);
  });

  it('logs every decision with argument keys and a hash, never the values', () => {
    const { ic } = setup({ deny: ['shell'] });
    ic.write(call(1, 'shell', { cmd: 'cat ~/.ssh/id_rsa' }) + call(2, 'read_file', { path: 'secret-value-123' }));
    const text = fs.readFileSync(file, 'utf8');
    expect(text).not.toContain('id_rsa');
    expect(text).not.toContain('secret-value-123');
    const events = lines().map(l => JSON.parse(l).event);
    expect(events.map(e => e.decision)).toEqual(['refused', 'allowed']);
    expect(events[0]).toMatchObject({ tool: 'shell', argKeys: ['cmd'] });
    expect(events[0].argsHmac).toMatch(/^[0-9a-f]{64}$/);
    expect(verifyChain(file).ok).toBe(true);
  });

  it('fails closed: if the decision cannot be recorded, the call is not forwarded', () => {
    const { ic, out, replies } = setup({});
    fs.mkdirSync(file); // a directory where the log should be: appends fail
    ic.write(call(1, 'read_file'));
    expect(out).toHaveLength(0);
    expect(JSON.parse(replies[0]).error.message).toMatch(/not forwarded/);
  });
});

describe('runProxy --enforce flags', () => {
  it('will not start with an allow list that names nothing', async () => {
    const { runProxy } = await import('../../src/commands/proxy.js');
    process.exitCode = undefined;
    await runProxy({ command: 'node', enforce: true, allowTools: ' , ', auditChain: path.join(os.tmpdir(), 'never-written.jsonl') });
    expect(process.exitCode).toBe(1);
    process.exitCode = undefined;
  });
});

describe('enforcement edge cases', () => {
  const setup2 = () => {
    const replies: string[] = [];
    const ic = new JsonRpcInterceptor('CLIENT -> SERVER', null, undefined, undefined, l => replies.push(l));
    ic.enforcer = new Enforcer({ deny: ['shell'] }, AuditChain.open(file));
    const out: string[] = [];
    ic.on('data', d => out.push(String(d)));
    return { ic, out, replies };
  };

  it('refuses nested and empty batches outright', () => {
    const { ic, out, replies } = setup2();
    ic.write('[[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell"}}]]\n[]\n');
    expect(out).toHaveLength(0);
    expect(replies.map(r => JSON.parse(r).error.code)).toEqual([-32600, -32600]);
  });

  it('does not crash on a message too deep to write back', () => {
    const { ic, out } = setup2();
    const deep = '['.repeat(60000) + ']'.repeat(60000);
    expect(() => ic.write(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"x":${deep}}}}\n`)).not.toThrow();
    expect(out).toHaveLength(0);
  });

  it('refuses to start when allow, deny or chain flags are given without --enforce, or a wildcard is misplaced', async () => {
    const { runProxy } = await import('../../src/commands/proxy.js');
    for (const o of [{ allowTools: 'a' }, { denyTools: 'a' }, { auditChain: path.join(dir, 'x.jsonl') }, { enforce: true, denyTools: '*_delete' }]) {
      process.exitCode = undefined;
      await runProxy({ command: 'node', ...o });
      expect(process.exitCode).toBe(1);
    }
    process.exitCode = undefined;
  });

  it('a stale lock from a dead process is taken over, and a live one is never deleted by a waiter', () => {
    const c = AuditChain.open(file);
    fs.writeFileSync(file + '.lock', 'dead-owner');
    const old = new Date(Date.now() - 60000);
    fs.utimesSync(file + '.lock', old, old);
    c.append({ n: 1 });
    expect(verifyChain(file).ok).toBe(true);
    expect(fs.existsSync(file + '.lock')).toBe(false);
  });
});

describe('chain key separation and responses', () => {
  it('a client-chosen argument cannot be turned into a snapshot-store signature', async () => {
    const { baselineHmac } = await import('../../src/utils/audit-logger.js');
    const { stable } = await import('../../src/utils/live-snapshot.js');
    const forged = { schema: 'mcp-scan/tool-snapshots/1', servers: {} };
    const chain = AuditChain.open(file);
    const enf = new Enforcer({}, chain);
    enf.screen({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'x', arguments: forged } });
    const logged = JSON.parse(fs.readFileSync(file, 'utf8').trim()).event.argsHmac;
    const m = baselineHmac(stable(forged), false);
    expect(m.status === 'ok' && m.mac).not.toBe(logged);
  });

  it('passes a client response that has look-alike keys instead of treating it as a call', () => {
    const replies: string[] = [];
    const ic = new JsonRpcInterceptor('CLIENT -> SERVER', null, undefined, undefined, l => replies.push(l));
    ic.enforcer = new Enforcer({ deny: ['x'] }, AuditChain.open(file));
    const out: string[] = [];
    ic.on('data', d => out.push(String(d)));
    ic.write('{"jsonrpc":"2.0","id":"srv-1","ID":2,"result":{}}\n');
    expect(out).toHaveLength(1);
  });
});
