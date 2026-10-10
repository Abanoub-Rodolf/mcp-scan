import { spawn } from 'child_process';
import { describe, it, expect } from 'vitest';
import { JsonRpcInterceptor, queuedBytes, owedBytes } from '../../src/commands/proxy.js';

// When the proxy gives up on a stalled client, input still queued behind a
// half-read line must go with it: delivering its back half later would send a
// fragment out as if it were a message.
describe('JsonRpcInterceptor.abandon', () => {
  const line = (i: number) => JSON.stringify({ jsonrpc: '2.0', id: i, result: { pad: 'x'.repeat(9000) } });

  const stalled = () => {
    const ic = new JsonRpcInterceptor('SERVER -> CLIENT', null);
    const all = Array.from({ length: 30 }, (_, i) => line(i)).join('\n') + '\n';
    const buf = Buffer.from(all);
    // 4 KB chunks, nobody reading: the readable side fills, the rest queues
    for (let o = 0; o < buf.length; o += 4096) ic.write(buf.subarray(o, o + 4096));
    return ic;
  };
  const drain = (ic: JsonRpcInterceptor) => new Promise<string[]>(resolve => {
    const out: Buffer[] = [];
    ic.on('data', d => out.push(d));
    ic.on('end', () => resolve(Buffer.concat(out).toString().split('\n').filter(Boolean)));
  });

  it('drops queued input and the half line, so only whole messages ever come out', async () => {
    const ic = stalled();
    expect(ic.writableLength).toBeGreaterThan(0);
    const dropped = ic.abandon();
    expect(dropped.queued).toBeGreaterThan(0);
    expect(dropped.fragment).toBe(true);
    ic.end();
    const lines = await drain(ic);
    expect(lines.length).toBeGreaterThan(0);
    expect(lines.length).toBeLessThan(30);
    for (const l of lines) expect(() => JSON.parse(l)).not.toThrow();
  });

  it('keeps a complete JSON tail when nothing is queued', async () => {
    const ic = new JsonRpcInterceptor('SERVER -> CLIENT', null);
    ic.write(Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 1, result: {} })));
    expect(ic.abandon()).toEqual({ queued: 0, fragment: false });
    ic.end();
    expect((await drain(ic)).map(l => JSON.parse(l).id)).toEqual([1]);
  });

  it('drops a fragment tail when nothing is queued', async () => {
    const ic = new JsonRpcInterceptor('SERVER -> CLIENT', null);
    ic.write(Buffer.from('{"jsonrpc":"2.0","id":1,"res'));
    expect(ic.abandon()).toEqual({ queued: 0, fragment: true });
    ic.end();
    expect(await drain(ic)).toEqual([]);
  });

  it('reports what the kernel has not taken, not the whole in-flight write', () => {
    // measured: a 30,000,001-byte write, reader took 1 MiB and paused
    expect(queuedBytes(30000001, 28820353)).toBe(28820353);
    expect(queuedBytes(4096, 100)).toBe(100);
    expect(queuedBytes(30000043, 30000043)).toBe(30000043);
    // no usable libuv figure: fall back to the stream's own count
    expect(queuedBytes(4096, 0)).toBe(4096);
    expect(queuedBytes(4096, undefined)).toBe(4096);
    expect(queuedBytes(4096, NaN)).toBe(4096);
    expect(queuedBytes(0, 0)).toBe(0);
    for (const bad of [undefined, null, NaN, Infinity, -5, '7', {}]) expect(queuedBytes(bad, bad)).toBe(0);
    expect(queuedBytes(undefined, 12)).toBe(12);
  });
  it('adds writes queued behind the in-flight one to what libuv has not sent', () => {
    // measured: a 30,000,000-byte write in flight, then 5,000,000 + 1,000 queued in Node
    expect(queuedBytes(35001000, 29934464, 30000000)).toBe(34935464);
    // in-flight write fully taken by the kernel but not yet called back: only the queue is owed
    expect(queuedBytes(35001000, 0, 30000000)).toBe(5001000);
    expect(queuedBytes(30000000, 0, 30000000)).toBe(0);
    // no in-flight figure: unchanged
    expect(queuedBytes(35001000, 29934464, undefined)).toBe(29934464);
    // a stale or oversized in-flight figure never goes negative
    expect(queuedBytes(100, 50, 200)).toBe(50);
  });

  it('owedBytes on a real pipe counts every queued write, not just the first', async () => {
    // a child that never reads its stdin, so the kernel pipe fills and Node queues the rest
    const child = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 5000)'], { stdio: ['pipe', 'ignore', 'ignore'] });
    child.stdin.on('error', () => {});
    try {
      child.stdin.write('x'.repeat(30000000));
      child.stdin.write('y'.repeat(5000000));
      child.stdin.write('z'.repeat(1000));
      const total = 35001000;
      const owed = owedBytes(child.stdin);
      // the kernel pipe buffer takes at most a few hundred KB of it
      expect(owed).toBeGreaterThan(total - 1_000_000);
      expect(owed).toBeLessThanOrEqual(total);
    } finally {
      child.kill('SIGKILL');
    }
  });
});
