import { describe, it, expect } from 'vitest';
import { JsonRpcInterceptor } from '../../src/commands/proxy.js';

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
});
