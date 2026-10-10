import { describe, it, expect } from 'vitest';
import { JsonRpcInterceptor } from '../../src/commands/proxy.js';

// The client side reports each write's outcome back to the interceptor, so a
// request whose write failed is answered instead of left waiting.
describe('JsonRpcInterceptor delivery tracking', () => {
  const msgs = [
    { jsonrpc: '2.0', id: 1, method: 'x' },
    { jsonrpc: '2.0', method: 'notifications/ping' },
    [{ jsonrpc: '2.0', id: 'b', method: 'x' }, { jsonrpc: '2.0', method: 'n' }],
  ];
  const run = (track: boolean) => {
    const replies: string[] = [];
    const ic = new JsonRpcInterceptor('CLIENT -> SERVER', null, undefined, undefined, l => replies.push(l));
    if (track) ic.trackDelivery();
    const chunks: Buffer[] = [];
    ic.on('data', d => chunks.push(d));
    ic.write(msgs.map(m => JSON.stringify(m)).join('\n') + '\n');
    return { ic, chunks, replies };
  };

  it('claim() binds entries to their own write, so settled() can be called in any order and each failed write answers exactly its own requests', () => {
    const { ic, chunks, replies } = run(true);
    const sent = chunks.map(c => ic.claim(c));
    expect(sent.flat()).toHaveLength(3);
    // last write fails first, the notification's write succeeds, the first fails last
    ic.settled(sent.slice(2).flat(), new Error('EPIPE'));
    ic.settled(sent.slice(1, 2).flat(), new Error('EPIPE'));
    ic.settled(sent.slice(0, 1).flat(), new Error('EPIPE'));
    const got = replies.map(r => JSON.parse(r));
    expect(got).toEqual([
      [expect.objectContaining({ id: 'b', error: expect.objectContaining({ code: -32603 }) })],
      expect.objectContaining({ id: 1, error: expect.objectContaining({ code: -32603 }) }),
    ]);
  });

  it('stays silent for writes that succeeded', () => {
    const { ic, chunks, replies } = run(true);
    for (const c of chunks) ic.settled(ic.claim(c), null);
    expect(replies).toEqual([]);
  });

  it('keeps no entries for an interceptor nobody reports back to', () => {
    const { ic, chunks } = run(false);
    expect(chunks.length).toBeGreaterThan(0);
    for (const c of chunks) expect(ic.claim(c)).toEqual([]);
  });
});
