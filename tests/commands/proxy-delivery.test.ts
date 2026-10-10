import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'events';
import { PassThrough } from 'stream';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawn } from 'child_process';
import { JsonRpcInterceptor, runProxy } from '../../src/commands/proxy.js';
import { loadPolicy } from '../../src/config/parser.js';

vi.mock('../../src/config/parser.js', async () => {
  const actual = await vi.importActual('../../src/config/parser.js') as any;
  return { ...actual, loadPolicy: vi.fn() };
});
vi.mock('child_process', () => ({ spawn: vi.fn() }));
vi.mock('../../src/utils/logger.js', () => ({
  logger: { brand: vi.fn(), info: vi.fn(), detail: vi.fn(), error: vi.fn(), warn: vi.fn() },
}));

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

  it('drops a non-JSON line once refusing: nothing is forwarded and no reply is sent', async () => {
    const replies: string[] = [];
    const ic = new JsonRpcInterceptor('CLIENT -> SERVER', null, undefined, undefined, l => replies.push(l));
    const chunks: Buffer[] = [];
    ic.on('data', d => chunks.push(d));
    ic.refuseFurther();
    // 'end' only fires once everything the interceptor pushed has been read
    const ended = new Promise<void>(resolve => ic.on('end', () => resolve()));
    ic.end('token=sk-live-not-json-0123456789\n');
    await ended;
    expect(chunks).toEqual([]);
    expect(replies).toEqual([]);
  });

  it('keeps no entries for an interceptor nobody reports back to', () => {
    const { ic, chunks } = run(false);
    expect(chunks.length).toBeGreaterThan(0);
    for (const c of chunks) expect(ic.claim(c)).toEqual([]);
  });
});

// The unit tests above hand claim() the right chunk. This one checks runProxy
// takes it when it writes, not later in the write's callback: callbacks can
// fire in any order, and a claim made there would hand a failed write the
// entries of a different one.
describe('runProxy claims each chunk when it writes it', () => {
  let dir: string;
  let writes: { chunk: Buffer; done: (err?: Error | null) => void }[];
  let out: string[];
  let outSpy: ReturnType<typeof vi.spyOn>;
  let errSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-proxy-claim-'));
    process.env.MCP_SCAN_LOG_DIR = path.join(dir, 'logs');
    process.env.MCP_SCAN_NO_EXIT = '1';
    writes = [];
    out = [];
    // a server stdin whose write callbacks the test fires by hand
    const stdin = Object.assign(new EventEmitter(), {
      destroyed: false,
      end: vi.fn(),
      write: vi.fn((chunk: Buffer, done: (err?: Error | null) => void) => { writes.push({ chunk, done }); return true; }),
    });
    vi.mocked(loadPolicy).mockReturnValue({});
    vi.mocked(spawn).mockReturnValue({ stdin, stdout: new PassThrough(), stderr: new PassThrough(), on: vi.fn(), kill: vi.fn() } as any);
    outSpy = vi.spyOn(process.stdout, 'write').mockImplementation(((c: unknown) => { out.push(String(c)); return true; }) as any);
    errSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    process.stdin.unpipe();
    process.stdout.removeAllListeners('error');
    process.stderr.removeAllListeners('error');
    outSpy.mockRestore();
    errSpy.mockRestore();
    delete process.env.MCP_SCAN_LOG_DIR;
    delete process.env.MCP_SCAN_NO_EXIT;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('answers the request whose write failed, even when it fails before an earlier write finishes', async () => {
    await runProxy({ command: 'node', args: '-v' });
    const wait = (n: number) => vi.waitFor(() => expect(writes).toHaveLength(n), { timeout: 10000, interval: 5 });
    process.stdin.emit('data', Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'x' }) + '\n'));
    await wait(1);
    process.stdin.emit('data', Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'x' }) + '\n'));
    await wait(2);

    // the second write fails first, the first one succeeds afterwards
    writes[1].done(Object.assign(new Error('write EPIPE'), { code: 'EPIPE' }));
    writes[0].done(null);

    const replies = out.filter(l => l.includes('"jsonrpc"')).map(l => JSON.parse(l));
    expect(replies).toEqual([{ jsonrpc: '2.0', id: 2, error: expect.objectContaining({ code: -32603 }) }]);
  });
});
