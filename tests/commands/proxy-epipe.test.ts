import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { runProxy } from '../../src/commands/proxy.js';
import { loadPolicy } from '../../src/config/parser.js';
import { spawn } from 'child_process';
import { PassThrough } from 'stream';
import { execa } from 'execa';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'node:url';

vi.mock('../../src/config/parser.js', async () => {
  const actual = await vi.importActual('../../src/config/parser.js') as any;
  return { ...actual, loadPolicy: vi.fn() };
});
vi.mock('child_process', () => ({ spawn: vi.fn() }));
vi.mock('../../src/utils/logger.js', () => ({
  logger: { brand: vi.fn(), info: vi.fn(), detail: vi.fn(), error: vi.fn(), warn: vi.fn() },
}));

const CLI = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../dist/index.js');

// A write to a server that is gone must not become an unhandled 'error'
// event: that would crash the proxy mid-session with a stack trace.
describe('proxy writes after the server is gone', () => {
  let dir: string;
  let childStdin: PassThrough;
  let childStdout: PassThrough;
  let stderrSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    vi.clearAllMocks();
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-proxy-epipe-'));
    process.env.MCP_SCAN_LOG_DIR = path.join(dir, 'logs');
    process.env.MCP_SCAN_NO_EXIT = '1';
    childStdin = new PassThrough();
    childStdout = new PassThrough();
    vi.mocked(loadPolicy).mockReturnValue({ privacy: { maskPii: true } });
    vi.mocked(spawn).mockReturnValue({ stdin: childStdin, stdout: childStdout, stderr: new PassThrough(), on: vi.fn(), kill: vi.fn() } as any);
    stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    await runProxy({ command: 'node', args: '-v' });
  });

  afterEach(() => {
    process.stdin.unpipe();
    // each runProxy adds its own handlers; keep tests independent
    process.stdout.removeAllListeners('error');
    process.stderr.removeAllListeners('error');
    stderrSpy.mockRestore();
    delete process.env.MCP_SCAN_LOG_DIR;
    delete process.env.MCP_SCAN_NO_EXIT;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const warnings = (): string[] => stderrSpy.mock.calls.map((c: unknown[]) => String(c[0])).filter((l: string) => l.includes('mcp-scan proxy:'));

  it('survives EPIPE on the server stdin and says so once', async () => {
    const epipe = () => Object.assign(new Error('write EPIPE'), { code: 'EPIPE' });
    expect(() => { childStdin.emit('error', epipe()); childStdin.emit('error', epipe()); }).not.toThrow();
    expect(warnings().filter(l => l.includes('EPIPE'))).toHaveLength(1);
  });

  it('survives a write error on the proxy stdout and says so once, separately from the server stdin', async () => {
    const epipe = () => Object.assign(new Error('write EPIPE'), { code: 'EPIPE' });
    expect(() => { childStdin.emit('error', epipe()); process.stdout.emit('error', epipe()); process.stdout.emit('error', epipe()); }).not.toThrow();
    expect(warnings().filter(l => l.includes('server stdin'))).toHaveLength(1);
    expect(warnings().filter(l => l.includes('proxy stdout'))).toHaveLength(1);
  });

  it('survives a reply written to a server stdin that was already ended', async () => {
    childStdin.end();
    const deep = (() => { let v: unknown = 'x@corp.example'; for (let i = 0; i < 150; i++) v = { n: v }; return v; })();
    childStdout.write(JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'sampling/createMessage', params: deep }) + '\n');
    await vi.waitFor(() => expect(warnings().length).toBeGreaterThan(0), { timeout: 10000, interval: 5 });
  });

  it('a real server that closes its stdin and keeps running does not crash the proxy', async () => {
    stderrSpy.mockRestore();
    const closed = path.join(dir, 'server-closed-stdin');
    const release = path.join(dir, 'release');
    const server = path.join(dir, 'server.js');
    // Stays up until released (or the test dir vanishes), so host load can't
    // make it exit before the writes below meet the closed stdin.
    fs.writeFileSync(server, `
      const fs = require('fs');
      fs.closeSync(0);
      fs.writeFileSync(${JSON.stringify(closed)}, '1');
      setInterval(() => { if (fs.existsSync(${JSON.stringify(release)}) || !fs.existsSync(${JSON.stringify(dir)})) process.exit(0); }, 20);
      setTimeout(() => process.exit(0), 30000);`);
    const proc = execa('node', [CLI, 'proxy', '--command', 'node', '--args', server], {
      cwd: dir, reject: false, env: { MCP_SCAN_LOG_DIR: path.join(dir, 'logs2') }, stdin: 'pipe',
    });
    let err = '';
    proc.stderr!.on('data', d => { err += d; });
    proc.stdin!.on('error', () => {});
    const wait = (check: () => void) => vi.waitFor(check, { timeout: 20000, interval: 10 });
    try {
      await wait(() => expect(fs.existsSync(closed)).toBe(true));
      for (let i = 0; i < 5; i++) proc.stdin!.write(JSON.stringify({ jsonrpc: '2.0', id: i, method: 'x' }) + '\n');
      await wait(() => expect(err).toMatch(/server stdin is no longer writable/));
      proc.stdin!.end();
    } finally {
      fs.writeFileSync(release, '1');
    }
    const res = await proc;
    expect(res.stderr).not.toMatch(/Unhandled|node:events|at .*\(node:/);
    expect(res.exitCode).toBe(0);
  }, 40000);
});
