import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execa } from 'execa';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(__dirname, '../../dist/index.js');

// Real subprocesses on purpose: the bugs live in how the OS pipes chunk
// the bytes (64 KB reads split a 3-byte character) and in end-of-stream.
describe('proxy hardening', () => {
  let dir: string;
  let logDir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-proxy-hard-'));
    logDir = path.join(dir, 'logs');
  });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  const maskOn = () => fs.writeFileSync(path.join(dir, '.mcp-scan.json'), JSON.stringify({ privacy: { maskPii: true } }));
  const logs = () => fs.readdirSync(logDir).map(f => fs.readFileSync(path.join(logDir, f), 'utf8')).join('\n');
  const serverFile = (src: string) => {
    const p = path.join(dir, 'server.js');
    fs.writeFileSync(p, src);
    return p;
  };
  const run = (server: string, input?: string | Buffer) =>
    execa('node', [CLI, 'proxy', '--command', 'node', '--args', server], {
      cwd: dir, reject: false, input: input ?? '', env: { MCP_SCAN_LOG_DIR: logDir },
    });
  const nest = (depth: number, leaf: unknown) => {
    let v: unknown = leaf;
    for (let i = 0; i < depth; i++) v = { n: v };
    return v;
  };

  it('masks and logs a final server line that has no trailing newline', async () => {
    maskOn();
    const server = serverFile(`process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: 3, result: { email: 'tail@corp.example' } }));`);
    const { stdout } = await run(server);
    expect(stdout).not.toContain('tail@corp.example');
    expect(JSON.parse(stdout.trim()).result.email).toBe('[EMAIL_MASKED]');
    expect(logs()).not.toContain('tail@corp.example');
    expect(logs()).toContain('[EMAIL_MASKED]');
  }, 30000);

  it('delivers everything the server wrote before it exited, tail included, even with a slow reader', async () => {
    maskOn();
    const big = JSON.stringify({ jsonrpc: '2.0', id: 1, result: { t: 'x'.repeat(3000000) } });
    const tail = JSON.stringify({ jsonrpc: '2.0', id: 2, result: { email: 'tail@corp.example' } });
    const server = serverFile(`process.stdout.write(${JSON.stringify(big)} + '\\n' + ${JSON.stringify(tail)});`);
    // Reading through a shell pipe that stalls first makes the proxy's stdout back up.
    const proc = execa('sh', ['-c', `node "${CLI}" proxy --command node --args "${server}" </dev/null | (sleep 0.5; cat)`], {
      cwd: dir, reject: false, env: { MCP_SCAN_LOG_DIR: logDir }, maxBuffer: 1e8,
    });
    const res = await proc;
    const lines = res.stdout.split('\n').filter(Boolean);
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]).result.t.length).toBe(3000000);
    expect(JSON.parse(lines[1]).result.email).toBe('[EMAIL_MASKED]');
  }, 30000);

  it('masks a final client line that has no trailing newline', async () => {
    maskOn();
    const out = path.join(dir, 'got.txt');
    const server = serverFile(`let b=[];process.stdin.on('data',d=>b.push(d));process.stdin.on('end',()=>require('fs').writeFileSync(${JSON.stringify(out)},Buffer.concat(b)));`);
    await run(server, JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'x', params: { email: 'tail@corp.example' } }));
    const got = fs.readFileSync(out, 'utf8');
    expect(got).not.toContain('tail@corp.example');
    expect(got).toContain('[EMAIL_MASKED]');
  }, 30000);

  it('fails closed past the depth limit: server response is replaced by an error for its id, nothing raw leaves', async () => {
    maskOn();
    const deep = JSON.stringify({ jsonrpc: '2.0', id: 42, result: nest(150, 'deep@corp.example') });
    const server = serverFile(`process.stdout.write(${JSON.stringify(deep)} + '\\n');`);
    const { stdout } = await run(server);
    expect(stdout).not.toContain('deep@corp.example');
    expect(JSON.parse(stdout.trim())).toMatchObject({ jsonrpc: '2.0', id: 42, error: { code: -32603 } });
    expect(logs()).not.toContain('deep@corp.example');
  }, 30000);

  it('fails closed past the depth limit: client request is not forwarded and its sender gets an error for its id', async () => {
    maskOn();
    const out = path.join(dir, 'got.txt');
    const server = serverFile(`let b=[];process.stdin.on('data',d=>b.push(d));process.stdin.on('end',()=>require('fs').writeFileSync(${JSON.stringify(out)},Buffer.concat(b)));`);
    const deep = JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'x', params: nest(150, 'deep@corp.example') });
    const { stdout } = await run(server, deep + '\n');
    expect(fs.readFileSync(out, 'utf8')).toBe('');
    expect(stdout).not.toContain('deep@corp.example');
    expect(JSON.parse(stdout.trim())).toMatchObject({ jsonrpc: '2.0', id: 7, error: { code: -32603 } });
    expect(logs()).not.toContain('deep@corp.example');
  }, 30000);

  // The pad shifts where the 64 KB pipe boundary lands inside a 3-byte
  // character; across the three pads at least one splits mid-character.
  it.each(['', 'a', 'aa'])('keeps multibyte characters intact when a 120 KB server line is split across chunks (pad %j)', async (pad) => {
    const text = pad + '日本語'.repeat(14000);
    const line = JSON.stringify({ jsonrpc: '2.0', id: 1, result: { text } });
    expect(Buffer.byteLength(line)).toBeGreaterThan(120000);
    const server = serverFile(`process.stdout.write(${JSON.stringify(line)} + '\\n');`);
    const { stdout } = await run(server);
    expect(stdout).not.toContain('\uFFFD');
    expect(JSON.parse(stdout.trim()).result.text).toBe(text);
  }, 30000);

  it.each(['', 'a', 'aa'])('keeps multibyte characters intact when a 120 KB client line is split across chunks (pad %j)', async (pad) => {
    const text = pad + '日本語'.repeat(14000);
    const line = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'x', params: { text } }) + '\n';
    const out = path.join(dir, 'got.txt');
    const server = serverFile(`let b=[];process.stdin.on('data',d=>b.push(d));process.stdin.on('end',()=>require('fs').writeFileSync(${JSON.stringify(out)},Buffer.concat(b)));`);
    await run(server, line);
    const got = fs.readFileSync(out, 'utf8');
    expect(got).not.toContain('\uFFFD');
    expect(JSON.parse(got).params.text).toBe(text);
  }, 30000);
});
