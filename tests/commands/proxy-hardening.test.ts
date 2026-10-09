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
    // the log must end with the tail too, not stop at the server's close
    expect(logs()).toContain('"id":2,"result":{"email":"[EMAIL_MASKED]"}');
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

  it('echoes the sender\'s id exactly, even when it looks like PII and masking dies after it', async () => {
    maskOn();
    const deep = JSON.stringify({ jsonrpc: '2.0', id: 'user@corp.example', result: nest(150, 'deep@corp.example') });
    const server = serverFile(`process.stdout.write(${JSON.stringify(deep)} + '\\n');`);
    const { stdout } = await run(server);
    expect(JSON.parse(stdout.trim())).toMatchObject({ id: 'user@corp.example', error: { code: -32603 } });
  }, 30000);

  it('drops a million-level payload too, whatever throws first', async () => {
    maskOn();
    const n = 1000000;
    const server = serverFile(`const n=${n};process.stdout.write('{"jsonrpc":"2.0","id":5,"result":' + '{"n":'.repeat(n) + '"deep@corp.example"' + '}'.repeat(n) + '}\\n');`);
    const { stdout } = await run(server);
    expect(stdout).not.toContain('deep@corp.example');
    expect(JSON.parse(stdout.trim())).toMatchObject({ id: 5, error: { code: -32603 } });
  }, 60000);

  it('masks PII used as an object key in a forwarded response and in the log, keeping envelope keys and colliding entries', async () => {
    maskOn();
    const msg = JSON.stringify({ jsonrpc: '2.0', id: 4, result: { 'a@corp.example': 1, 'b@corp.example': 2 } });
    const server = serverFile(`process.stdout.write(${JSON.stringify(msg)} + '\\n');`);
    const { stdout } = await run(server);
    expect(stdout).not.toContain('corp.example');
    expect(JSON.parse(stdout.trim())).toEqual({ jsonrpc: '2.0', id: 4, result: { '[EMAIL_MASKED]': 1, '[EMAIL_MASKED_2]': 2 } });
    expect(logs()).not.toContain('corp.example');
    expect(logs()).toContain('[EMAIL_MASKED_2]');
  }, 30000);

  it('masks a non-JSON stdout line from the server too, and does not log it', async () => {
    maskOn();
    const server = serverFile(`process.stdout.write('debug: mailing tail@corp.example now\\n');`);
    const { stdout } = await run(server);
    expect(stdout).not.toContain('tail@corp.example');
    expect(stdout).toContain('mailing [EMAIL_MASKED] now');
    expect(logs()).not.toContain('corp.example');
  }, 30000);

  it('forwards a non-JSON line untouched when masking is off', async () => {
    const server = serverFile(`process.stdout.write('debug: mailing tail@corp.example now\\n');`);
    const { stdout } = await run(server);
    expect(stdout.trim()).toBe('debug: mailing tail@corp.example now');
  }, 30000);

  it.each([
    ['uuid', '3f2b8c1e-9a4d-4e7b-8c55-1234567890ab'],
    ['req-number', 'req-1234567890'],
    ['zip-like', '12345'],
    ['pii-looking', 'user@corp.example'],
  ])('passes the envelope id through unmasked so the reply still matches (%s)', async (_n, id) => {
    maskOn();
    const server = serverFile(`process.stdout.write(${JSON.stringify(JSON.stringify({ jsonrpc: '2.0', id, result: { email: 'a@corp.example', id: 'req-1234567890' } }))} + '\\n');`);
    const { stdout } = await run(server);
    const msg = JSON.parse(stdout.trim());
    expect(msg.id).toBe(id);
    // only the envelope id is exempt; the same text inside the payload is still masked
    expect(msg.result).toEqual({ email: '[EMAIL_MASKED]', id: 'req-[NPI_MASKED]' });
  }, 30000);

  it('forwards a million-level message untouched, and survives it, when masking is off', async () => {
    const n = 1000000;
    const server = serverFile(`const n=${n};process.stdout.write('{"jsonrpc":"2.0","id":5,"result":' + '{"n":'.repeat(n) + '1' + '}'.repeat(n) + '}\\n');`);
    const { stdout, exitCode } = await run(server);
    expect(exitCode).toBe(0);
    expect(stdout.trim().length).toBe(('{"jsonrpc":"2.0","id":5,"result":' + '{"n":'.repeat(n) + '1' + '}'.repeat(n) + '}').length);
    expect(stdout.startsWith('{"jsonrpc":"2.0","id":5,"result":{"n":{"n":')).toBe(true);
  }, 60000);

  it.each([['masking on', true], ['masking off', false]])('drops a server line cut off mid-message at exit, with a warning (%s)', async (_n, on) => {
    if (on) maskOn();
    const server = serverFile(`process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: 0, result: {} }) + '\\n' + '{"jsonrpc":"2.0","id":1,"result":{"a":"hel');`);
    const { stdout, stderr } = await run(server);
    expect(stdout.trim().split('\n')).toHaveLength(1);
    expect(JSON.parse(stdout.trim()).id).toBe(0);
    expect(stderr).toMatch(/dropped an unfinished last line/);
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
