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
});
