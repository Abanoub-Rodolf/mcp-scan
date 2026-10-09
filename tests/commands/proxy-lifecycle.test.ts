import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execa } from 'execa';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'node:url';

const CLI = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../dist/index.js');

// How the proxy ends: server gone, client gone, server stdin gone.
describe('proxy lifecycle', () => {
  let dir: string;
  let logDir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-proxy-life-'));
    logDir = path.join(dir, 'logs');
  });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  const serverFile = (src: string) => {
    const p = path.join(dir, 'server.js');
    fs.writeFileSync(p, src);
    return p;
  };
  const alive = (pid: number) => { try { process.kill(pid, 0); return true; } catch { return false; } };

  it('exits promptly when the server exits but a descendant keeps its stdout open', async () => {
    const server = serverFile(`
      require('child_process').spawn('sleep', ['9'], { stdio: ['ignore', 'inherit', 'ignore'], detached: true }).unref();
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { ok: true } }) + '\\n');
      process.exit(0);`);
    const started = Date.now();
    const res = await execa('node', [CLI, 'proxy', '--command', 'node', '--args', server], {
      cwd: dir, reject: false, input: '', env: { MCP_SCAN_LOG_DIR: logDir },
    });
    expect(Date.now() - started).toBeLessThan(6000);
    expect(res.exitCode).toBe(0);
    expect(JSON.parse(res.stdout.trim())).toMatchObject({ id: 1, result: { ok: true } });
  }, 30000);

  it('shuts the server down when the client goes away (stdout closed)', async () => {
    const pidFile = path.join(dir, 'pid');
    const server = serverFile(`
      require('fs').writeFileSync(${JSON.stringify(pidFile)}, String(process.pid));
      setInterval(() => process.stdout.write(JSON.stringify({ jsonrpc: '2.0', method: 'tick', params: { pad: 'x'.repeat(2000) } }) + '\\n'), 20);
      setTimeout(() => process.exit(0), 20000);`);
    const started = Date.now();
    await execa('sh', ['-c', `node "${CLI}" proxy --command node --args "${server}" </dev/null | head -c 10 >/dev/null`], {
      cwd: dir, reject: false, env: { MCP_SCAN_LOG_DIR: logDir },
    });
    expect(Date.now() - started).toBeLessThan(10000);
    const pid = Number(fs.readFileSync(pidFile, 'utf8'));
    await new Promise(r => setTimeout(r, 300));
    expect(alive(pid)).toBe(false);
  }, 40000);

  it('answers requests that arrive after the server closed its stdin, with their own id, and ignores notifications', async () => {
    const server = serverFile(`require('fs').closeSync(0); setTimeout(() => process.exit(0), 3000);`);
    const proc = execa('node', [CLI, 'proxy', '--command', 'node', '--args', server], {
      cwd: dir, reject: false, env: { MCP_SCAN_LOG_DIR: logDir }, stdin: 'pipe',
    });
    const send = (m: object) => proc.stdin!.write(JSON.stringify(m) + '\n');
    await new Promise(r => setTimeout(r, 500));
    send({ jsonrpc: '2.0', id: 1, method: 'x' }); // meets the broken pipe
    await new Promise(r => setTimeout(r, 400));
    send({ jsonrpc: '2.0', id: 2, method: 'x' });
    send({ jsonrpc: '2.0', method: 'notifications/ping' });
    send({ jsonrpc: '2.0', id: 'three', method: 'x' });
    send([{ jsonrpc: '2.0', id: 4, method: 'x' }, { jsonrpc: '2.0', method: 'n' }]);
    await new Promise(r => setTimeout(r, 300));
    proc.stdin!.end();
    const res = await proc;
    const replies = res.stdout.split('\n').filter(Boolean).map(l => JSON.parse(l));
    const flat = replies.flat();
    expect(flat.map((r: any) => r.id).sort()).toEqual([2, 4, 'three']);
    for (const r of flat) expect(r).toMatchObject({ jsonrpc: '2.0', error: { code: -32603 } });
    expect(Array.isArray(replies[replies.length - 1])).toBe(true);
    expect(res.stderr).not.toMatch(/Unhandled|node:events/);
  }, 30000);
});
