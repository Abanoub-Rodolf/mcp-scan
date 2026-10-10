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

  it('delivers every line when the server exits while a slow client has not read yet', async () => {
    const lines: string[] = [];
    for (let i = 0; i < 40; i++) lines.push(JSON.stringify({ jsonrpc: '2.0', id: i, result: { pad: 'x'.repeat(9000) } }));
    const file = path.join(dir, 'responses.txt');
    fs.writeFileSync(file, lines.join('\n') + '\n');
    const bytes = fs.statSync(file).size;
    // cat exits at once; the reader sleeps longer than any fixed grace period
    const res = await execa('sh', ['-c', `node "${CLI}" proxy --command cat --args "${file}" </dev/null | (sleep 4; wc -lc)`], {
      cwd: dir, reject: false, env: { MCP_SCAN_LOG_DIR: logDir },
    });
    expect(res.stdout.trim().split(/\s+/).map(Number)).toEqual([40, bytes]);
  }, 30000);

  it('still exits within about 3s when only a descendant holds the stdout open', async () => {
    const server = serverFile(`
      require('child_process').spawn('sleep', ['9'], { stdio: ['ignore', 'inherit', 'ignore'], detached: true }).unref();
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { ok: true } }) + '\\n' + '{"partial":');
      process.exit(0);`);
    const started = Date.now();
    const res = await execa('node', [CLI, 'proxy', '--command', 'node', '--args', server], {
      cwd: dir, reject: false, input: '', env: { MCP_SCAN_LOG_DIR: logDir },
    });
    expect(Date.now() - started).toBeLessThan(4500);
    // the unfinished fragment is abandoned with a warning, never forwarded as if it were a message
    expect(res.stdout.trim().split('\n')).toHaveLength(1);
    expect(res.stderr).toMatch(/abandon|unfinished/i);
  }, 30000);

  it('delivers a complete last line that lacks a newline even when the output pipe never closes', async () => {
    const server = serverFile(`
      require('child_process').spawn('sleep', ['9'], { stdio: ['ignore', 'inherit', 'ignore'], detached: true }).unref();
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: 1, result: {} }) + '\\n' + JSON.stringify({ jsonrpc: '2.0', id: 2, result: {} }));
      process.exit(0);`);
    const res = await execa('node', [CLI, 'proxy', '--command', 'node', '--args', server], {
      cwd: dir, reject: false, input: '', env: { MCP_SCAN_LOG_DIR: logDir },
    });
    expect(res.stdout.trim().split('\n').map(l => JSON.parse(l).id)).toEqual([1, 2]);
  }, 30000);

  it('with a descendant holding the pipe, a slow client still gets all of a large backlog', async () => {
    const lines: string[] = [];
    for (let i = 0; i < 40; i++) lines.push(JSON.stringify({ jsonrpc: '2.0', id: i, result: { pad: 'x'.repeat(9000) } }));
    const file = path.join(dir, 'responses.txt');
    fs.writeFileSync(file, lines.join('\n') + '\n');
    const bytes = fs.statSync(file).size;
    const server = serverFile(`
      require('child_process').spawn('sleep', ['14'], { stdio: ['ignore', 'inherit', 'ignore'], detached: true }).unref();
      require('child_process').spawnSync('cat', [${JSON.stringify(file)}], { stdio: ['ignore', 'inherit', 'ignore'] });
      process.exit(0);`);
    const res = await execa('sh', ['-c', `node "${CLI}" proxy --command node --args "${server}" </dev/null | (sleep 4; wc -lc)`], {
      cwd: dir, reject: false, env: { MCP_SCAN_LOG_DIR: logDir },
    });
    expect(res.stdout.trim().split(/\s+/).map(Number)).toEqual([40, bytes]);
  }, 40000);

  it('gives up on a client that never reads after one stall deadline, not two', async () => {
    const lines: string[] = [];
    for (let i = 0; i < 40; i++) lines.push(JSON.stringify({ jsonrpc: '2.0', id: i, result: { pad: 'x'.repeat(9000) } }));
    const file = path.join(dir, 'responses.txt');
    fs.writeFileSync(file, lines.join('\n') + '\n');
    const server = serverFile(`
      require('child_process').spawn('sleep', ['30'], { stdio: ['ignore', 'inherit', 'ignore'], detached: true }).unref();
      require('child_process').spawnSync('cat', [${JSON.stringify(file)}], { stdio: ['ignore', 'inherit', 'ignore'] });
      process.exit(0);`);
    const stamp = path.join(dir, 'stamp');
    const started = Date.now();
    // the reader holds the pipe open without reading for 14s
    const res = await execa('sh', ['-c', `(node "${CLI}" proxy --command node --args "${server}" </dev/null; node -e "require('fs').writeFileSync('${stamp}', String(Date.now()))") | sleep 14`], {
      cwd: dir, reject: false, env: { MCP_SCAN_LOG_DIR: logDir, MCP_SCAN_STALL_MS: '5000' },
    });
    // 5s stall + about 1s to flush + startup; the old two-stage wait took about 11s
    expect(Number(fs.readFileSync(stamp, 'utf8')) - started).toBeLessThan(8500);
    // and it says what it dropped
    expect(res.stderr).toMatch(/gave up on a client that stopped reading: dropped \d+ bytes/);
    // and when the exit then cuts off output already queued on stdout
    expect(res.stderr).toMatch(/client stopped reading: dropped \d+ bytes of queued output/);
    const reported = Number(res.stderr.match(/client stopped reading: dropped (\d+) bytes of queued output/)![1]);
    // the two queue measures overlap; the figure must not double count
    expect(reported).toBeLessThanOrEqual(fs.statSync(file).size);
  }, 40000);

  it('stops a still-running server whose client never reads, whatever the Node stream defaults', async () => {
    // 4 MB is past what any Node version buffers, so the server blocks on its own write
    const pidFile = path.join(dir, 'pid');
    const server = serverFile(`
      require('fs').writeFileSync(${JSON.stringify(pidFile)}, String(process.pid));
      const line = JSON.stringify({ jsonrpc: '2.0', id: 1, result: { pad: 'x'.repeat(9000) } }) + '\\n';
      for (let i = 0; i < 450; i++) require('fs').writeSync(1, line);
      setTimeout(() => process.exit(0), 30000);`);
    const stamp = path.join(dir, 'stamp');
    const started = Date.now();
    const res = await execa('sh', ['-c', `(node "${CLI}" proxy --command node --args "${server}" </dev/null; node -e "require('fs').writeFileSync('${stamp}', String(Date.now()))") | sleep 14`], {
      cwd: dir, reject: false, env: { MCP_SCAN_LOG_DIR: logDir, MCP_SCAN_STALL_MS: '5000' },
    });
    expect(Number(fs.readFileSync(stamp, 'utf8')) - started).toBeLessThan(8500);
    expect(res.stderr).toMatch(/client stopped reading for 5s: stopping the server/);
    await new Promise(r => setTimeout(r, 300));
    expect(alive(Number(fs.readFileSync(pidFile, 'utf8')))).toBe(false);
  }, 40000);

  it('a slow reader of one huge line is not mistaken for a stalled one', async () => {
    const big = JSON.stringify({ jsonrpc: '2.0', id: 1, result: { pad: 'x'.repeat(4 * 1024 * 1024) } }) + '\n';
    const file = path.join(dir, 'big.txt');
    fs.writeFileSync(file, big);
    const reader = path.join(dir, 'reader.js');
    // about 400 KB/s: 64 KB every 150 ms
    fs.writeFileSync(reader, `let n = 0; process.stdin.on('data', d => { n += d.length; process.stdin.pause(); setTimeout(() => process.stdin.resume(), 150); }); process.stdin.on('end', () => console.log(n));`);
    const res = await execa('sh', ['-c', `node "${CLI}" proxy --command cat --args "${file}" </dev/null | node "${reader}"`], {
      cwd: dir, reject: false, env: { MCP_SCAN_LOG_DIR: logDir, MCP_SCAN_STALL_MS: '3000' },
    });
    expect(Number(res.stdout.trim())).toBe(Buffer.byteLength(big));
  }, 60000);

  it('the stdout stream handle still exposes writeQueueSize as a number on a pipe (the stall net reads it)', async () => {
    const res = await execa('node', ['-e', 'console.log(typeof process.stdout._handle.writeQueueSize)']);
    expect(res.stdout).toBe('number');
  });
});
