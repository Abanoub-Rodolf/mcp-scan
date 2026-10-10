import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
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
  const descPidFile = () => path.join(dir, 'descendant-pid');
  afterEach(() => {
    // a descendant that outlives the proxy on purpose must not outlive the test
    try { process.kill(Number(fs.readFileSync(descPidFile(), 'utf8')), 'SIGKILL'); } catch { /* none, or already gone */ }
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const serverFile = (src: string) => {
    const p = path.join(dir, 'server.js');
    fs.writeFileSync(p, src);
    return p;
  };
  const alive = (pid: number) => { try { process.kill(pid, 0); return true; } catch { return false; } };
  // Polls ok() until it holds or the shared deadline `stop` passes.
  const until = (stop: number, what: string, ok: () => boolean) =>
    vi.waitFor(() => { if (!ok()) throw new Error(`timed out waiting for ${what}`); }, { timeout: Math.max(1, stop - Date.now()), interval: 10 });
  // A server that exits while a descendant keeps its stdout open. The descendant
  // outlives every deadline below, so a proxy that finished before its deadline
  // did not wait for it, whatever the host's load.
  const holder = (tail: string) => serverFile(`
      const c = require('child_process').spawn('sleep', ['60'], { stdio: ['ignore', 'inherit', 'ignore'], detached: true });
      c.unref();
      require('fs').writeFileSync(${JSON.stringify(descPidFile())}, String(c.pid));
      ${tail}
      process.exit(0);`);

  it('exits promptly when the server exits but a descendant keeps its stdout open', async () => {
    const server = holder(`process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { ok: true } }) + '\\n');`);
    const res = await execa('node', [CLI, 'proxy', '--command', 'node', '--args', server], {
      cwd: dir, reject: false, input: '', env: { MCP_SCAN_LOG_DIR: logDir }, timeout: 25000,
    });
    expect(res.timedOut).toBe(false);
    // the proxy is gone while the descendant still holds the pipe
    expect(alive(Number(fs.readFileSync(descPidFile(), 'utf8')))).toBe(true);
    expect(res.exitCode).toBe(0);
    expect(JSON.parse(res.stdout.trim())).toMatchObject({ id: 1, result: { ok: true } });
  }, 30000);

  it('shuts the server down when the client goes away (stdout closed)', async () => {
    const pidFile = path.join(dir, 'pid');
    const server = serverFile(`
      require('fs').writeFileSync(${JSON.stringify(pidFile)}, String(process.pid));
      // survive its own broken pipe, so only the proxy can end it
      process.stdout.on('error', () => {});
      setInterval(() => {
        if (!require('fs').existsSync(${JSON.stringify(dir)})) process.exit(0);
        process.stdout.write(JSON.stringify({ jsonrpc: '2.0', method: 'tick', params: { pad: 'x'.repeat(2000) } }) + '\\n');
      }, 20);
      setTimeout(() => process.exit(0), 60000);`);
    const res = await execa('sh', ['-c', `node "${CLI}" proxy --command node --args "${server}" </dev/null | head -c 10 >/dev/null`], {
      cwd: dir, reject: false, env: { MCP_SCAN_LOG_DIR: logDir }, timeout: 25000,
    });
    expect(res.timedOut).toBe(false);
    // the server's own exit is 60s out, so only the proxy can end it inside this deadline
    const pid = Number(fs.readFileSync(pidFile, 'utf8'));
    await vi.waitFor(() => expect(alive(pid)).toBe(false), { timeout: 20000, interval: 25 });
  }, 60000);

  it('answers every request in a pipelined burst that meets the broken pipe, not just the ones after it', async () => {
    const closed = path.join(dir, 'server-closed-stdin');
    const release = path.join(dir, 'release');
    const server = serverFile(`
      const fs = require('fs');
      fs.closeSync(0);
      fs.writeFileSync(${JSON.stringify(closed)}, '1');
      setInterval(() => { if (fs.existsSync(${JSON.stringify(release)}) || !fs.existsSync(${JSON.stringify(dir)})) process.exit(0); }, 20);
      setTimeout(() => process.exit(0), 40000);`);
    const proc = execa('node', [CLI, 'proxy', '--command', 'node', '--args', server], {
      cwd: dir, reject: false, env: { MCP_SCAN_LOG_DIR: logDir }, stdin: 'pipe',
    });
    let out = '';
    proc.stdout!.on('data', d => { out += d; });
    proc.stdin!.on('error', () => {});
    const stop = Date.now() + 25000;
    const ids = () => out.split('\n').slice(0, -1).filter(Boolean).map(l => JSON.parse(l)).flat().map((r: any) => r.id);
    // backstop: a hung proxy fails the test here instead of at vitest's timeout
    const kill = setTimeout(() => proc.kill('SIGKILL'), 30000);
    kill.unref();
    let res;
    try {
      await until(stop, 'the server to close its stdin', () => fs.existsSync(closed));
      // one write: every line is forwarded before the first EPIPE comes back
      proc.stdin!.write([
        { jsonrpc: '2.0', id: 1, method: 'x' },
        { jsonrpc: '2.0', method: 'notifications/ping' },
        { jsonrpc: '2.0', id: 'two', method: 'x' },
        [{ jsonrpc: '2.0', id: 3, method: 'x' }, { jsonrpc: '2.0', method: 'n' }],
      ].map(m => JSON.stringify(m)).join('\n') + '\n');
      await until(stop, 'a reply to every request', () => ids().length >= 3);
    } finally {
      proc.stdin!.end();
      fs.writeFileSync(release, '1');
      res = await proc;
      clearTimeout(kill);
    }
    const replies = res.stdout.split('\n').filter(Boolean).map(l => JSON.parse(l));
    expect(replies.flat().map((r: any) => r.id).sort()).toEqual([1, 3, 'two']);
    for (const r of replies.flat()) expect(r).toMatchObject({ jsonrpc: '2.0', error: { code: -32603 } });
    // the batch is answered as a batch
    expect(replies.find(r => Array.isArray(r))).toEqual([expect.objectContaining({ id: 3 })]);
    expect(res.stderr).not.toMatch(/Unhandled|node:events/);
  }, 60000);

  it('answers requests that arrive after the server closed its stdin, with their own id, and ignores notifications', async () => {
    // Every step waits on an observable event instead of a sleep: how long node
    // takes to start the proxy and the server depends on the host's load.
    const closed = path.join(dir, 'server-closed-stdin');
    const release = path.join(dir, 'release');
    const server = serverFile(`
      const fs = require('fs');
      fs.closeSync(0);
      fs.writeFileSync(${JSON.stringify(closed)}, '1');
      // a vanished test dir counts as release too, so a failed run never leaves it waiting
      setInterval(() => { if (fs.existsSync(${JSON.stringify(release)}) || !fs.existsSync(${JSON.stringify(dir)})) process.exit(0); }, 20);
      setTimeout(() => process.exit(0), 40000);`);
    const proc = execa('node', [CLI, 'proxy', '--command', 'node', '--args', server], {
      cwd: dir, reject: false, env: { MCP_SCAN_LOG_DIR: logDir }, stdin: 'pipe',
    });
    let out = '';
    let err = '';
    proc.stdout!.on('data', d => { out += d; });
    proc.stderr!.on('data', d => { err += d; });
    // an early proxy death should fail on the waits below, not as an unhandled EPIPE
    proc.stdin!.on('error', () => {});
    // one deadline for every wait, well inside the test timeout
    const stop = Date.now() + 25000;
    const send = (m: object) => proc.stdin!.write(JSON.stringify(m) + '\n');
    const ids = () => out.split('\n').slice(0, -1).filter(Boolean).map(l => JSON.parse(l)).flat().map((r: any) => r.id);

    let res;
    try {
      await until(stop, 'the server to close its stdin', () => fs.existsSync(closed));
      send({ jsonrpc: '2.0', id: 1, method: 'x' }); // meets the broken pipe
      await until(stop, 'the proxy to hit the broken pipe', () => /server stdin is no longer writable/.test(err));
      send({ jsonrpc: '2.0', id: 2, method: 'x' });
      send({ jsonrpc: '2.0', method: 'notifications/ping' });
      send({ jsonrpc: '2.0', id: 'three', method: 'x' });
      send([{ jsonrpc: '2.0', id: 4, method: 'x' }, { jsonrpc: '2.0', method: 'n' }]);
      // The batch is the last line sent, and lines are handled in order, so its
      // reply means everything before it, the notification included, is done.
      await until(stop, 'the reply to the last request', () => ids().includes(4));
    } finally {
      // also on a failed wait, so no proxy outlives the test
      proc.stdin!.end();
      fs.writeFileSync(release, '1');
      res = await proc;
    }
    const replies = res.stdout.split('\n').filter(Boolean).map(l => JSON.parse(l));
    const flat = replies.flat();
    // id 1 met the broken pipe on its way in, so it is answered too
    expect(flat.map((r: any) => r.id).sort()).toEqual([1, 2, 4, 'three']);
    for (const r of flat) expect(r).toMatchObject({ jsonrpc: '2.0', error: { code: -32603 } });
    expect(Array.isArray(replies[replies.length - 1])).toBe(true);
    expect(res.stderr).not.toMatch(/Unhandled|node:events/);
  }, 60000);

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

  it('still exits, abandoning the fragment, when only a descendant holds the stdout open', async () => {
    const server = holder(`process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { ok: true } }) + '\\n' + '{"partial":');`);
    const res = await execa('node', [CLI, 'proxy', '--command', 'node', '--args', server], {
      cwd: dir, reject: false, input: '', env: { MCP_SCAN_LOG_DIR: logDir }, timeout: 25000,
    });
    expect(res.timedOut).toBe(false);
    expect(alive(Number(fs.readFileSync(descPidFile(), 'utf8')))).toBe(true);
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
      require('child_process').spawn('cat', [${JSON.stringify(file)}], { stdio: ['ignore', 'inherit', 'ignore'], detached: true }).unref();
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
    // cat is detached so the server exits at once whatever the proxy has read:
    // with spawnSync it blocked on a full pipe, and how soon that happens depends
    // on the Node version's stream buffer sizes (16 KiB on 20, 64 KiB on 22)
    const server = serverFile(`
      require('child_process').spawn('sleep', ['30'], { stdio: ['ignore', 'inherit', 'ignore'], detached: true }).unref();
      require('child_process').spawn('cat', [${JSON.stringify(file)}], { stdio: ['ignore', 'inherit', 'ignore'], detached: true }).unref();
      process.exit(0);`);
    // The reader holds the pipe open without reading for 14s. Two notes mark the
    // proxy's two stages: giving up on the unread server output (after the stall
    // deadline), then cutting off what is queued on stdout. Both stages share one
    // deadline, so the second note follows the first by about a flush (1s); a
    // fresh deadline would put it a whole stall (5s) later. The gap between two
    // lines of the same process, not the time since the test started, so a slow
    // host moves both and leaves the gap alone.
    const proc = execa('sh', ['-c', `node "${CLI}" proxy --command node --args "${server}" </dev/null | sleep 14`], {
      cwd: dir, reject: false, env: { MCP_SCAN_LOG_DIR: logDir, MCP_SCAN_STALL_MS: '5000' }, timeout: 35000,
    });
    let seen = '';
    const at: Record<string, number> = {};
    proc.stderr!.on('data', d => {
      seen += d;
      if (!at.gaveUp && /gave up on a client that stopped reading/.test(seen)) at.gaveUp = Date.now();
      if (!at.cut && /client stopped reading: dropped \d+ bytes of queued output/.test(seen)) at.cut = Date.now();
    });
    const res = await proc;
    expect(res.timedOut).toBe(false);
    expect(at.gaveUp).toBeDefined();
    expect(at.cut).toBeDefined();
    expect(at.cut - at.gaveUp).toBeLessThan(3000);
    // and it says what it dropped
    expect(res.stderr).toMatch(/gave up on a client that stopped reading: dropped \d+ bytes/);
    // and when the exit then cuts off output already queued on stdout
    expect(res.stderr).toMatch(/client stopped reading: dropped \d+ bytes of queued output/);
    const reported = Number(res.stderr.match(/client stopped reading: dropped (\d+) bytes of queued output/)![1]);
    // the two queue measures overlap; the figure must not double count
    expect(reported).toBeLessThanOrEqual(fs.statSync(file).size);
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
