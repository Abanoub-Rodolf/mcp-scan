import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execa } from 'execa';
import { execSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'node:url';

const CLI = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../dist/index.js');

// Masking that fails closed cannot start from a policy it failed to read.
describe('proxy policy file', () => {
  let dir: string;
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-proxy-policy-')); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  const run = () => {
    const marker = path.join(dir, 'started');
    const server = path.join(dir, 'server.js');
    fs.writeFileSync(server, `require('fs').writeFileSync(${JSON.stringify(marker)}, 'x'); process.stdout.write('{"jsonrpc":"2.0","id":1,"result":{"e":"a@corp.example"}}\\n');`);
    return execa('node', [CLI, 'proxy', '--command', 'node', '--args', server], {
      cwd: dir, reject: false, input: '', env: { MCP_SCAN_LOG_DIR: path.join(dir, 'logs') },
    }).then(res => ({ ...res, started: fs.existsSync(marker) }));
  };

  it('refuses to start, and starts no server, when .mcp-scan.json does not parse', async () => {
    fs.writeFileSync(path.join(dir, '.mcp-scan.json'), '{ "privacy": { "maskPii": true ');
    const res = await run();
    expect(res.exitCode).not.toBe(0);
    expect(res.stdout).toBe('');
    expect(res.started).toBe(false);
    expect(res.stderr).toMatch(/not starting.*\.mcp-scan\.json/is);
  }, 30000);

  it.each([['an array', '[]'], ['a string', '"x"'], ['null', 'null']])('refuses a policy file that parses but is %s', async (_n, body) => {
    fs.writeFileSync(path.join(dir, '.mcp-scan.json'), body);
    const res = await run();
    expect(res.exitCode).not.toBe(0);
    expect(res.started).toBe(false);
  }, 30000);

  it('refuses a .mcp-scan.json that is a dangling symlink', async () => {
    fs.symlinkSync(path.join(dir, 'missing-policy.json'), path.join(dir, '.mcp-scan.json'));
    const res = await run();
    expect(res.exitCode).not.toBe(0);
    expect(res.started).toBe(false);
  }, 30000);

  it('refuses a policy path that is not a regular file, without hanging on it', async () => {
    execSync(`mkfifo "${path.join(dir, '.mcp-scan.json')}"`);
    const res = await run();
    expect(res.exitCode).not.toBe(0);
    expect(res.started).toBe(false);
  }, 15000);

  it('follows a symlink to a valid policy', async () => {
    fs.writeFileSync(path.join(dir, 'real.json'), JSON.stringify({ privacy: { maskPii: true } }));
    fs.symlinkSync(path.join(dir, 'real.json'), path.join(dir, '.mcp-scan.json'));
    const res = await run();
    expect(res.exitCode).toBe(0);
    expect(res.stdout).toContain('[EMAIL_MASKED]');
  }, 30000);

  it('starts normally with a valid policy, or with none', async () => {
    const none = await run();
    expect(none.exitCode).toBe(0);
    expect(none.started).toBe(true);
    fs.rmSync(path.join(dir, 'started'));
    fs.writeFileSync(path.join(dir, '.mcp-scan.json'), JSON.stringify({ privacy: { maskPii: true } }));
    const masked = await run();
    expect(masked.exitCode).toBe(0);
    expect(masked.stdout).toContain('[EMAIL_MASKED]');
  }, 30000);
});
