import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../../src/commands/scan.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(here, '../../dist/index.js');
const FIXTURE = path.resolve(here, '../fixtures/valid-config.json');

describe('baseline.key that is not a regular file', () => {
  let home: string;
  const keyPath = () => path.join(home, 'baseline.key');
  const cli = (...args: string[]) => spawnSync(process.execPath, [CLI, ...args], {
    env: { ...process.env, MCP_SCAN_HOME: home },
    timeout: 20000,
    encoding: 'utf8',
  });

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-keypath-'));
    process.env.MCP_SCAN_HOME = home;
  });
  afterEach(() => {
    delete process.env.MCP_SCAN_HOME;
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('scan exits nonzero with a message naming the key and the fix, and scans nothing', () => {
    fs.mkdirSync(keyPath());
    const res = cli('--config', FIXTURE, '--offline', '--json');
    expect(res.status).toBe(1);
    expect(res.stdout).toBe('');
    expect(res.stderr).toContain(keyPath());
    expect(res.stderr).toMatch(/is a directory/);
    expect(res.stderr).toMatch(/move or remove/i);
    expect(res.stderr).not.toMatch(/\n\s+at /); // no stack trace
    expect(fs.existsSync(path.join(home, 'audit.log'))).toBe(false);
    expect(fs.existsSync(path.join(home, 'known-servers.json'))).toBe(false);
    expect(fs.statSync(keyPath()).isDirectory()).toBe(true); // left alone
  });

  it('ci exits nonzero too', () => {
    fs.mkdirSync(keyPath());
    const res = cli('ci', '--config', FIXTURE, '--offline');
    expect(res.status).toBe(1);
    expect(res.stderr).toMatch(/baseline\.key.*is a directory/);
  });

  it('runScan rejects with BaselineKeyError before doing any work', async () => {
    fs.mkdirSync(keyPath());
    await expect(runScan({ config: FIXTURE, offline: true, silent: true }))
      .rejects.toMatchObject({ name: 'BaselineKeyError', message: expect.stringContaining('is a directory') });
    expect(fs.existsSync(path.join(home, 'audit.log'))).toBe(false);
  });

  it.skipIf(process.platform === 'win32')('a FIFO key is refused, not waited on', () => {
    expect(spawnSync('mkfifo', [keyPath()]).status).toBe(0);
    const res = cli('--config', FIXTURE, '--offline', '--json');
    expect(res.error).toBeUndefined();
    expect(res.status).toBe(1);
    expect(res.stderr).toMatch(/baseline\.key.*not a regular file/);
  });

  it('a normal first run still creates a key and exits 0', () => {
    const res = cli('--config', FIXTURE, '--offline', '--json');
    expect(res.status).toBe(0);
    expect(fs.statSync(keyPath()).isFile()).toBe(true);
  });
});
