import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../../src/commands/scan.js';
import { logScan, BaselineKeyError } from '../../src/utils/audit-logger.js';
import * as lib from '../../src/lib.js';
import type { ScanReport } from '../../src/types/scan-result.js';

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

  // assertBaselineKeyUsable() runs once up front; a path swapped in after it
  // reaches loadOrCreateKey, which must refuse rather than delete it.
  const emptyReport: ScanReport = {
    results: [], totalScanned: 0, criticalCount: 0, highCount: 0, mediumCount: 0,
    lowCount: 0, infoCount: 0, totalDurationMs: 1, version: 'test',
  };

  // logScan swallows write-side errors by design (the scan already ran), so
  // the observable contract is: the path survives and no baseline is signed.
  const lastLine = () => JSON.parse(fs.readFileSync(path.join(home, 'audit.log'), 'utf8').trim().split('\n').pop()!);

  it('logScan leaves a directory key alone and signs nothing', () => {
    fs.mkdirSync(keyPath());
    logScan(emptyReport);
    expect(fs.statSync(keyPath()).isDirectory()).toBe(true);
    expect(lastLine().baselineSigned).toBe(false);
    expect(fs.existsSync(path.join(home, 'known-servers.json'))).toBe(false);
  });

  it.skipIf(process.platform === 'win32')('logScan does not delete a FIFO key swapped in after the up-front check', () => {
    expect(spawnSync('mkfifo', [keyPath()]).status).toBe(0);
    logScan(emptyReport);
    expect(fs.lstatSync(keyPath()).isFIFO()).toBe(true);
    expect(lastLine().baselineSigned).toBe(false);
  });

  it('a corrupt regular-file key is still replaced', () => {
    fs.writeFileSync(keyPath(), 'not a key');
    logScan(emptyReport);
    expect(fs.readFileSync(keyPath(), 'utf8').trim()).toMatch(/^[0-9a-f]{64}$/);
  });

  it('the library entry exports the same BaselineKeyError that runScan rejects with', async () => {
    expect(lib.BaselineKeyError).toBe(BaselineKeyError);
    fs.mkdirSync(keyPath());
    await expect(lib.runScan({ config: FIXTURE, offline: true, silent: true })).rejects.toBeInstanceOf(lib.BaselineKeyError);
  });
});
