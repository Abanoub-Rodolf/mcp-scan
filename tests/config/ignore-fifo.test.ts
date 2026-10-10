import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'node:url';
import { loadIgnoreList } from '../../src/config/parser.js';

const CLI = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../dist/index.js');
const FIXTURE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../fixtures/valid-config.json');

describe('.mcp-scan-ignore that is not a regular file', () => {
  let dir: string;
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-ignore-')); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('reads a regular ignore file as before, comments and blanks dropped', () => {
    fs.writeFileSync(path.join(dir, '.mcp-scan-ignore'), '# note\nunverified-source\n\n  srv  \n');
    expect(loadIgnoreList(dir)).toEqual(['unverified-source', 'srv']);
  });

  it('follows a symlink to a regular file', () => {
    fs.writeFileSync(path.join(dir, 'real'), 'a-rule\n');
    fs.symlinkSync('real', path.join(dir, '.mcp-scan-ignore'));
    expect(loadIgnoreList(dir)).toEqual(['a-rule']);
  });

  it('skips a directory without throwing', () => {
    fs.mkdirSync(path.join(dir, '.mcp-scan-ignore'));
    expect(loadIgnoreList(dir)).toEqual([]);
  });

  // The FIFO case blocks the whole thread in readFileSync, so it runs in a
  // child process with a hard timeout; in-process a regression would hang the runner.
  it.skipIf(process.platform === 'win32')('does not hang on a FIFO: the scan finishes and applies no suppressions', () => {
    const fifo = path.join(dir, '.mcp-scan-ignore');
    const mk = spawnSync('mkfifo', [fifo]);
    expect(mk.status).toBe(0);
    const home = path.join(dir, 'home');
    fs.mkdirSync(home);
    const res = spawnSync(process.execPath, [CLI, '--config', FIXTURE, '--offline', '--json'], {
      cwd: dir,
      env: { ...process.env, MCP_SCAN_HOME: home },
      timeout: 20000,
      encoding: 'utf8',
    });
    expect(res.error, 'scan timed out on the FIFO').toBeUndefined();
    expect(res.signal).toBeNull();
    expect(res.status).toBe(0);
    expect(() => JSON.parse(res.stdout)).not.toThrow();
    expect(res.stderr).toMatch(/\.mcp-scan-ignore.*not a regular file/);
  });

  it('ci runs silent, so no ignore-list notice reaches its stderr', () => {
    fs.mkdirSync(path.join(dir, '.mcp-scan-ignore'));
    const home = path.join(dir, 'home');
    fs.mkdirSync(home);
    const res = spawnSync(process.execPath, [CLI, 'ci', '--config', FIXTURE, '--offline'], {
      cwd: dir,
      env: { ...process.env, MCP_SCAN_HOME: home },
      timeout: 20000,
      encoding: 'utf8',
    });
    expect(res.error).toBeUndefined();
    expect(res.stderr).not.toMatch(/ignoring/);
  });

  describe('skip notice', () => {
    let err: ReturnType<typeof vi.spyOn>;
    beforeEach(() => { err = vi.spyOn(process.stderr, 'write').mockImplementation(() => true); });
    afterEach(() => { err.mockRestore(); });
    const notices = () => err.mock.calls.filter(c => String(c[0]).includes('.mcp-scan-ignore'));

    it('stays quiet when the caller asked for silent', () => {
      fs.mkdirSync(path.join(dir, '.mcp-scan-ignore'));
      expect(loadIgnoreList(dir, { silent: true })).toEqual([]);
      expect(notices()).toHaveLength(0);
    });

    it('prints once per process for the same path, not on every rescan', () => {
      fs.mkdirSync(path.join(dir, '.mcp-scan-ignore'));
      loadIgnoreList(dir);
      loadIgnoreList(dir);
      loadIgnoreList(dir, { silent: true });
      expect(notices()).toHaveLength(1);
    });

    it('says nothing when the file simply does not exist', () => {
      expect(loadIgnoreList(dir)).toEqual([]);
      expect(notices()).toHaveLength(0);
    });
  });
});
