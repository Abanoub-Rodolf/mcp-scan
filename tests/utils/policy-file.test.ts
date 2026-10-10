import { describe, it, expect, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { policyFileExists } from '../../src/utils/policy-file.js';

describe('policyFileExists', () => {
  let dir: string;
  afterEach(() => {
    if (dir) { fs.chmodSync(dir, 0o755); fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('is false only when the file is really absent', () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pfe-'));
    expect(policyFileExists(path.join(dir, '.mcp-scan.json'))).toBe(false);
    fs.writeFileSync(path.join(dir, 'blocker'), '');
    expect(policyFileExists(path.join(dir, 'blocker', '.mcp-scan.json'))).toBe(false);
  });

  it('treats a dangling symlink as present', () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pfe-'));
    const link = path.join(dir, '.mcp-scan.json');
    fs.symlinkSync(path.join(dir, 'gone.json'), link);
    expect(policyFileExists(link)).toBe(true);
  });

  // A parent without search permission hides the file from existsSync too;
  // calling that absent would scan with no policy at all.
  it.skipIf(process.getuid?.() === 0 || process.platform === 'win32')('treats a policy behind an unsearchable directory as present', () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pfe-'));
    const p = path.join(dir, '.mcp-scan.json');
    fs.writeFileSync(p, '{}');
    fs.chmodSync(dir, 0o600);
    expect(fs.existsSync(p)).toBe(false);
    expect(policyFileExists(p)).toBe(true);
  });
});

