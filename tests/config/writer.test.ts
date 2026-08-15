import { describe, it, expect } from 'vitest';
import { atomicWriteConfig } from '../../src/config/writer.js';
import fs from 'fs';
import os from 'os';
import path from 'path';

function tmpFile(name: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-writer-'));
  return path.join(dir, name);
}

describe('config/writer', () => {
  it('writes content atomically and preserves existing file mode', () => {
    const file = tmpFile('secret-config.json');
    fs.writeFileSync(file, '{"a":1}', { mode: 0o600 });

    atomicWriteConfig(file, '{"a":2}');

    expect(fs.readFileSync(file, 'utf8')).toBe('{"a":2}');
    const mode = fs.statSync(file).mode & 0o777;
    expect(mode).toBe(0o600);
    fs.rmSync(path.dirname(file), { recursive: true, force: true });
  });

  it('keeps a timestamped backup of the previous content', () => {
    const file = tmpFile('cfg.json');
    fs.writeFileSync(file, '{"old":true}');

    atomicWriteConfig(file, '{"new":true}');

    const backups = fs.readdirSync(path.dirname(file)).filter(f => f.startsWith('cfg.json.backup-'));
    expect(backups.length).toBe(1);
    expect(fs.readFileSync(path.join(path.dirname(file), backups[0]), 'utf8')).toBe('{"old":true}');
    fs.rmSync(path.dirname(file), { recursive: true, force: true });
  });

  it('replaces the symlink target, not the link itself', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-writer-'));
    const real = path.join(dir, 'real.json');
    const link = path.join(dir, 'link.json');
    fs.writeFileSync(real, '{"v":1}');
    fs.symlinkSync(real, link);

    atomicWriteConfig(link, '{"v":2}');

    expect(fs.lstatSync(link).isSymbolicLink()).toBe(true);
    expect(fs.readFileSync(real, 'utf8')).toBe('{"v":2}');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('creates missing parent directories', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-writer-'));
    const file = path.join(dir, 'nested', 'deep', 'cfg.json');

    atomicWriteConfig(file, '{"ok":1}');

    expect(fs.readFileSync(file, 'utf8')).toBe('{"ok":1}');
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
