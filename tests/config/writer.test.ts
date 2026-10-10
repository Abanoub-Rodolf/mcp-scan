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

  it('keeps only the newest backups when keepBackups is set', () => {
    const file = tmpFile('known-servers.json');
    const dir = path.dirname(file);
    fs.writeFileSync(file, '{"v":0}');
    for (let i = 1; i <= 8; i++) fs.writeFileSync(`${file}.backup-${1000 + i}`, `{"v":${i}}`);
    fs.writeFileSync(path.join(dir, 'other.json.backup-1001'), 'x');
    fs.writeFileSync(`${file}.backup-notes`, 'x');

    atomicWriteConfig(file, '{"v":9}', { keepBackups: 5 });

    const left = fs.readdirSync(dir).filter(f => /^known-servers\.json\.backup-\d+$/.test(f)).sort();
    expect(left.length).toBe(5);
    // The backup this write just made is the newest, so it survives the cut.
    expect(left.map(f => fs.readFileSync(path.join(dir, f), 'utf8'))).toContain('{"v":0}');
    expect(left).not.toContain('known-servers.json.backup-1004');
    expect(fs.existsSync(path.join(dir, 'other.json.backup-1001'))).toBe(true);
    expect(fs.existsSync(`${file}.backup-notes`)).toBe(true);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('keeps the backup it just made even when older ones carry later stamps', () => {
    const file = tmpFile('known-servers.json');
    const dir = path.dirname(file);
    fs.writeFileSync(file, '{"v":0}');
    // A clock that stepped back leaves stamps newer than Date.now().
    const ahead = Date.now() + 86_400_000;
    for (let i = 1; i <= 3; i++) fs.writeFileSync(`${file}.backup-${ahead + i}`, `{"v":${i}}`);

    atomicWriteConfig(file, '{"v":9}', { keepBackups: 2 });

    const left = fs.readdirSync(dir).filter(f => /^known-servers\.json\.backup-\d+$/.test(f));
    expect(left.length).toBe(2);
    expect(left.map(f => fs.readFileSync(path.join(dir, f), 'utf8'))).toContain('{"v":0}');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('never prunes backups unless asked', () => {
    const file = tmpFile('cfg.json');
    fs.writeFileSync(file, '{}');
    for (let i = 1; i <= 8; i++) fs.writeFileSync(`${file}.backup-${1000 + i}`, '{}');

    atomicWriteConfig(file, '{"a":1}');

    const left = fs.readdirSync(path.dirname(file)).filter(f => f.startsWith('cfg.json.backup-'));
    expect(left.length).toBe(9);
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
