import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { badgeHint, findBadgeablePackage } from '../src/utils/repo-hint.js';
import { ScanReport, ServerScanResult } from '../src/types/scan-result.js';

function fakeStream(isTTY: boolean) {
  const writes: string[] = [];
  return {
    stream: { isTTY, write: (s: string) => { writes.push(s); return true; } } as unknown as NodeJS.WriteStream,
    writes,
  };
}

// repoHint keeps a module-level "shown this process" flag so a read-only
// home (marker write fails) doesn't reprint on every findings scan. Reset
// the module between tests so that flag doesn't leak across cases.
async function freshRepoHint() {
  vi.resetModules();
  const mod = await import('../src/utils/repo-hint.js');
  return mod.repoHint;
}

describe('repoHint', () => {
  let tmpHome: string;

  beforeEach(() => {
    // Marker lives under MCP_SCAN_HOME (auditDir()); redirect it to a temp
    // dir per test so the real ~/.mcp-scan is never touched.
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-repo-hint-'));
    process.env.MCP_SCAN_HOME = tmpHome;
  });

  afterEach(() => {
    delete process.env.MCP_SCAN_HOME;
    delete process.env.MCP_SCAN_NO_HINTS;
    // Restore permissions before recursive removal in case a test locked the dir down.
    fs.chmodSync(tmpHome, 0o700);
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  it('writes exactly one line containing the repo URL on first call with findings', async () => {
    const repoHint = await freshRepoHint();
    const { stream, writes } = fakeStream(true);
    repoHint(true, stream);
    expect(writes).toHaveLength(1);
    expect(writes[0]).toContain('github.com/Abanoub-Rodolf/mcp-scan');
  });

  it('writes nothing on a second call once the marker exists', async () => {
    const repoHint = await freshRepoHint();
    const { stream: first } = fakeStream(true);
    repoHint(true, first);

    const { stream: second, writes: secondWrites } = fakeStream(true);
    repoHint(true, second);
    expect(secondWrites).toHaveLength(0);
  });

  it('stays silent when the stream is not a TTY, and never claims the marker', async () => {
    const repoHint = await freshRepoHint();
    const { stream, writes } = fakeStream(false);
    repoHint(true, stream);
    expect(writes).toHaveLength(0);

    const markerPath = path.join(tmpHome, 'repo-hint-shown');
    expect(fs.existsSync(markerPath)).toBe(false);
  });

  it('respects MCP_SCAN_NO_HINTS', async () => {
    const repoHint = await freshRepoHint();
    process.env.MCP_SCAN_NO_HINTS = '1';
    const { stream, writes } = fakeStream(true);
    repoHint(true, stream);
    expect(writes).toHaveLength(0);
  });

  it('stays silent when there are no findings', async () => {
    const repoHint = await freshRepoHint();
    const { stream, writes } = fakeStream(true);
    repoHint(false, stream);
    expect(writes).toHaveLength(0);
  });

  it('swallows a read-only home without throwing and without printing twice in one process', async () => {
    const repoHint = await freshRepoHint();
    // Lock the marker directory down so mkdirSync/writeFileSync inside
    // repoHint hit EACCES, simulating a read-only $HOME.
    fs.chmodSync(tmpHome, 0o500);

    const { stream: first, writes: firstWrites } = fakeStream(true);
    expect(() => repoHint(true, first)).not.toThrow();
    expect(firstWrites).toHaveLength(1);

    // Marker write failed, but the module-level flag still caps it at
    // once per process: a second qualifying call in the same process
    // must not print again.
    const { stream: second, writes: secondWrites } = fakeStream(true);
    expect(() => repoHint(true, second)).not.toThrow();
    expect(secondWrites).toHaveLength(0);
  });
});

function fakeResult(overrides: Partial<ServerScanResult> = {}): ServerScanResult {
  return {
    serverName: 'server',
    toolName: 'claude-desktop',
    configPath: '/config.json',
    findings: [],
    scanDurationMs: 1,
    ...overrides,
  };
}

function fakeReport(results: ServerScanResult[]): ScanReport {
  return {
    results,
    totalScanned: results.length,
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    infoCount: 0,
    totalDurationMs: 1,
  };
}

describe('findBadgeablePackage', () => {
  it('returns the package name for an npx server', () => {
    const report = fakeReport([fakeResult({ connection: { command: 'npx', args: ['@modelcontextprotocol/server-filesystem', '/tmp'] } })]);
    expect(findBadgeablePackage(report)).toBe('@modelcontextprotocol/server-filesystem');
  });

  it('returns the first valid package across multiple servers', () => {
    const report = fakeReport([
      fakeResult({ serverName: 'a', connection: { command: 'node', args: ['/usr/local/bin/server.js'] } }),
      fakeResult({ serverName: 'b', connection: { command: 'npx', args: ['-y', 'good-package'] } }),
    ]);
    expect(findBadgeablePackage(report)).toBe('good-package');
  });

  it('returns undefined when no server runs via npx/npm/node', () => {
    const report = fakeReport([fakeResult({ connection: { command: 'python', args: ['server.py'] } })]);
    expect(findBadgeablePackage(report)).toBeUndefined();
  });

  it('returns undefined when the only candidate arg is a file path, not a package spec', () => {
    const report = fakeReport([fakeResult({ connection: { command: 'node', args: ['/usr/local/bin/server.js'] } })]);
    expect(findBadgeablePackage(report)).toBeUndefined();
  });

  it('returns undefined for a bare local entrypoint (node index.js)', () => {
    const report = fakeReport([fakeResult({ connection: { command: 'node', args: ['index.js'] } })]);
    expect(findBadgeablePackage(report)).toBeUndefined();
  });

  it('returns undefined for a bare local entrypoint (node server.mjs)', () => {
    const report = fakeReport([fakeResult({ connection: { command: 'node', args: ['server.mjs'] } })]);
    expect(findBadgeablePackage(report)).toBeUndefined();
  });

  it('returns undefined for a bare local entrypoint (node main.cjs)', () => {
    const report = fakeReport([fakeResult({ connection: { command: 'node', args: ['main.cjs'] } })]);
    expect(findBadgeablePackage(report)).toBeUndefined();
  });

  it('returns undefined for a nested relative entrypoint (node dist/index.js)', () => {
    const report = fakeReport([fakeResult({ connection: { command: 'node', args: ['dist/index.js'] } })]);
    expect(findBadgeablePackage(report)).toBeUndefined();
  });

  it('returns undefined for a relative entrypoint with no extension but a path separator', () => {
    const report = fakeReport([fakeResult({ connection: { command: 'node', args: ['dist/index'] } })]);
    expect(findBadgeablePackage(report)).toBeUndefined();
  });

  it('rejects a local entrypoint even under npx/npm, not just node', () => {
    const report = fakeReport([fakeResult({ connection: { command: 'npx', args: ['./local-server.js'] } })]);
    expect(findBadgeablePackage(report)).toBeUndefined();
  });

  it('returns the --package value, not the bin name, for npx --package=<pkg> <bin>', () => {
    const report = fakeReport([fakeResult({ connection: { command: 'npx', args: ['--package=good-package', 'some-bin'] } })]);
    expect(findBadgeablePackage(report)).toBe('good-package');
  });

  it('returns the --package value, not the bin name, for npx --package <pkg> <bin>', () => {
    const report = fakeReport([fakeResult({ connection: { command: 'npx', args: ['--package', 'good-package', 'some-bin'] } })]);
    expect(findBadgeablePackage(report)).toBe('good-package');
  });

  it('returns the -p value, not the bin name, for npx -p <pkg> <bin>', () => {
    const report = fakeReport([fakeResult({ connection: { command: 'npx', args: ['-p', 'good-package', 'some-bin'] } })]);
    expect(findBadgeablePackage(report)).toBe('good-package');
  });

  it('returns the scoped --package value ahead of an earlier flag', () => {
    const report = fakeReport([fakeResult({ connection: { command: 'npx', args: ['-y', '--package=@scope/name', 'bin'] } })]);
    expect(findBadgeablePackage(report)).toBe('@scope/name');
  });

  it('returns undefined for an empty report', () => {
    expect(findBadgeablePackage(fakeReport([]))).toBeUndefined();
  });
});

describe('badgeHint', () => {
  afterEach(() => { delete process.env.MCP_SCAN_NO_HINTS; });

  it('writes one line naming the package when a package is given', () => {
    const { stream, writes } = fakeStream(true);
    badgeHint('mcp-scan', stream);
    expect(writes).toHaveLength(1);
    expect(writes[0]).toContain('npx mcp-scan badge mcp-scan');
  });

  it('stays silent when there is no package', () => {
    const { stream, writes } = fakeStream(true);
    badgeHint(undefined, stream);
    expect(writes).toHaveLength(0);
  });

  it('stays silent when the stream is not a TTY', () => {
    const { stream, writes } = fakeStream(false);
    badgeHint('mcp-scan', stream);
    expect(writes).toHaveLength(0);
  });

  it('respects MCP_SCAN_NO_HINTS', () => {
    process.env.MCP_SCAN_NO_HINTS = '1';
    const { stream, writes } = fakeStream(true);
    badgeHint('mcp-scan', stream);
    expect(writes).toHaveLength(0);
  });
});
