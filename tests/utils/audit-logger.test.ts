import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { checkFingerprints, logScan } from '../../src/utils/audit-logger.js';
import { ScanReport, ServerScanResult } from '../../src/types/scan-result.js';

function server(args: string[], version?: string, pkg = 'pkg'): ServerScanResult {
  return {
    serverName: 'files',
    toolName: 'Cursor',
    configPath: '/tmp/none',
    findings: [],
    scanDurationMs: 1,
    connection: { command: 'npx', args, type: 'stdio', env: [] },
    // Offline scans still know the package name; only the version is missing.
    metadata: { packageName: pkg, ...(version ? { version } : {}) },
  };
}

function report(results: ServerScanResult[]): ScanReport {
  return {
    results, totalScanned: results.length, criticalCount: 0, highCount: 0,
    mediumCount: 0, lowCount: 0, infoCount: 0, totalDurationMs: 1, version: 'test',
  };
}

describe('tamper store', () => {
  let home: string;
  let store: string;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-audit-'));
    store = path.join(home, 'known-servers.json');
    process.env.MCP_SCAN_HOME = home;
  });

  afterEach(() => {
    delete process.env.MCP_SCAN_HOME;
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('flags a changed server when the store is healthy', () => {
    logScan(report([server(['-y', 'pkg'])]));
    const found = checkFingerprints([server(['-y', 'pkg', '--evil'])]);
    expect(found['Cursor:files']?.[0].id).toBe('server-mutation');
  });

  it('reports every server when the store is corrupt, instead of passing them', () => {
    fs.writeFileSync(store, '{ not json');
    const found = checkFingerprints([server(['-y', 'pkg'])]);
    expect(found['Cursor:files']?.[0].id).toBe('server-mutation');
    expect(found['Cursor:files']?.[0].description).toMatch(/unreadable or corrupt/);
  });

  it('treats a store with the wrong shape as corrupt', () => {
    fs.writeFileSync(store, JSON.stringify({ 'Cursor:files': 42 }));
    expect(checkFingerprints([server(['-y', 'pkg'])])['Cursor:files']).toBeDefined();
    fs.writeFileSync(store, '[]');
    expect(checkFingerprints([server(['-y', 'pkg'])])['Cursor:files']).toBeDefined();
  });

  it('treats an unreadable store as corrupt', () => {
    fs.mkdirSync(store);
    expect(checkFingerprints([server(['-y', 'pkg'])])['Cursor:files']).toBeDefined();
  });

  it('quarantines the bad file and rebuilds a baseline for the next run', () => {
    fs.writeFileSync(store, '{ not json');
    const results = [server(['-y', 'pkg'])];
    expect(checkFingerprints(results)['Cursor:files']).toBeDefined();

    const aside = fs.readdirSync(home).filter(f => f.startsWith('known-servers.json.corrupt-'));
    expect(aside.length).toBe(1);

    logScan(report(results));
    expect(() => JSON.parse(fs.readFileSync(store, 'utf8'))).not.toThrow();
    expect(checkFingerprints(results)).toEqual({});
    expect(checkFingerprints([server(['-y', 'pkg', '--evil'])])['Cursor:files']).toBeDefined();
  });

  it('stays quiet on a first run with no store', () => {
    expect(checkFingerprints([server(['-y', 'pkg'])])).toEqual({});
  });
});

describe('fingerprint scope', () => {
  let home: string;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-audit-fp-'));
    process.env.MCP_SCAN_HOME = home;
  });

  afterEach(() => {
    delete process.env.MCP_SCAN_HOME;
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('flags a patch bump of the same package at MEDIUM, not LOW', () => {
    logScan(report([server(['-y', 'pkg'], '1.0.0')]));
    const f = checkFingerprints([server(['-y', 'pkg'], '1.0.1')])['Cursor:files'];
    expect(f?.[0]).toMatchObject({ id: 'server-mutation', severity: 'MEDIUM' });
    expect(f?.[0].description).toContain('1.0.0 -> 1.0.1');
  });

  it.each([
    ['minor bump', '1.0.0', '1.1.0'],
    ['major bump', '1.0.0', '2.0.0'],
    ['downgrade', '1.0.5', '1.0.4'],
    ['prerelease', '1.0.0', '1.0.1-beta.1'],
    ['non-semver', '1.0.0', 'latest-build'],
  ])('flags a resolved version swap (%s) at MEDIUM', (_n, before, after) => {
    logScan(report([server(['-y', 'pkg'], before)]));
    const f = checkFingerprints([server(['-y', 'pkg'], after)])['Cursor:files'];
    expect(f?.[0]).toMatchObject({ id: 'server-mutation', severity: 'MEDIUM' });
  });

  it('flags a different package name at MEDIUM even when args and version look the same', () => {
    logScan(report([server(['-y', 'pkg'], '1.0.0', 'pkg')]));
    const f = checkFingerprints([server(['-y', 'pkg'], '1.0.0', 'pkg-evil')])['Cursor:files'];
    expect(f?.[0]).toMatchObject({ severity: 'MEDIUM' });
  });

  it('does not flag the same config scanned offline then online', () => {
    logScan(report([server(['-y', 'pkg'])]));
    expect(checkFingerprints([server(['-y', 'pkg'], '1.0.1')])).toEqual({});
  });

  it('still flags an edited config even when the version also moved', () => {
    logScan(report([server(['-y', 'pkg'], '1.0.0')]));
    const f = checkFingerprints([server(['-y', 'pkg', '--evil'], '1.0.1')])['Cursor:files'];
    expect(f?.[0]).toMatchObject({ severity: 'MEDIUM' });
  });

  const sha = 'a'.repeat(64);
  const storeFile = () => path.join(home, 'known-servers.json');
  const quarantined = () => fs.readdirSync(home).filter(f => f.startsWith('known-servers.json.corrupt-'));

  it('upgrades a verified old-format store with an INFO line, not silence', () => {
    fs.writeFileSync(storeFile(), JSON.stringify({ 'Cursor:files': sha, 'Cursor:other': sha }));
    const f = checkFingerprints([server(['-y', 'pkg'], '1.0.0')])['Cursor:files'];
    expect(f).toHaveLength(1);
    expect(f?.[0]).toMatchObject({ id: 'server-mutation', severity: 'INFO' });
    expect(f?.[0].description).toMatch(/baseline was reset/);
    expect(quarantined()).toHaveLength(0);
    logScan(report([server(['-y', 'pkg'], '1.0.0')]));
    expect(checkFingerprints([server(['-y', 'pkg', '--evil'], '1.0.0')])['Cursor:files']?.[0].severity).toBe('MEDIUM');
  });

  it.each([
    ['a wrong schema value', { __schema: '1', 'Cursor:files': sha }],
    ['a future schema value', { __schema: '3', 'Cursor:files': sha }],
    ['a missing schema with non-hash values', { 'Cursor:files': 'not-a-hash' }],
    ['a missing schema but current-format extras', { 'Cursor:files': sha, 'Cursor:files#resolved': '1.0.0' }],
    ['an emptied store', {}],
  ])('treats %s as a bad store: MEDIUM finding and quarantine', (_n, content) => {
    fs.writeFileSync(storeFile(), JSON.stringify(content));
    const f = checkFingerprints([server(['-y', 'pkg'], '1.0.0')])['Cursor:files'];
    expect(f?.[0]).toMatchObject({ id: 'server-mutation', severity: 'MEDIUM' });
    expect(quarantined()).toHaveLength(1);
  });
});
