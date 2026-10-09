import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
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

describe('signed baseline', () => {
  let home: string;
  const storeFile = () => path.join(home, 'known-servers.json');
  const keyFile = () => path.join(home, 'baseline.key');
  const quarantined = () => fs.readdirSync(home).filter(f => f.startsWith('known-servers.json.corrupt-'));
  const results = () => [server(['-y', 'pkg'], '1.0.0')];
  const evil = () => [server(['-y', 'pkg', '--evil'], '1.0.0')];

  // The attack: bless the evil config by writing its fingerprint straight
  // into the store, so a plain fingerprint compare sees no change.
  function forgeBaselineFor(evilResults: ServerScanResult[]) {
    const honest = fs.readFileSync(storeFile(), 'utf8');
    logScan(report(evilResults));
    const blessed = JSON.parse(fs.readFileSync(storeFile(), 'utf8'))['Cursor:files'];
    const forged = JSON.parse(honest);
    forged['Cursor:files'] = blessed;
    fs.writeFileSync(storeFile(), JSON.stringify(forged));
  }

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-audit-sig-'));
    process.env.MCP_SCAN_HOME = home;
  });

  afterEach(() => {
    delete process.env.MCP_SCAN_HOME;
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('signs the store with a 32-byte key kept outside it', () => {
    logScan(report(results()));
    expect(fs.readFileSync(keyFile(), 'utf8').trim()).toMatch(/^[0-9a-f]{64}$/);
    const store = JSON.parse(fs.readFileSync(storeFile(), 'utf8'));
    expect(store.__sig).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(store)).not.toContain(fs.readFileSync(keyFile(), 'utf8').trim());
  });

  it.skipIf(process.platform === 'win32')('creates the key readable by the owner only', () => {
    logScan(report(results()));
    expect(fs.statSync(keyFile()).mode & 0o777).toBe(0o600);
  });

  it('keeps the same key and stays quiet across healthy runs', () => {
    logScan(report(results()));
    const key = fs.readFileSync(keyFile(), 'utf8');
    logScan(report(results()));
    expect(fs.readFileSync(keyFile(), 'utf8')).toBe(key);
    expect(checkFingerprints(results())).toEqual({});
    expect(quarantined()).toHaveLength(0);
  });

  it('flags a hand-edited store even though it is still valid JSON of the right shape', () => {
    logScan(report(results()));
    forgeBaselineFor(evil());
    const f = checkFingerprints(evil())['Cursor:files'];
    expect(f?.[0]).toMatchObject({ id: 'server-mutation', severity: 'MEDIUM' });
    expect(f?.[0].description).toMatch(/integrity check \(signature does not match\)/);
    expect(quarantined()).toHaveLength(1);
  });

  it('flags a store whose signature was stripped', () => {
    logScan(report(results()));
    const store = JSON.parse(fs.readFileSync(storeFile(), 'utf8'));
    delete store.__sig;
    fs.writeFileSync(storeFile(), JSON.stringify(store));
    const f = checkFingerprints(results())['Cursor:files'];
    expect(f?.[0]).toMatchObject({ severity: 'MEDIUM' });
    expect(f?.[0].description).toMatch(/signature missing/);
    expect(quarantined()).toHaveLength(1);
  });

  it('does not let an old-format file stand in once the install has a key', () => {
    logScan(report(results()));
    fs.writeFileSync(storeFile(), JSON.stringify({ 'Cursor:files': 'a'.repeat(64) }));
    const f = checkFingerprints(results())['Cursor:files'];
    expect(f?.[0]).toMatchObject({ severity: 'MEDIUM' });
    expect(quarantined()).toHaveLength(1);
  });

  it('rebuilds a signed baseline after a tamper, so the next run is clean', () => {
    logScan(report(results()));
    forgeBaselineFor(evil());
    expect(checkFingerprints(evil())['Cursor:files']).toBeDefined();
    logScan(report(evil()));
    expect(checkFingerprints(evil())).toEqual({});
  });

  it('treats a signed store with no key as tampered, then starts over with a new key', () => {
    logScan(report(results()));
    const old = fs.readFileSync(keyFile(), 'utf8');
    fs.rmSync(keyFile());
    const f = checkFingerprints(results())['Cursor:files'];
    expect(f?.[0]).toMatchObject({ id: 'server-mutation', severity: 'MEDIUM' });
    expect(f?.[0].description).toMatch(/baseline key is gone/);
    expect(quarantined()).toHaveLength(1);
    logScan(report(results()));
    expect(fs.readFileSync(keyFile(), 'utf8')).not.toBe(old);
    expect(checkFingerprints(results())).toEqual({});
  });

  it.each([
    ['too short', 'abcd\n'],
    ['not hex', 'z'.repeat(64) + '\n'],
    ['empty', ''],
  ])('treats a %s key file as tampered and replaces it', (_n, content) => {
    logScan(report(results()));
    fs.writeFileSync(keyFile(), content);
    const f = checkFingerprints(results())['Cursor:files'];
    expect(f?.[0]).toMatchObject({ severity: 'MEDIUM' });
    expect(f?.[0].description).toMatch(/baseline key unreadable/);
    expect(quarantined()).toHaveLength(1);
    logScan(report(results()));
    expect(fs.readFileSync(keyFile(), 'utf8').trim()).toMatch(/^[0-9a-f]{64}$/);
    expect(checkFingerprints(results())).toEqual({});
  });

  // What MR 17 wrote: schema 2, valid, but no signature and no key yet.
  // Its audit log lines predate the baselineSigned field.
  function writeUnsignedStore(rs: ServerScanResult[]) {
    logScan(report(rs));
    fs.rmSync(keyFile());
    const store = JSON.parse(fs.readFileSync(storeFile(), 'utf8'));
    delete store.__sig;
    fs.writeFileSync(storeFile(), JSON.stringify(store));
    const log = path.join(home, 'audit.log');
    fs.writeFileSync(log, fs.readFileSync(log, 'utf8').replaceAll(',"baselineSigned":true', ''));
  }

  it('signs a valid unsigned store once, with a single INFO and no quarantine', () => {
    const two = [server(['-y', 'pkg'], '1.0.0'), { ...server(['-y', 'pkg'], '1.0.0'), serverName: 'other' }];
    writeUnsignedStore(two);
    const found = checkFingerprints(two);
    expect(Object.values(found).flat()).toHaveLength(1);
    expect(Object.values(found).flat()[0]).toMatchObject({ id: 'server-mutation', severity: 'INFO' });
    expect(Object.values(found).flat()[0].description).toMatch(/was not signed.*will be signed/);
    expect(quarantined()).toHaveLength(0);

    logScan(report(two));
    expect(fs.readFileSync(keyFile(), 'utf8').trim()).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.parse(fs.readFileSync(storeFile(), 'utf8')).__sig).toMatch(/^[0-9a-f]{64}$/);
    expect(checkFingerprints(two)).toEqual({});
  });

  it('still compares an unsigned store while upgrading it', () => {
    writeUnsignedStore(results());
    const f = checkFingerprints(evil())['Cursor:files'];
    expect(f?.map(x => x.severity).sort()).toEqual(['INFO', 'MEDIUM']);
  });

  it('reports a deleted store as a missing baseline, not a quiet first run', () => {
    logScan(report(results()));
    const key = fs.readFileSync(keyFile(), 'utf8');
    fs.rmSync(storeFile());
    const f = checkFingerprints(results())['Cursor:files'];
    expect(f?.[0]).toMatchObject({ id: 'server-mutation', severity: 'MEDIUM' });
    expect(f?.[0].description).toMatch(/went missing/);
    expect(quarantined()).toHaveLength(0);
    logScan(report(results()));
    expect(fs.readFileSync(keyFile(), 'utf8')).toBe(key);
    expect(checkFingerprints(results())).toEqual({});
  });

  it('catches a deleted store even when the key went with it, if the audit log remembers', () => {
    logScan(report(results()));
    fs.rmSync(storeFile());
    fs.rmSync(keyFile());
    expect(checkFingerprints(results())['Cursor:files']?.[0]).toMatchObject({ severity: 'MEDIUM' });
    logScan(report(results()));
    expect(checkFingerprints(results())).toEqual({});
  });

  it('catches a store deleted before the first signed run, from an install that already scanned', () => {
    fs.writeFileSync(path.join(home, 'audit.log'), '{"timestamp":"2026-10-01T00:00:00.000Z"}\n');
    expect(checkFingerprints(results())['Cursor:files']?.[0]).toMatchObject({ severity: 'MEDIUM' });
  });

  it('stays quiet on a true first run, even with an empty audit log or stray files', () => {
    fs.writeFileSync(path.join(home, 'audit.log'), '');
    fs.writeFileSync(path.join(home, 'notes.txt'), 'x');
    expect(checkFingerprints(results())).toEqual({});
  });

  it('does not take a stripped signature plus a deleted key for an upgrade', () => {
    logScan(report(results()));
    forgeBaselineFor(evil());
    const store = JSON.parse(fs.readFileSync(storeFile(), 'utf8'));
    delete store.__sig;
    fs.writeFileSync(storeFile(), JSON.stringify(store));
    fs.rmSync(keyFile());
    const f = checkFingerprints(evil())['Cursor:files'];
    expect(f?.[0]).toMatchObject({ severity: 'MEDIUM' });
    expect(f?.[0].description).toMatch(/signed before/);
    expect(quarantined()).toHaveLength(1);
  });

  it('does not take an old-format file plus a deleted key for a baseline reset', () => {
    logScan(report(results()));
    fs.writeFileSync(storeFile(), JSON.stringify({ 'Cursor:files': 'a'.repeat(64) }));
    fs.rmSync(keyFile());
    const f = checkFingerprints(results())['Cursor:files'];
    expect(f?.[0]).toMatchObject({ severity: 'MEDIUM' });
    expect(quarantined()).toHaveLength(1);
  });

  it('does not record a signed baseline when the store could not be written', () => {
    const rename = vi.spyOn(fs, 'renameSync').mockImplementation(() => { throw new Error('disk full'); });
    try {
      logScan(report(results()));
    } finally {
      rename.mockRestore();
    }
    expect(fs.readFileSync(path.join(home, 'audit.log'), 'utf8')).toContain('"baselineSigned":false');
  });

  it('leaves no key behind when the first store write fails, so the next run is still a first run', () => {
    const rename = vi.spyOn(fs, 'renameSync').mockImplementation(() => { throw new Error('disk full'); });
    try {
      logScan(report(results()));
    } finally {
      rename.mockRestore();
    }
    expect(fs.existsSync(keyFile())).toBe(false);
    expect(checkFingerprints(results())).toEqual({});
  });

  it('adopts the key another first run wrote at the same moment, and still signs with it', () => {
    const realWrite = fs.writeFileSync;
    const other = 'c'.repeat(64) + '\n';
    const write = vi.spyOn(fs, 'writeFileSync').mockImplementation(((p: fs.PathOrFileDescriptor, ...rest: unknown[]) => {
      if (String(p) === keyFile() && !fs.existsSync(keyFile())) {
        realWrite(p, other);
        throw Object.assign(new Error('exists'), { code: 'EEXIST' });
      }
      return (realWrite as (...a: unknown[]) => void)(p, ...rest);
    }) as typeof fs.writeFileSync);
    try {
      logScan(report(results()));
    } finally {
      write.mockRestore();
    }
    expect(fs.readFileSync(keyFile(), 'utf8')).toBe(other);
    expect(checkFingerprints(results())).toEqual({});
    expect(quarantined()).toHaveLength(0);
  });
});
