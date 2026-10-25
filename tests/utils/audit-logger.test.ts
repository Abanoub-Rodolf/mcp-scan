import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { checkFingerprints, logScan, fingerprintKey } from '../../src/utils/audit-logger.js';
import { ScanReport, ServerScanResult } from '../../src/types/scan-result.js';

function server(args: string[], version?: string, pkg = 'pkg', source: 'registry' | 'snapshot' = 'registry'): ServerScanResult {
  return {
    serverName: 'files',
    toolName: 'Cursor',
    configPath: '/tmp/none',
    findings: [],
    scanDurationMs: 1,
    connection: { command: 'npx', args, type: 'stdio', env: [] },
    // Offline scans still know the package name; only the version is missing.
    metadata: { packageName: pkg, ...(version ? { version, versionSource: source } : {}) },
  };
}

const K = fingerprintKey(server([]));

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
    expect(found[K]?.[0].id).toBe('server-mutation');
  });

  it('reports every server when the store is corrupt, instead of passing them', () => {
    fs.writeFileSync(store, '{ not json');
    const found = checkFingerprints([server(['-y', 'pkg'])]);
    expect(found[K]?.[0].id).toBe('server-mutation');
    expect(found[K]?.[0].description).toMatch(/unreadable or corrupt/);
  });

  it('treats a store with the wrong shape as corrupt', () => {
    fs.writeFileSync(store, JSON.stringify({ 'Cursor:files': 42 }));
    expect(checkFingerprints([server(['-y', 'pkg'])])[K]).toBeDefined();
    fs.writeFileSync(store, '[]');
    expect(checkFingerprints([server(['-y', 'pkg'])])[K]).toBeDefined();
  });

  it('treats an unreadable store as corrupt', () => {
    fs.mkdirSync(store);
    expect(checkFingerprints([server(['-y', 'pkg'])])[K]).toBeDefined();
  });

  it('quarantines the bad file and rebuilds a baseline for the next run', () => {
    fs.writeFileSync(store, '{ not json');
    const results = [server(['-y', 'pkg'])];
    expect(checkFingerprints(results)[K]).toBeDefined();

    const aside = fs.readdirSync(home).filter(f => f.startsWith('known-servers.json.corrupt-'));
    expect(aside.length).toBe(1);

    logScan(report(results));
    expect(() => JSON.parse(fs.readFileSync(store, 'utf8'))).not.toThrow();
    expect(checkFingerprints(results)).toEqual({});
    expect(checkFingerprints([server(['-y', 'pkg', '--evil'])])[K]).toBeDefined();
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
    const f = checkFingerprints([server(['-y', 'pkg'], '1.0.1')])[K];
    expect(f?.[0]).toMatchObject({ id: 'server-mutation', severity: 'MEDIUM' });
    expect(f?.[0].description).toContain('registry latest changed for an unpinned server');
    expect(f?.[0].description).toContain('1.0.0 -> 1.0.1');
  });

  it('does not flag an online scan followed by an offline one that sees an older snapshot', () => {
    logScan(report([server(['-y', 'pkg'], '1.0.1', 'pkg', 'registry')]));
    expect(checkFingerprints([server(['-y', 'pkg'], '1.0.0', 'pkg', 'snapshot')])).toEqual({});
    logScan(report([server(['-y', 'pkg'], '1.0.0', 'pkg', 'snapshot')]));
    expect(checkFingerprints([server(['-y', 'pkg'], '1.0.1', 'pkg', 'registry')])).toEqual({});
  });

  it('does not flag an offline scan after the bundled snapshot version changed (mcp-scan upgrade)', () => {
    logScan(report([server(['-y', 'pkg'], '1.0.0', 'pkg', 'snapshot')]));
    expect(checkFingerprints([server(['-y', 'pkg'], '1.1.0', 'pkg', 'snapshot')])).toEqual({});
    logScan(report([server(['-y', 'pkg'], '1.1.0', 'pkg', 'snapshot')]));
    expect(checkFingerprints([server(['-y', 'pkg'], '2.0.0', 'pkg', 'snapshot')])).toEqual({});
  });

  it('ignores #resolved:snapshot entries an earlier build left in a signed store', () => {
    logScan(report([server(['-y', 'pkg'], '1.0.0', 'pkg', 'snapshot')]));
    const file = path.join(home, 'known-servers.json');
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    data[`${K}#resolved:snapshot`] = '0.1.0';
    delete data.__sig;
    const key = Buffer.from(fs.readFileSync(path.join(home, 'baseline.key'), 'utf8').trim(), 'hex');
    const entries = Object.keys(data).sort().map(k => [k, data[k]]);
    data.__sig = crypto.createHmac('sha256', key).update(JSON.stringify(entries)).digest('hex');
    fs.writeFileSync(file, JSON.stringify(data));
    expect(checkFingerprints([server(['-y', 'pkg'], '9.9.9', 'pkg', 'snapshot')])).toEqual({});
  });

  it('still catches a registry change across an offline scan in between', () => {
    logScan(report([server(['-y', 'pkg'], '1.0.0', 'pkg', 'registry')]));
    logScan(report([server(['-y', 'pkg'], '0.9.0', 'pkg', 'snapshot')]));
    const f = checkFingerprints([server(['-y', 'pkg'], '1.0.1', 'pkg', 'registry')])[K];
    expect(f?.[0]).toMatchObject({ id: 'server-mutation', severity: 'MEDIUM' });
  });

  it('does not flag a pinned server when the registry latest moves', () => {
    const pinned = (latest: string) => server(['-y', 'pkg@1.0.0'], latest, 'pkg@1.0.0');
    logScan(report([pinned('1.0.0')]));
    expect(checkFingerprints([pinned('2.0.0')])).toEqual({});
    const scoped = (latest: string) => server(['-y', '@s/pkg@1.0.0-rc.1'], latest, '@s/pkg@1.0.0-rc.1');
    logScan(report([scoped('1.0.0')]));
    expect(checkFingerprints([scoped('1.0.1')])).toEqual({});
  });

  it('flags a changed pin as a config change', () => {
    logScan(report([server(['-y', 'pkg@1.0.0'], '1.0.0', 'pkg@1.0.0')]));
    const f = checkFingerprints([server(['-y', 'pkg@1.0.1'], '1.0.0', 'pkg@1.0.1')])[K];
    expect(f?.[0]).toMatchObject({ severity: 'MEDIUM' });
    expect(f?.[0].description).toContain('configuration has changed');
  });

  it('tracks the bare name and @latest, where latest is what runs', () => {
    for (const spec of ['pkg', 'pkg@latest']) {
      logScan(report([server(['-y', spec], '1.0.0', spec)]));
      expect(checkFingerprints([server(['-y', spec], '1.0.1', spec)])[K]?.[0].severity).toBe('MEDIUM');
    }
  });

  it.each(['pkg@^1.0.0', 'pkg@~1.0.0', 'pkg@v1.2.3', 'pkg@beta', '@s/pkg@^1.0.0'])(
    'does not track registry latest for %s, which can resolve to something else',
    (spec) => {
      logScan(report([server(['-y', spec], '1.0.0', spec)]));
      expect(checkFingerprints([server(['-y', spec], '2.0.0', spec)])).toEqual({});
    });

  it.each([
    ['minor bump', '1.0.0', '1.1.0'],
    ['major bump', '1.0.0', '2.0.0'],
    ['downgrade', '1.0.5', '1.0.4'],
    ['prerelease', '1.0.0', '1.0.1-beta.1'],
    ['non-semver', '1.0.0', 'latest-build'],
  ])('flags a resolved version swap (%s) at MEDIUM', (_n, before, after) => {
    logScan(report([server(['-y', 'pkg'], before)]));
    const f = checkFingerprints([server(['-y', 'pkg'], after)])[K];
    expect(f?.[0]).toMatchObject({ id: 'server-mutation', severity: 'MEDIUM' });
  });

  it('flags a different package name at MEDIUM even when args and version look the same', () => {
    logScan(report([server(['-y', 'pkg'], '1.0.0', 'pkg')]));
    const f = checkFingerprints([server(['-y', 'pkg'], '1.0.0', 'pkg-evil')])[K];
    expect(f?.[0]).toMatchObject({ severity: 'MEDIUM' });
  });

  it('does not flag the same config scanned offline then online', () => {
    logScan(report([server(['-y', 'pkg'])]));
    expect(checkFingerprints([server(['-y', 'pkg'], '1.0.1')])).toEqual({});
  });

  it('still flags an edited config even when the version also moved', () => {
    logScan(report([server(['-y', 'pkg'], '1.0.0')]));
    const f = checkFingerprints([server(['-y', 'pkg', '--evil'], '1.0.1')])[K];
    expect(f?.[0]).toMatchObject({ severity: 'MEDIUM' });
  });

  const sha = 'a'.repeat(64);
  const storeFile = () => path.join(home, 'known-servers.json');
  const quarantined = () => fs.readdirSync(home).filter(f => f.startsWith('known-servers.json.corrupt-'));

  it('upgrades a verified old-format store with an INFO line, not silence', () => {
    fs.writeFileSync(storeFile(), JSON.stringify({ 'Cursor:files': sha, 'Cursor:other': sha }));
    const f = checkFingerprints([server(['-y', 'pkg'], '1.0.0')])[K];
    expect(f).toHaveLength(1);
    expect(f?.[0]).toMatchObject({ id: 'server-mutation', severity: 'INFO' });
    expect(f?.[0].description).toMatch(/baseline was reset/);
    expect(quarantined()).toHaveLength(0);
    logScan(report([server(['-y', 'pkg'], '1.0.0')]));
    expect(checkFingerprints([server(['-y', 'pkg', '--evil'], '1.0.0')])[K]?.[0].severity).toBe('MEDIUM');
  });

  it.each([
    ['a hash in a name', 'Cursor:my#srv'],
    ['an underscore-led name', 'Cursor:_srv'],
    ['an underscore-led tool', '_Cursor:srv'],
  ])('upgrades a 2.0.13 store with %s with INFO, not a quarantine', (_n, key) => {
    fs.writeFileSync(storeFile(), JSON.stringify({ [key]: sha }));
    const [tool, name] = [key.split(':')[0], key.split(':').slice(1).join(':')];
    const s = { ...server(['-y', 'pkg'], '1.0.0'), toolName: tool, serverName: name };
    const f = checkFingerprints([s])[fingerprintKey(s)];
    expect(f?.[0]).toMatchObject({ id: 'server-mutation', severity: 'INFO' });
    expect(f?.[0].description).toMatch(/baseline was reset/);
    expect(quarantined()).toHaveLength(0);
  });

  it.each([
    ['a #resolved key', { 'Cursor:files': sha, 'Cursor:files#resolved': sha }],
    ['a per-source #resolved key', { 'Cursor:files': sha, 'Cursor:files#resolved:registry': sha }],
  ])('does not take %s for the old format, even with a hash value', (_n, content) => {
    fs.writeFileSync(storeFile(), JSON.stringify(content));
    const f = checkFingerprints([server(['-y', 'pkg'], '1.0.0')])[K];
    expect(f?.[0]).toMatchObject({ severity: 'MEDIUM' });
    expect(quarantined()).toHaveLength(1);
  });

  it.each([
    ['a wrong schema value', { __schema: '1', 'Cursor:files': sha }],
    ['a future schema value', { __schema: '3', 'Cursor:files': sha }],
    ['a missing schema with non-hash values', { 'Cursor:files': 'not-a-hash' }],
    ['a missing schema but current-format extras', { 'Cursor:files': sha, 'Cursor:files#resolved': '1.0.0' }],
  ])('treats %s as a bad store: MEDIUM finding and quarantine', (_n, content) => {
    fs.writeFileSync(storeFile(), JSON.stringify(content));
    const f = checkFingerprints([server(['-y', 'pkg'], '1.0.0')])[K];
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
    const blessed = JSON.parse(fs.readFileSync(storeFile(), 'utf8'))[K];
    const forged = JSON.parse(honest);
    forged[K] = blessed;
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
    const f = checkFingerprints(evil())[K];
    expect(f?.[0]).toMatchObject({ id: 'server-mutation', severity: 'MEDIUM' });
    expect(f?.[0].description).toMatch(/integrity check \(signature does not match\)/);
    expect(quarantined()).toHaveLength(1);
  });

  it('flags a store whose signature was stripped', () => {
    logScan(report(results()));
    const store = JSON.parse(fs.readFileSync(storeFile(), 'utf8'));
    delete store.__sig;
    fs.writeFileSync(storeFile(), JSON.stringify(store));
    const f = checkFingerprints(results())[K];
    expect(f?.[0]).toMatchObject({ severity: 'MEDIUM' });
    expect(f?.[0].description).toMatch(/signature missing/);
    expect(quarantined()).toHaveLength(1);
  });

  it('does not let an old-format file stand in once the install has a key', () => {
    logScan(report(results()));
    fs.writeFileSync(storeFile(), JSON.stringify({ 'Cursor:files': 'a'.repeat(64) }));
    const f = checkFingerprints(results())[K];
    expect(f?.[0]).toMatchObject({ severity: 'MEDIUM' });
    expect(quarantined()).toHaveLength(1);
  });

  it('rebuilds a signed baseline after a tamper, so the next run is clean', () => {
    logScan(report(results()));
    forgeBaselineFor(evil());
    expect(checkFingerprints(evil())[K]).toBeDefined();
    logScan(report(evil()));
    expect(checkFingerprints(evil())).toEqual({});
  });

  it('treats a signed store with no key as tampered, then starts over with a new key', () => {
    logScan(report(results()));
    const old = fs.readFileSync(keyFile(), 'utf8');
    fs.rmSync(keyFile());
    const f = checkFingerprints(results())[K];
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
    const f = checkFingerprints(results())[K];
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

  // What mcp-scan <= 2.0.13 wrote: "tool:server" -> sha256 hex, no schema marker.
  const sha = (x: string) => crypto.createHash('sha256').update(x).digest('hex');

  it('upgrading a real 2.0.x store: one INFO per scanned server, no change check, then a signed baseline', () => {
    const two = [server(['-y', 'pkg'], '1.0.0'), { ...server(['-y', 'pkg'], '1.0.0'), serverName: 'other' }];
    fs.writeFileSync(storeFile(), JSON.stringify({ 'Cursor:files': sha('old files'), 'Cursor:other': sha('old other') }));
    const found = checkFingerprints(two);
    // both fingerprints differ from the old recipe's, yet nothing is reported as a change
    expect(Object.keys(found).sort()).toEqual(two.map(fingerprintKey).sort());
    for (const f of Object.values(found)) {
      expect(f).toHaveLength(1);
      expect(f[0]).toMatchObject({ id: 'server-mutation', severity: 'INFO' });
      expect(f[0].description).toMatch(/baseline was reset.*older format/);
    }
    expect(quarantined()).toHaveLength(0);

    logScan(report(two));
    const written = JSON.parse(fs.readFileSync(storeFile(), 'utf8'));
    expect(written.__schema).toBe('2');
    expect(written.__sig).toMatch(/^[0-9a-f]{64}$/);
    expect(checkFingerprints(two)).toEqual({});
  });

  it('treats the empty store 2.0.13 wrote for a zero-server scan as an old-format baseline: one INFO per server, then signed', () => {
    fs.writeFileSync(storeFile(), '{}');
    const f = checkFingerprints(results())[K];
    expect(f).toHaveLength(1);
    expect(f?.[0]).toMatchObject({ id: 'server-mutation', severity: 'INFO' });
    expect(f?.[0].description).toMatch(/baseline was reset/);
    expect(quarantined()).toHaveLength(0);
    logScan(report(results()));
    expect(JSON.parse(fs.readFileSync(storeFile(), 'utf8')).__sig).toMatch(/^[0-9a-f]{64}$/);
    expect(checkFingerprints(results())).toEqual({});
  });

  it('still reports something when a signed install has its store replaced by {} and its key and signing history removed', () => {
    logScan(report(results()));
    fs.rmSync(keyFile());
    fs.writeFileSync(storeFile(), '{}');
    const log = path.join(home, 'audit.log');
    fs.writeFileSync(log, fs.readFileSync(log, 'utf8').replaceAll(',"baselineSigned":true', ''));
    const f = checkFingerprints(results())[K];
    expect(f?.length).toBeGreaterThan(0);
    expect(f?.[0].severity).toBe('INFO');
  });

  it('still calls an empty unsigned store tampered on an install that signed before', () => {
    logScan(report(results()));
    fs.rmSync(keyFile());
    fs.writeFileSync(storeFile(), '{}');
    expect(checkFingerprints(results())[K]?.[0]).toMatchObject({ severity: 'MEDIUM' });
  });

  it('2.0.13 run against a 2.1.0-signed store makes the next scan report a signature mismatch, once', () => {
    logScan(report(results()));
    // what 2.0.13's updateFingerprints does (release commit 946c7c0): load the whole
    // file, overwrite its own entries with old-recipe fingerprints, write it back
    const store = JSON.parse(fs.readFileSync(storeFile(), 'utf8'));
    store['Cursor:files'] = sha('2.0.13 recipe');
    fs.writeFileSync(storeFile(), JSON.stringify(store, null, 2));
    const f = checkFingerprints(results())[K];
    expect(f?.[0]).toMatchObject({ id: 'server-mutation', severity: 'MEDIUM' });
    expect(f?.[0].description).toMatch(/signature does not match/);
    expect(quarantined()).toHaveLength(1);
    logScan(report(results()));
    expect(checkFingerprints(results())).toEqual({});
  });

  it('still compares an unsigned store while upgrading it', () => {
    writeUnsignedStore(results());
    const f = checkFingerprints(evil())[K];
    expect(f?.map(x => x.severity).sort()).toEqual(['INFO', 'MEDIUM']);
  });

  it('reports a deleted store as a missing baseline, not a quiet first run', () => {
    logScan(report(results()));
    const key = fs.readFileSync(keyFile(), 'utf8');
    fs.rmSync(storeFile());
    const f = checkFingerprints(results())[K];
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
    expect(checkFingerprints(results())[K]?.[0]).toMatchObject({ severity: 'MEDIUM' });
    logScan(report(results()));
    expect(checkFingerprints(results())).toEqual({});
  });

  it('catches a store deleted before the first signed run, from an install that already scanned', () => {
    fs.writeFileSync(path.join(home, 'audit.log'), '{"timestamp":"2026-10-01T00:00:00.000Z"}\n');
    expect(checkFingerprints(results())[K]?.[0]).toMatchObject({ severity: 'MEDIUM' });
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
    const f = checkFingerprints(evil())[K];
    expect(f?.[0]).toMatchObject({ severity: 'MEDIUM' });
    expect(f?.[0].description).toMatch(/signed before/);
    expect(quarantined()).toHaveLength(1);
  });

  it('does not take an old-format file plus a deleted key for a baseline reset', () => {
    logScan(report(results()));
    fs.writeFileSync(storeFile(), JSON.stringify({ 'Cursor:files': 'a'.repeat(64) }));
    fs.rmSync(keyFile());
    const f = checkFingerprints(results())[K];
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

describe('audit log write failure', () => {
  let home: string;
  let err: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-audit-fail-'));
    process.env.MCP_SCAN_HOME = home;
    err = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    err.mockRestore();
    delete process.env.MCP_SCAN_HOME;
    fs.rmSync(home, { recursive: true, force: true });
  });

  const said = () => err.mock.calls.map((c: unknown[]) => String(c[0])).filter((l: string) => l.includes('could not write the audit log'));

  it('does not throw, but says the audit log could not be written, once', () => {
    // a directory where the log file should be makes the append fail
    fs.mkdirSync(path.join(home, 'audit.log'));
    expect(() => logScan(report([server(['-y', 'pkg'])]))).not.toThrow();
    expect(() => logScan(report([server(['-y', 'pkg'])]))).not.toThrow();
    expect(said()).toHaveLength(1);
    expect(said()[0]).toContain(home);
  });

  it('stays quiet when the log is written', () => {
    logScan(report([server(['-y', 'pkg'])]));
    expect(said()).toHaveLength(0);
  });
});

// One repo with the same server name in several configs (runsheet-mcp has
// three `runsheet` servers). 2.1.0 keyed the baseline by tool and name only,
// so scanning the second file reported "unauthorized modification" against
// the first one in the same clean session.
describe('baseline per config file', () => {
  let home: string;
  const at = (configPath: string, args: string[]): ServerScanResult => ({ ...server(args), configPath });
  const a = at('/repo/.mcp.json', ['-y', 'pkg']);
  const b = at('/repo/plugins/runsheet/.mcp.json', ['-y', 'pkg', '--stdio']);

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-perfile-'));
    process.env.MCP_SCAN_HOME = home;
  });

  afterEach(() => {
    delete process.env.MCP_SCAN_HOME;
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('does not compare two files that share a server name, file by file', () => {
    logScan(report([a]));
    expect(checkFingerprints([b])).toEqual({});
    logScan(report([b]));
    expect(checkFingerprints([a])).toEqual({});
  });

  it('does not compare them when both are in one scan', () => {
    logScan(report([a, b]));
    expect(checkFingerprints([a, b])).toEqual({});
  });

  it('still flags a change to one of them, and only that one', () => {
    logScan(report([a, b]));
    const found = checkFingerprints([at(a.configPath, ['-y', 'pkg', '--evil']), b]);
    const flagged = Object.values(found).flat();
    expect(flagged).toHaveLength(1);
    expect(flagged[0].id).toBe('server-mutation');
  });

  // A baseline written before this change is keyed by tool and name. It
  // must keep catching a change on the first scan after the upgrade.
  // Rewrites the store as 2.1.0 would have keyed it, signed.
  const toNameKeys = () => {
    const file = path.join(home, 'known-servers.json');
    const key = Buffer.from(fs.readFileSync(path.join(home, 'baseline.key'), 'utf8').trim(), 'hex');
    const data: Record<string, string> = JSON.parse(fs.readFileSync(file, 'utf8'));
    for (const k of Object.keys(data).filter(k => k.startsWith('['))) {
      data['Cursor:files'] = data[k];
      delete data[k];
    }
    delete data.__sig;
    const entries = Object.keys(data).sort().map(k => [k, data[k]]);
    data.__sig = crypto.createHmac('sha256', key).update(JSON.stringify(entries)).digest('hex');
    fs.writeFileSync(file, JSON.stringify(data));
  };

  // A second config planted with the same name must not switch the
  // carried-over check off.
  it('checks every file sharing the name against an older baseline', () => {
    logScan(report([a]));
    toNameKeys();
    const found = checkFingerprints([at(a.configPath, ['-y', 'pkg', '--evil']), at('/repo/planted/.mcp.json', ['-y', 'pkg'])]);
    expect(found[fingerprintKey(a)]?.[0].id).toBe('server-mutation');
  });

  it('carries an older tool:name baseline over to the per-file key', () => {
    logScan(report([a]));
    const file = path.join(home, 'known-servers.json');
    const key = Buffer.from(fs.readFileSync(path.join(home, 'baseline.key'), 'utf8').trim(), 'hex');
    const data: Record<string, string> = JSON.parse(fs.readFileSync(file, 'utf8'));
    const [newKey] = Object.keys(data).filter(k => !k.startsWith('__'));
    data['Cursor:files'] = data[newKey];
    delete data[newKey];
    delete data.__sig;
    const entries = Object.keys(data).sort().map(k => [k, data[k]]);
    data.__sig = crypto.createHmac('sha256', key).update(JSON.stringify(entries)).digest('hex');
    fs.writeFileSync(file, JSON.stringify(data));

    expect(checkFingerprints([a])).toEqual({});
    expect(Object.values(checkFingerprints([at(a.configPath, ['-y', 'pkg', '--evil'])])).flat()[0]?.id).toBe('server-mutation');

    logScan(report([a]));
    expect(JSON.parse(fs.readFileSync(file, 'utf8'))[K]).toBeUndefined();
  });
});
