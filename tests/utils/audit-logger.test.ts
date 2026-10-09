import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { checkFingerprints, logScan } from '../../src/utils/audit-logger.js';
import { ScanReport, ServerScanResult } from '../../src/types/scan-result.js';

function server(args: string[]): ServerScanResult {
  return {
    serverName: 'files',
    toolName: 'Cursor',
    configPath: '/tmp/none',
    findings: [],
    scanDurationMs: 1,
    connection: { command: 'npx', args, type: 'stdio', env: [] },
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
