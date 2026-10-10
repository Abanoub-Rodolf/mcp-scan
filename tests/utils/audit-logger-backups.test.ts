import { describe, it, expect, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { logScan } from '../../src/utils/audit-logger.js';
import type { ScanReport } from '../../src/types/scan-result.js';

const report: ScanReport = {
  results: [],
  totalScanned: 0,
  criticalCount: 0,
  highCount: 0,
  mediumCount: 0,
  lowCount: 0,
  infoCount: 0,
  totalDurationMs: 1,
};

describe('audit-logger known-servers backups', () => {
  let home: string;

  afterEach(() => {
    delete process.env.MCP_SCAN_HOME;
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('a scan leaves at most 5 known-servers backups', () => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-home-'));
    process.env.MCP_SCAN_HOME = home;
    const store = path.join(home, 'known-servers.json');
    fs.writeFileSync(store, '{}');
    for (let i = 1; i <= 12; i++) fs.writeFileSync(`${store}.backup-${1000 + i}`, '{}');

    logScan(report);

    const backups = fs.readdirSync(home).filter(f => f.startsWith('known-servers.json.backup-'));
    expect(backups.length).toBe(5);
  });
});
