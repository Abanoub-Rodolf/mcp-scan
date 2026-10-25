import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

const runScanMock = vi.fn();
vi.mock('../../src/commands/scan.js', () => ({
  runScan: (...args: unknown[]) => runScanMock(...args),
}));

import { runMultiConfigReport } from '../../src/commands/report.js';
import { logger } from '../../src/utils/logger.js';

// 2.1.0 printed "Aggregating reports from" and "Found N potential config
// files" on stdout ahead of the JSON, so `report --json | jq` failed.
describe('report --json stdout', () => {
  let tmpDir: string;
  const saved = { toStderr: logger.toStderr, isSilent: logger.isSilent };

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-report-json-'));
    fs.writeFileSync(path.join(tmpDir, '.mcp.json'), JSON.stringify({ mcpServers: { docs: { command: 'node' } } }));
    runScanMock.mockResolvedValue({
      results: [{ serverName: 'docs', toolName: '.mcp', configPath: '.mcp.json', findings: [], scanDurationMs: 1 }],
      totalScanned: 1, criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, infoCount: 0, totalDurationMs: 1,
    });
  });

  afterEach(() => {
    Object.assign(logger, saved);
    vi.restoreAllMocks();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('writes only the JSON report to stdout', async () => {
    const stdout = vi.spyOn(console, 'log').mockImplementation(() => {});
    const stderr = vi.spyOn(console, 'error').mockImplementation(() => {});

    await runMultiConfigReport({ configs: tmpDir, json: true });

    const printed = stdout.mock.calls.map(c => c.join(' ')).join('\n');
    expect(() => JSON.parse(printed)).not.toThrow();
    expect(JSON.parse(printed).totalScanned).toBe(1);
    // The progress lines still reach the user, on stderr.
    expect(stderr.mock.calls.flat().join(' ')).toContain('Aggregating reports from');
  });

  it('keeps progress lines on stdout without --json', async () => {
    const stdout = vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});

    await runMultiConfigReport({ configs: tmpDir });

    expect(stdout.mock.calls.flat().join(' ')).toContain('Aggregating reports from');
  });

  // runScan({ silent: true }) leaves the logger silent, and every line of
  // the human report is gated on it, so findings never printed.
  it('prints findings without --json after the silent per-file scans', async () => {
    runScanMock.mockImplementation(async () => {
      logger.isSilent = true;
      return {
        results: [{ serverName: 'docs', toolName: '.mcp', configPath: '.mcp.json', scanDurationMs: 1,
          findings: [{ id: 'http-transport-no-auth', severity: 'HIGH', description: 'plain http', fixRecommendation: 'https' }] }],
        totalScanned: 1, criticalCount: 0, highCount: 1, mediumCount: 0, lowCount: 0, infoCount: 0, totalDurationMs: 1,
      };
    });
    const stdout = vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});

    await runMultiConfigReport({ configs: tmpDir });

    expect(stdout.mock.calls.flat().join(' ')).toContain('http-transport-no-auth');
  });
});
