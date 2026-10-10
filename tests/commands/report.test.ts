import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

// runScan is mocked so this test is hermetic (no npm/GitHub network calls)
// and isolates what we actually care about here: whether report.ts's own
// file-discovery glob finds a given config file at all.
const runScanMock = vi.fn();
vi.mock('../../src/commands/scan.js', () => ({
  runScan: (...args: unknown[]) => runScanMock(...args),
}));

vi.mock('../../src/utils/logger.js', () => ({
  logger: {
    brand: vi.fn(),
    info: vi.fn(),
    detail: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    pass: vi.fn(),
  },
}));

vi.mock('../../src/utils/json-reporter.js', () => ({
  printJsonReport: vi.fn(),
}));

import { runMultiConfigReport } from '../../src/commands/report.js';
import { logger } from '../../src/utils/logger.js';
import { BaselineKeyError } from '../../src/utils/audit-logger.js';

describe('runMultiConfigReport', () => {
  let tmpDir: string;

  beforeEach(() => {
    vi.clearAllMocks();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-report-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // Regression for the bug found scanning modelcontextprotocol/servers:
  // `.mcp.json` is the standard MCP config filename, and fast-glob's
  // default excludes dotfiles/dot-dirs. Without dot:true, `report` told
  // you it scanned everything while silently never looking at the one
  // file that actually mattered.
  it('finds and scans a dotfile config (.mcp.json)', async () => {
    fs.writeFileSync(
      path.join(tmpDir, '.mcp.json'),
      JSON.stringify({ mcpServers: { docs: { type: 'http', url: 'https://example.com/mcp' } } })
    );

    runScanMock.mockResolvedValue({
      results: [{ serverName: 'docs', toolName: '.mcp', configPath: '.mcp.json', findings: [], scanDurationMs: 1 }],
      totalScanned: 1,
      criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, infoCount: 0, totalDurationMs: 1,
    });

    await runMultiConfigReport({ configs: tmpDir, json: true });

    expect(runScanMock).toHaveBeenCalledTimes(1);
    expect(runScanMock).toHaveBeenCalledWith(
      expect.objectContaining({ config: path.join(tmpDir, '.mcp.json') })
    );
  });

  it('still finds and scans a non-dotfile config file', async () => {
    fs.writeFileSync(
      path.join(tmpDir, 'claude_desktop_config.json'),
      JSON.stringify({ mcpServers: { docs: { type: 'http', url: 'https://example.com/mcp' } } })
    );

    runScanMock.mockResolvedValue({
      results: [{ serverName: 'docs', toolName: 'claude_desktop_config', configPath: 'x', findings: [], scanDurationMs: 1 }],
      totalScanned: 1,
      criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, infoCount: 0, totalDurationMs: 1,
    });

    await runMultiConfigReport({ configs: tmpDir, json: true });

    expect(runScanMock).toHaveBeenCalledTimes(1);
  });

  // A directory full of files that glob finds but that turn out not to be
  // MCP configs (or that fail to scan) must not read as a clean "0
  // findings" report - that's false assurance, not a clean bill of health.
  it('errors loudly instead of reporting a silent clean scan when nothing usable was found', async () => {
    fs.writeFileSync(path.join(tmpDir, 'unrelated.json'), JSON.stringify({ foo: 'bar' }));

    await runMultiConfigReport({ configs: tmpDir, json: true });

    expect(runScanMock).not.toHaveBeenCalled();
    expect(logger.error).toHaveBeenCalledWith(
      expect.stringContaining('scanned 0 MCP servers')
    );
  });

  it('does not exclude dotfiles while still excluding node_modules and .git', async () => {
    fs.mkdirSync(path.join(tmpDir, 'node_modules', 'pkg'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpDir, 'node_modules', 'pkg', 'mcp.json'),
      JSON.stringify({ mcpServers: { x: { command: 'npx', args: ['x'] } } })
    );
    fs.mkdirSync(path.join(tmpDir, '.git'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpDir, '.git', 'mcpServers.json'),
      JSON.stringify({ mcpServers: { x: { command: 'npx', args: ['x'] } } })
    );
    fs.writeFileSync(
      path.join(tmpDir, '.mcp.json'),
      JSON.stringify({ mcpServers: { docs: { type: 'http', url: 'https://example.com/mcp' } } })
    );

    runScanMock.mockResolvedValue({
      results: [{ serverName: 'docs', toolName: '.mcp', configPath: 'x', findings: [], scanDurationMs: 1 }],
      totalScanned: 1,
      criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, infoCount: 0, totalDurationMs: 1,
    });

    await runMultiConfigReport({ configs: tmpDir, json: true });

    expect(runScanMock).toHaveBeenCalledTimes(1);
    expect(runScanMock).toHaveBeenCalledWith(
      expect.objectContaining({ config: path.join(tmpDir, '.mcp.json') })
    );
  });
  // A baseline.key that is not a file fails every scan the same way, so the
  // loop must not turn it into one "Skipping <file>" line per config.
  describe('unusable baseline key', () => {
    let home: string;
    beforeEach(() => {
      home = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-report-home-'));
      process.env.MCP_SCAN_HOME = home;
      for (const n of ['a.json', 'b.json']) {
        fs.writeFileSync(path.join(tmpDir, n), JSON.stringify({ mcpServers: { x: { command: 'npx', args: ['x'] } } }));
      }
    });
    afterEach(() => {
      delete process.env.MCP_SCAN_HOME;
      fs.rmSync(home, { recursive: true, force: true });
    });

    it('rejects once, before scanning any file, with no per-file skip lines', async () => {
      fs.mkdirSync(path.join(home, 'baseline.key'));
      await expect(runMultiConfigReport({ configs: tmpDir, json: true })).rejects.toBeInstanceOf(BaselineKeyError);
      expect(runScanMock).not.toHaveBeenCalled();
      expect(logger.warn).not.toHaveBeenCalled();
    });

    it('rethrows a BaselineKeyError that appears mid-run instead of skipping the file', async () => {
      runScanMock.mockRejectedValue(new BaselineKeyError('baseline key went bad'));
      await expect(runMultiConfigReport({ configs: tmpDir, json: true })).rejects.toBeInstanceOf(BaselineKeyError);
      expect(runScanMock).toHaveBeenCalledTimes(1);
      expect(logger.warn).not.toHaveBeenCalled();
    });
  });
});
