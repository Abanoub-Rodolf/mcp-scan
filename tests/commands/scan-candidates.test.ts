import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { runScan } from '../../src/commands/scan.js';

describe('scan grades every package candidate behind an unknown flag', () => {
  let home: string;
  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-cands-'));
    process.env.MCP_SCAN_HOME = home;
  });
  afterEach(() => {
    delete process.env.MCP_SCAN_HOME;
    fs.rmSync(home, { recursive: true, force: true });
  });

  const scanArgs = async (args: string[]) => {
    const cfg = path.join(home, 'mcp.json');
    fs.writeFileSync(cfg, JSON.stringify({ mcpServers: { s: { command: 'npx', args } } }));
    const report = await runScan({ config: cfg, silent: true, offline: true });
    return report.results.flatMap(r => r.findings);
  };

  it('finds a typosquat in the second slot', async () => {
    const base = (await scanArgs(['--made-up-flag', 'random-name', 'x'])).map(f => f.id);
    const found = await scanArgs(['--made-up-flag', 'random-name', '@modelcontextprotocol/server-filesytem']);
    expect(found.some(f => f.id.includes('typosquat'))).toBe(true);
    expect(base.some(id => id.includes('typosquat'))).toBe(false);
  });

  it('the blocked-package policy matches a versioned spec', async () => {
    const cfg = path.join(home, 'mcp.json');
    fs.writeFileSync(cfg, JSON.stringify({ mcpServers: { s: { command: 'npx', args: ['-y', 'blocked-pkg@1.2.3'] } } }));
    fs.writeFileSync(path.join(home, '.mcp-scan.json'), JSON.stringify({ blockedPackages: ['blocked-pkg'] }));
    const cwd = process.cwd();
    process.chdir(home);
    try {
      const report = await runScan({ config: cfg, silent: true, offline: true });
      expect(report.results.flatMap(r => r.findings).some(f => f.id === 'blocked-package-policy')).toBe(true);
    } finally {
      process.chdir(cwd);
    }
  });
});
