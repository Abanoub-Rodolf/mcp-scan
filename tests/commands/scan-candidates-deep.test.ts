import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

const deep = vi.fn(async () => []);
const chain = vi.fn(async () => ({ findings: [], trustScore: 50, metadata: { source: 'local' } }));
vi.mock('../../src/scanners/package-scanner.js', async (orig) => ({
  ...(await orig<typeof import('../../src/scanners/package-scanner.js')>()),
  scanPackageDeep: deep,
}));
vi.mock('../../src/scanners/supply-chain-scanner.js', async (orig) => ({
  ...(await orig<typeof import('../../src/scanners/supply-chain-scanner.js')>()),
  scanSupplyChain: chain,
}));

describe('scan runs the deeper package checks on every candidate', () => {
  let home: string;
  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-deep-'));
    process.env.MCP_SCAN_HOME = home;
    deep.mockClear();
    chain.mockClear();
  });
  afterEach(() => {
    delete process.env.MCP_SCAN_HOME;
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('covers the non-primary candidate behind an unknown flag', async () => {
    const { runScan } = await import('../../src/commands/scan.js');
    const cfg = path.join(home, 'mcp.json');
    fs.writeFileSync(cfg, JSON.stringify({ mcpServers: { s: { command: 'npx', args: ['--made-up-flag', 'first-pkg', 'second-pkg'] } } }));
    await runScan({ config: cfg, silent: true, offline: true });
    for (const spy of [deep, chain]) {
      const argLists = (spy.mock.calls as any[]).map(c => c[0].args.join(' '));
      expect(argLists).toContain('second-pkg');
    }
  });
});
