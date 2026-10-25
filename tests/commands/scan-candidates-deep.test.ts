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

  it('runs candidate checks under npx.cmd and keeps the registry and env', async () => {
    const { runScan } = await import('../../src/commands/scan.js');
    const cfg = path.join(home, 'mcp.json');
    fs.writeFileSync(cfg, JSON.stringify({ mcpServers: { s: {
      command: 'C:\\nodejs\\NPX.CMD',
      args: ['--registry=http://e.example', '--made-up-flag', 'first-pkg', 'second-pkg'],
      env: { npm_config_userconfig: './x' },
    } } }));
    await runScan({ config: cfg, silent: true, offline: true });
    const alt = (deep.mock.calls as any[]).map(c => c[0]).find(s => s.args.includes('second-pkg') && !s.args.includes('first-pkg'));
    expect(alt?.args).toContain('--registry=http://e.example');
  });

  it('applies blockedPackages under an uppercase npx.cmd', async () => {
    const { runScan } = await import('../../src/commands/scan.js');
    const cfg = path.join(home, 'mcp.json');
    fs.writeFileSync(cfg, JSON.stringify({ mcpServers: { s: { command: 'NPX.CMD', args: ['-y', 'evil-pkg'] } } }));
    fs.writeFileSync(path.join(home, '.mcp-scan.json'), JSON.stringify({ blockedPackages: ['evil-pkg'] }));
    const cwd = process.cwd();
    process.chdir(home);
    try {
      const report = await runScan({ config: cfg, silent: true, offline: true });
      const ids = report.results.flatMap(r => r.findings.map(f => f.id));
      expect(ids).toContain('blocked-package-policy');
    } finally {
      process.chdir(cwd);
    }
  });

  it('does not carry a registry flag that comes after the package', async () => {
    const { runScan } = await import('../../src/commands/scan.js');
    const cfg = path.join(home, 'mcp.json');
    fs.writeFileSync(cfg, JSON.stringify({ mcpServers: { s: { command: 'npx',
      args: ['--made-up-flag', 'first-pkg', 'second-pkg', '--registry=http://own.example'] } } }));
    await runScan({ config: cfg, silent: true, offline: true });
    const alts = (deep.mock.calls as any[]).map(c => c[0]).filter(s => !s.args.includes('first-pkg'));
    expect(alts.length).toBeGreaterThan(0);
    for (const a of alts) expect(a.args).not.toContain('--registry=http://own.example');
  });

  it('carries a registry flag that sits between two candidates', async () => {
    const { runScan } = await import('../../src/commands/scan.js');
    const cfg = path.join(home, 'mcp.json');
    fs.writeFileSync(cfg, JSON.stringify({ mcpServers: { s: { command: 'npx',
      args: ['--made-up', 'a-pkg', '--registry=http://r.example', 'b-pkg'] } } }));
    await runScan({ config: cfg, silent: true, offline: true });
    const alts = (deep.mock.calls as any[]).map(c => c[0]).filter(s => s.args.length <= 2);
    expect(alts.length).toBeGreaterThan(0);
    for (const a of alts) expect(a.args).toContain('--registry=http://r.example');
  });
});
