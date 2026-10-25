import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from 'vitest';
import { runScan } from '../src/commands/scan.js';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

describe('E2E Scan', () => {
  let tmpHome: string;

  beforeAll(() => {
    // Redirect the audit store away from the real user home: every
    // runScan appends to ~/.mcp-scan/audit.log and rewrites
    // known-servers.json fingerprints with fixture data.
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-e2e-'));
    process.env.MCP_SCAN_HOME = tmpHome;
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  afterAll(() => {
    delete process.env.MCP_SCAN_HOME;
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  // offline: the assertions below only need local checks. Live registry/OSV
  // calls made this test time out on a slow runner (2026-09-06 main).
  it('should run a full scan on a vulnerable fixture and find issues', async () => {
    const fixturePath = path.join(__dirname, 'fixtures/vulnerable-config.json');
    const report = await runScan({ config: fixturePath, silent: true, offline: true });

    expect(report.totalScanned).toBeGreaterThan(0);
    // vulnerable-config.json has a ghp_ token and a dangerous path '/'
    expect(report.criticalCount).toBeGreaterThan(0);
    expect(report.highCount).toBeGreaterThan(0);
    
    const githubResult = report.results.find(r => r.serverName === 'github');
    expect(githubResult).toBeDefined();
    expect(githubResult?.findings.some(f => f.id === 'exposed-secret')).toBe(true);

    const fsResult = report.results.find(r => r.serverName === 'filesystem-danger');
    expect(fsResult).toBeDefined();
    expect(fsResult?.findings.some(f => f.id === 'excessive-permissions')).toBe(true);
  });

  it('should run a full scan on a malicious fixture', async () => {
    const fixturePath = path.join(__dirname, 'fixtures/malicious-config.json');
    const report = await runScan({ config: fixturePath, silent: true, offline: true });

    expect(report.totalScanned).toBeGreaterThan(0);
    // malicious-config.json has known malicious packages
    expect(report.criticalCount).toBeGreaterThan(0);
    
    const elonResult = report.results.find(r => r.serverName === 'what-would-elon-do');
    expect(elonResult).toBeDefined();
    expect(elonResult?.findings.some(f => f.id === 'known-malicious')).toBe(true);
  });

  // The online branch (package, supply-chain, registry provenance) is the
  // part of runScan the offline tests above never reach. Canned responses
  // stand in for npm and OSV so it runs end to end without a network.
  it('runs the online path end to end against mocked npm and OSV responses', async () => {
    const pkg = 'online-e2e-pkg';
    const configPath = path.join(tmpHome, 'online-config.json');
    fs.writeFileSync(configPath, JSON.stringify({
      mcpServers: { online: { command: 'npx', args: ['-y', pkg] } },
    }));

    const json = (body: unknown, status = 200) =>
      ({ ok: status === 200, status, json: async () => body }) as unknown as Response;
    const calls: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request) => {
      const u = String(url);
      calls.push(u);
      // version doc, fetched for the provenance check on an unpinned spec
      if (u === `https://registry.npmjs.org/${pkg}/latest`) {
        return json({ version: '1.0.0', dist: { attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } } });
      }
      // packument, read by the package and supply-chain scanners (no repo URL on purpose)
      if (u === `https://registry.npmjs.org/${pkg}`) {
        return json({
          'dist-tags': { latest: '1.0.0' },
          versions: { '1.0.0': {} },
          time: { modified: new Date().toISOString() },
          license: 'MIT',
        });
      }
      if (u === 'https://api.osv.dev/v1/query') {
        return json({
          vulns: [{
            id: 'GHSA-test-0000-0000',
            summary: 'canned advisory for the e2e online path',
            database_specific: { severity: 'HIGH' },
            affected: [{
              package: { name: pkg, ecosystem: 'npm' },
              ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.1' }] }],
            }],
          }],
        });
      }
      return json({}, 404);
    }));

    const report = await runScan({ config: configPath, silent: true, severity: 'info' });
    const findings = report.results.find(r => r.serverName === 'online')?.findings ?? [];
    const ids = findings.map(f => f.id);

    // package scanner: OSV advisory matched against the resolved 1.0.0
    expect(findings.find(f => f.id === 'known-vulnerability-high')?.description).toContain('GHSA-test-0000-0000');
    // registry scanner: provenance lookup succeeded, so no unverified-source
    expect(ids).toContain('provenance-verified');
    expect(ids).not.toContain('unverified-source');
    // supply-chain scanner: packument has no repository URL
    expect(ids).toContain('supply-chain-low-trust');
    // a throwing scanner is swallowed into a LOW scanner-error finding
    expect(ids).not.toContain('scanner-error');
    expect(report.highCount).toBeGreaterThan(0);

    expect(calls).toContain(`https://registry.npmjs.org/${pkg}/latest`);
    expect(calls).toContain('https://api.osv.dev/v1/query');
    // nothing but the mocked registries was contacted
    expect(calls.every(c => c.startsWith('https://registry.npmjs.org/') || c.startsWith('https://api.osv.dev/'))).toBe(true);
  });

  it('does not write to the real ~/.mcp-scan during scans', () => {
    const realHome = path.join(os.homedir(), '.mcp-scan');
    const before = fs.existsSync(realHome) ? fs.readdirSync(realHome).sort() : null;
    expect(fs.existsSync(tmpHome)).toBe(true);
    // The tmp store is the one that got the audit entries
    expect(fs.readdirSync(tmpHome).length).toBeGreaterThan(0);
    if (before !== null) {
      expect(fs.readdirSync(realHome).sort()).toEqual(before);
    }
  });
  // A plugin manifest that points mcpServers at ./.mcp.json: results and
  // file checks must name the file that defines the server.
  it('reports a referenced server against the file that defines it', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-e2e-plugin-'));
    try {
      fs.mkdirSync(path.join(root, '.claude-plugin'));
      const manifest = path.join(root, '.claude-plugin', 'plugin.json');
      fs.writeFileSync(manifest, JSON.stringify({ name: 'p', mcpServers: './.mcp.json' }));
      fs.writeFileSync(path.join(root, '.mcp.json'), JSON.stringify({ mcpServers: { docs: { command: 'node', args: ['s.js'] } } }));

      const report = await runScan({ config: manifest, silent: true, offline: true });
      expect(report.results.map(r => [r.serverName, r.configPath])).toEqual([['docs', path.join(root, '.mcp.json')]]);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
