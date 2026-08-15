import { describe, it, expect, beforeAll, afterAll } from 'vitest';
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

  afterAll(() => {
    delete process.env.MCP_SCAN_HOME;
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  it('should run a full scan on a vulnerable fixture and find issues', async () => {
    const fixturePath = path.join(__dirname, 'fixtures/vulnerable-config.json');
    const report = await runScan({ config: fixturePath, silent: true });

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
    const report = await runScan({ config: fixturePath, silent: true });

    expect(report.totalScanned).toBeGreaterThan(0);
    // malicious-config.json has known malicious packages
    expect(report.criticalCount).toBeGreaterThan(0);
    
    const elonResult = report.results.find(r => r.serverName === 'what-would-elon-do');
    expect(elonResult).toBeDefined();
    expect(elonResult?.findings.some(f => f.id === 'known-malicious')).toBe(true);
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
});
