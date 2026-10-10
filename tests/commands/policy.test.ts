import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { runScan } from '../../src/commands/scan.js';
import fs from 'fs';
import os from 'os';
import path from 'path';

// Real files in a temp cwd: the loaders open and fstat the policy, so the
// old whole-module fs mock no longer describes what they do.
describe('Policy Engine', () => {
  let dir: string;
  let home: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-policy-scan-'));
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-policy-scan-home-'));
    process.env.MCP_SCAN_HOME = home;
    vi.spyOn(process, 'cwd').mockReturnValue(dir);
    vi.spyOn(os, 'homedir').mockReturnValue(home);
  });
  afterEach(() => {
    vi.restoreAllMocks();
    delete process.env.MCP_SCAN_HOME;
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  });

  const scanWith = async (policy: object, args: string[]) => {
    fs.writeFileSync(path.join(dir, '.mcp-scan.json'), JSON.stringify(policy));
    const config = path.join(dir, 'config.json');
    fs.writeFileSync(config, JSON.stringify({ mcpServers: { 'test-server': { command: 'npx', args } } }));
    const report = await runScan({ silent: true, config, offline: true });
    return report.results.find(r => r.serverName === 'test-server');
  };

  it('should apply blockedPackages policy', async () => {
    const result = await scanWith({ blockedPackages: ['malicious-pkg'] }, ['malicious-pkg']);
    expect(result?.findings.some(f => f.id === 'blocked-package-policy')).toBe(true);
  });

  it('should apply suppressRules policy', async () => {
    const result = await scanWith({ suppressRules: ['unverified-source'] }, ['@some/pkg']);
    expect(result?.findings.some(f => f.id === 'unverified-source')).toBe(false);
  });
});
