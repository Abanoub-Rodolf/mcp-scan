import { describe, it, expect } from 'vitest';
import { scanTyposquat } from '../../src/scanners/typosquat-scanner.js';
import { scanSupplyChain } from '../../src/scanners/supply-chain-scanner.js';
import { scanPackageDeep } from '../../src/scanners/package-scanner.js';
import { scanRegistry } from '../../src/scanners/registry-scanner.js';

const srv = (command: string, args: string[]) => ({ name: 'test', toolName: 't', configPath: 'p', command, args });
// npx.cmd on Windows, full paths, and case-insensitive filesystems all run npx.
const FORMS: Array<[string, string[]]> = [
  ['NPX.CMD', ['-y', 'server-githb']],
  ['npx.cmd', ['-y', 'server-githb']],
  ['/usr/local/bin/npx', ['-y', 'server-githb']],
  ['npx.ps1', ['-y', 'server-githb']],
  ['NPM.BAT', ['exec', 'server-githb']],
  ['C:\\nodejs\\NPM.CMD', ['exec', 'server-githb']],
];

describe('launcher command forms', () => {
  it.each(FORMS)('typosquat grades the package under %s', (command, args) => {
    expect(scanTyposquat(srv(command, args)).map(f => f.id)).toEqual(['typosquat-detection']);
  });

  it.each(FORMS)('supply chain grades the package under %s', async (command, args) => {
    const want = await scanSupplyChain(srv('npx', ['-y', 'server-githb']), true);
    expect(await scanSupplyChain(srv(command, args), true)).toEqual(want);
  });

  it.each(FORMS)('deep package checks run under %s', async (command, args) => {
    // mcp-server-git has advisories in the offline snapshot, so this can't pass empty.
    const pkgArgs = args.map(a => a === 'server-githb' ? 'mcp-server-git' : a);
    const want = await scanPackageDeep(srv('npx', ['-y', 'mcp-server-git']), true);
    expect(want.length).toBeGreaterThan(0);
    expect(await scanPackageDeep(srv(command, pkgArgs), true)).toEqual(want);
  });

  // A local binary has no registry artifact, so its file name earns no trust.
  it('grants no allowlist trust to a path-launched binary', async () => {
    const ids = (await scanRegistry(srv('/x/redis-mcp', []), true)).map(f => f.id);
    expect(ids).not.toContain('trusted-community-server');
  });
});
