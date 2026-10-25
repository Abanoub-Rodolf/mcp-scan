import { describe, it, expect, vi, beforeEach } from 'vitest';
import { scanRegistry } from '../../src/scanners/registry-scanner.js';

const mockFetch = vi.fn();
global.fetch = mockFetch;

vi.mock('../../src/utils/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), detail: vi.fn(), log: vi.fn(), brand: vi.fn(), isVerbose: false },
}));

const scan = (args: string[], env?: Record<string, string>, command = 'npx') =>
  scanRegistry({ name: 'test', toolName: 't', configPath: 'p', command, args, env }, true);
const custom = (fs: Awaited<ReturnType<typeof scan>>) => fs.filter(f => f.id === 'custom-registry');

describe('custom npm registry', () => {
  beforeEach(() => mockFetch.mockReset());

  it('flags --registry= with an https host other than npmjs as MEDIUM', async () => {
    const f = custom(await scan(['-y', '--registry=https://npm.evil.example', 'some-mcp']));
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('MEDIUM');
    expect(f[0].description).toContain('npm.evil.example');
  });

  it('flags a plain http registry as HIGH, scheme case-insensitive', async () => {
    const f = custom(await scan(['-y', '--registry=HTTP://npm.evil.example', 'some-mcp']));
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('HIGH');
  });

  it('reads the space-separated --registry form', async () => {
    const f = custom(await scan(['--registry', 'https://npm.evil.example', '-y', 'some-mcp']));
    expect(f).toHaveLength(1);
  });

  it('reads scoped registries', async () => {
    const f = custom(await scan(['-y', '--@acme:registry=https://npm.acme.example', '@acme/mcp']));
    expect(f).toHaveLength(1);
    expect(f[0].description).toContain('@acme');
  });

  it('reads registry overrides from the server env, any key case', async () => {
    expect(custom(await scan(['-y', 'some-mcp'], { NPM_CONFIG_REGISTRY: 'https://npm.evil.example' }))).toHaveLength(1);
    expect(custom(await scan(['-y', 'some-mcp'], { npm_config_registry: 'http://npm.evil.example' }))[0].severity).toBe('HIGH');
    expect(custom(await scan(['-y', '@acme/mcp'], { 'npm_config_@acme:registry': 'https://npm.acme.example' }))).toHaveLength(1);
  });

  it('works for npm exec too', async () => {
    expect(custom(await scan(['exec', '--registry=https://npm.evil.example', '--', 'some-mcp'], undefined, 'npm'))).toHaveLength(1);
  });

  it('does not flag the default registry', async () => {
    expect(custom(await scan(['-y', '--registry=https://registry.npmjs.org/', 'some-mcp']))).toHaveLength(0);
    expect(custom(await scan(['-y', 'some-mcp'], { NPM_CONFIG_REGISTRY: 'https://registry.npmjs.org' }))).toHaveLength(0);
  });

  it('does not vouch for an official package name served from a custom registry', async () => {
    const fs = await scan(['-y', '--registry=https://npm.evil.example', '@modelcontextprotocol/server-filesystem']);
    expect(custom(fs)).toHaveLength(1);
    expect(fs.some(f => f.id === 'official-server')).toBe(false);
  });

  it('still blocks a known malicious package behind a custom registry', async () => {
    const fs = await scan(['-y', '--registry=https://npm.evil.example', 'postmark-mcp']);
    expect(fs.some(f => f.id === 'known-malicious')).toBe(true);
    expect(custom(fs)).toHaveLength(1);
  });

  it('ignores registry flags on non-npm commands', async () => {
    expect(custom(await scan(['--registry=https://npm.evil.example'], undefined, 'node'))).toHaveLength(0);
  });

  it('trims env values before grading the scheme', async () => {
    expect(custom(await scan(['-y', 'some-mcp'], { NPM_CONFIG_REGISTRY: ' http://npm.evil.example ' }))[0].severity).toBe('HIGH');
  });

  it('flags plain http even to the npm registry host', async () => {
    const f = custom(await scan(['-y', '--registry=http://registry.npmjs.org', 'some-mcp']));
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('HIGH');
  });

  it('does not take a following flag as the registry value', async () => {
    expect(custom(await scan(['--registry', '--yes', 'some-mcp']))).toHaveLength(0);
  });

  it('reports one finding for a registry set twice', async () => {
    expect(custom(await scan(['-y', '--registry=https://npm.evil.example', 'some-mcp'], { npm_config_registry: 'https://npm.evil.example' }))).toHaveLength(1);
  });

  it('skips the npmjs provenance lookup when a custom registry is set', async () => {
    const fs = await scanRegistry({ name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', '--registry=https://npm.evil.example', 'some-mcp'] }, false);
    expect(mockFetch).not.toHaveBeenCalled();
    expect(fs.some(f => f.id === 'unverified-source' || f.id === 'provenance-verified')).toBe(false);
  });

  it('reads abbreviated registry flags the way npm does', async () => {
    expect(custom(await scan(['--reg=http://npm.evil.example', 'some-mcp']))[0].severity).toBe('HIGH');
    expect(custom(await scan(['-regi=https://npm.evil.example', 'some-mcp']))).toHaveLength(1);
    expect(custom(await scan(['--reg', 'https://npm.evil.example', 'some-mcp']))).toHaveLength(1);
  });

  it('flags a config file that can set the registry', async () => {
    expect(custom(await scan(['--userconfig=./evil.npmrc', 'some-mcp']))[0].description).toContain('evil.npmrc');
    expect(custom(await scan(['--globalconfig', '/tmp/rc', 'some-mcp']))).toHaveLength(1);
    expect(custom(await scan(['some-mcp'], { NPM_CONFIG_USERCONFIG: './evil.npmrc' }))).toHaveLength(1);
  });

  it('ignores a --registry npx passes through to the package', async () => {
    expect(custom(await scan(['-y', 'some-mcp', '--registry=https://ghcr.io']))).toHaveLength(0);
  });

  it('still reads flags after the package for npm exec', async () => {
    expect(custom(await scan(['exec', 'some-mcp', '--registry=https://npm.evil.example'], undefined, 'npm'))).toHaveLength(1);
  });

  it('reads object-shaped args', async () => {
    const fs = await scanRegistry({ name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: { a: '--registry=https://npm.evil.example', b: 'some-mcp' } as unknown as string[] }, true);
    expect(custom(fs)).toHaveLength(1);
  });

  it.each([
    'https://registry.npmjs.org.evil.example',
    'https://registry.npmjs.org@evil.example',
    'https://REGISTRY.npmjs.org.evil.example',
    'https://registry.npmjs.org./',
  ])('does not take %s for the npm registry', async (url) => {
    expect(custom(await scan(['--registry=' + url, 'some-mcp']))[0]?.severity).toBe('MEDIUM');
  });

  it('survives non-string args, env values and bad urls', async () => {
    const fs = await scanRegistry({ name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: [42, null, '--registry=not a url', 'some-mcp'] as unknown as string[],
      env: { npm_config_registry: 7 } as unknown as Record<string, string> }, true);
    expect(custom(fs)).toHaveLength(1);
  });

  it.each([
    ['--loglevel', 'warn', '--registry', 'http://e.example', 'pkg'],
    ['--fetch-retries', '2', '--registry=http://e.example', 'pkg'],
    ['--foo', 'bar', '--registry', 'http://e.example', '@modelcontextprotocol/server-everything'],
  ])('reads a --registry after another valued flag: %j', async (...args) => {
    expect(custom(await scan(args))[0]?.severity).toBe('HIGH');
  });

  it('still stops at the package after a consumed --registry value', async () => {
    expect(custom(await scan(['--registry', 'https://registry.npmjs.org', 'pkg', '--registry', 'http://own.example']))).toHaveLength(0);
  });

  it.each(['/usr/local/bin/npx', 'npx.cmd', 'C:\\nodejs\\npm.cmd'])('normalizes the %s command', async (command) => {
    const args = command.includes('npm') ? ['exec', '--registry=http://e.example', 'pkg'] : ['-y', '--registry=http://e.example', 'pkg'];
    expect(custom(await scan(args, undefined, command))).toHaveLength(1);
  });

  it('flags --prefix LOW, naming the npmrc it selects', async () => {
    const f = custom(await scan(['--prefix', '/x', 'pkg']));
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('LOW');
    expect(f[0].description).toContain('/x/etc/npmrc');
  });

  it('stops at the package after a known boolean like --timing', async () => {
    expect(custom(await scan(['--timing', 'some-mcp', '--registry=http://own.example']))).toHaveLength(0);
  });

  it('applies the prefix rule to flags only, not env names', async () => {
    expect(custom(await scan(['pkg'], { npm_config_reg: 'http://e.example' }))).toHaveLength(0);
    expect(custom(await scan(['pkg'], { NPM_CONFIG_REGISTRY: 'http://e.example' }))).toHaveLength(1);
  });

  it('keeps the npm checks when only another scope is overridden', async () => {
    const fs = await scan(['--@acme:registry=https://acme.example', 'evil-pkg']);
    expect(custom(fs)).toHaveLength(1);
    expect(fs.some(f => f.id === 'unverified-source')).toBe(true);
  });

  it.each([['--audit'], ['-yq']])('stops at the package after boolean %s', async (flag) => {
    expect(custom(await scan([flag, 'pkg', '--registry', 'https://c.io']))).toHaveLength(0);
  });

  it('reads abbreviated config flags but not abbreviated env keys', async () => {
    expect(custom(await scan(['--userconf=./x', 'pkg']))).toHaveLength(1);
    expect(custom(await scan(['pkg'], { npm_config_userconf: './x' }))).toHaveLength(0);
  });

  it('matches the command case-insensitively', async () => {
    expect(custom(await scan(['--registry=https://c.io', 'pkg'], undefined, 'NPX.CMD'))).toHaveLength(1);
  });

  it('needs an unambiguous prefix for globalconfig', async () => {
    expect(custom(await scan(['--globa=/x', 'pkg']))).toHaveLength(0);
    expect(custom(await scan(['--globalc=/x', 'pkg']))).toHaveLength(1);
  });
});
