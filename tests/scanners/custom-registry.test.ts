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
  });

  it('ignores registry flags on non-npm commands', async () => {
    expect(custom(await scan(['--registry=https://npm.evil.example'], undefined, 'node'))).toHaveLength(0);
  });
});
