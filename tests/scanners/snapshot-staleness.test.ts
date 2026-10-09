import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ResolvedServer } from '../../src/types/config.js';

vi.mock('../../src/utils/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), detail: vi.fn(), log: vi.fn(), brand: vi.fn(), isVerbose: false },
}));

const server = (pkg: string): ResolvedServer => ({
  name: `${pkg}-server`, toolName: 'mock-tool', configPath: '/p/config.json',
  command: 'npx', args: [pkg], schema: {}, description: '', env: {}, disabled: false,
});

// The bundled snapshot is dated 2026-08-15, so it is stale for any run past
// mid-September 2026. Pin the clock anyway so the test does not depend on it.
describe('stale CVE snapshot warning', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2027-01-01'));
  });

  async function load() {
    const { scanPackageDeep } = await import('../../src/scanners/package-scanner.js');
    const { logger } = await import('../../src/utils/logger.js');
    vi.mocked(logger.warn).mockClear();
    return { scanPackageDeep, warn: vi.mocked(logger.warn) };
  }

  it('prints once per run, not once per server', async () => {
    const { scanPackageDeep, warn } = await load();
    for (const p of ['alpha-pkg', 'beta-pkg', 'gamma-pkg']) await scanPackageDeep(server(p), true);
    const stale = warn.mock.calls.filter(c => String(c[0]).includes('days old'));
    expect(stale).toHaveLength(1);
  });

  it('does not point installed users at an npm script that only exists in the repo', async () => {
    const { scanPackageDeep, warn } = await load();
    await scanPackageDeep(server('alpha-pkg'), true);
    const msg = String(warn.mock.calls.find(c => String(c[0]).includes('days old'))?.[0]);
    expect(msg).not.toContain('npm run');
    expect(msg).toMatch(/[Uu]pgrade/);
  });
});
