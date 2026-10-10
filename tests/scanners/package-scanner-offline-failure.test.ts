import { describe, it, expect, vi, beforeEach } from 'vitest';
import { scanPackageDeep } from '../../src/scanners/package-scanner.js';
import { loadCveSnapshot } from '../../src/utils/cve-snapshot.js';
import { logger } from '../../src/utils/logger.js';
import { ResolvedServer } from '../../src/types/config.js';

vi.mock('../../src/utils/cve-snapshot.js', () => ({ loadCveSnapshot: vi.fn() }));
vi.mock('../../src/utils/logger.js', () => ({ logger: { warn: vi.fn(), info: vi.fn(), detail: vi.fn() } }));

const server = (pkg: string): ResolvedServer => ({
  name: 's', toolName: 't', configPath: '/c.json', command: 'npx', args: [pkg],
  schema: {}, description: '', env: {}, disabled: false,
} as ResolvedServer);

describe('offline CVE check on a malformed snapshot', () => {
  beforeEach(() => vi.clearAllMocks());

  it('warns that the check did not finish instead of reading as no vulnerabilities', async () => {
    // a null entry in vulns throws inside the lookup
    vi.mocked(loadCveSnapshot).mockReturnValue({
      raw: { updatedAt: new Date().toISOString(), packages: { 'bad-snap': { version: '1.0.0', vulns: [null as any] } } },
    });
    const findings = await scanPackageDeep(server('bad-snap'), true);
    expect(findings).toEqual([]);
    expect(logger.warn).toHaveBeenCalledWith(expect.stringMatching(/Offline CVE check for 'bad-snap' failed .*incomplete/));
  });

  it('stays quiet on a healthy snapshot', async () => {
    vi.mocked(loadCveSnapshot).mockReturnValue({
      raw: { updatedAt: new Date().toISOString(), packages: { 'ok-snap': { version: '1.0.0', vulns: [] } } },
    });
    await scanPackageDeep(server('ok-snap'), true);
    expect(logger.warn).not.toHaveBeenCalled();
  });
});
