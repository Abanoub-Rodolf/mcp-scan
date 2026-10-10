import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { scanPackageDeep } from '../../src/scanners/package-scanner.js';
import { loadCveSnapshot } from '../../src/utils/cve-snapshot.js';
import { logger } from '../../src/utils/logger.js';
import { ResolvedServer } from '../../src/types/config.js';

vi.mock('../../src/utils/cve-snapshot.js', () => ({ loadCveSnapshot: vi.fn() }));

const server = (pkg: string): ResolvedServer => ({
  name: 's', toolName: 't', configPath: '/c.json', command: 'npx', args: [pkg],
  schema: {}, description: '', env: {}, disabled: false,
} as ResolvedServer);

describe('offline CVE check on a malformed snapshot', () => {
  // --json/--ci set isSilent, and that is exactly when CI must still see the failure
  let stderr: () => string;
  beforeEach(() => {
    vi.clearAllMocks();
    logger.isSilent = true;
    const w = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    stderr = () => w.mock.calls.map(c => String(c[0])).join('');
  });
  afterEach(() => { logger.isSilent = false; vi.restoreAllMocks(); });

  it('warns that the check did not finish instead of reading as no vulnerabilities', async () => {
    // a null entry in vulns throws inside the lookup
    vi.mocked(loadCveSnapshot).mockReturnValue({
      raw: { updatedAt: new Date().toISOString(), packages: { 'bad-snap': { version: '1.0.0', vulns: [null as any] } } },
    });
    const findings = await scanPackageDeep(server('bad-snap'), true);
    expect(findings).toEqual([]);
    expect(stderr()).toMatch(/Offline CVE check for 'bad-snap' failed .*incomplete/);
  });

  it('warns once per failure, with control characters stripped from the name', async () => {
    vi.mocked(loadCveSnapshot).mockReturnValue({
      raw: { updatedAt: new Date().toISOString(), packages: { 'evil\x1b[2Jpkg': { version: '1.0.0', vulns: [null as any] } } },
    });
    await scanPackageDeep(server('evil\x1b[2Jpkg'), true);
    await scanPackageDeep(server('evil\x1b[2Jpkg'), true);
    expect(stderr().match(/Offline CVE check/g)).toHaveLength(1);
    expect(stderr()).not.toContain('\x1b');
    expect(stderr()).toContain("'evil?[2Jpkg'");
  });

  it('stays quiet on a healthy snapshot', async () => {
    vi.mocked(loadCveSnapshot).mockReturnValue({
      raw: { updatedAt: new Date().toISOString(), packages: { 'ok-snap': { version: '1.0.0', vulns: [] } } },
    });
    await scanPackageDeep(server('ok-snap'), true);
    expect(stderr()).not.toContain('Offline CVE check');
  });
});
