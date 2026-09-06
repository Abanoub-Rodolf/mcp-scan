import { describe, it, expect, vi } from 'vitest';
import {
  resolveDependencies,
  queryOsvBatch,
  fetchVulnDetails,
  scanDependencyCves,
} from '../../src/scanners/osv-scanner.js';

vi.mock('../../src/utils/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), detail: vi.fn(), log: vi.fn(), brand: vi.fn(), isVerbose: false },
}));

// Same fixed vector->score table package-scanner.test.ts uses: pins the
// severity math to known values instead of trusting live CVSS parsing.
vi.mock('vuln-vects', () => ({
  parseCvssVector: vi.fn((score: string) => {
    if (score === 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H') return { baseScore: 9.8 };
    if (score === 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L') return { baseScore: 7.5 };
    if (score === 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L') return { baseScore: 5.0 };
    throw new Error('Invalid CVSS vector');
  }),
}));

const jsonResponse = (body: unknown, status = 200) => ({
  ok: status >= 200 && status < 300,
  status,
  headers: new Headers(),
  json: vi.fn().mockResolvedValue(body),
});

// Recorded (trimmed) fixture shaped like a real GET /v1/vulns/{id} response
// for a lodash prototype-pollution advisory - no live OSV calls in tests.
const LODASH_VULN = {
  id: 'GHSA-p6mc-m468-83gw',
  summary: 'Prototype Pollution in lodash',
  details: 'Versions of lodash prior to 4.17.21 are vulnerable to Prototype Pollution.',
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L' }],
  affected: [
    {
      package: { ecosystem: 'npm', name: 'lodash' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
    },
  ],
  references: [{ type: 'ADVISORY', url: 'https://github.com/advisories/GHSA-p6mc-m468-83gw' }],
};

describe('osv-scanner: resolveDependencies', () => {
  it('prefers a shipped lockfile version over registry resolution', async () => {
    const deps = await resolveDependencies(
      { dependencies: { lodash: '^4.17.0' } },
      { packages: { 'node_modules/lodash': { version: '4.17.15' } } }
    );
    expect(deps).toEqual([{ name: 'lodash', version: '4.17.15', resolvedFrom: 'lockfile' }]);
  });

  it('falls back to a registry lookup when no lockfile is shipped', async () => {
    const mockFetch = vi.fn().mockResolvedValue(jsonResponse({
      'dist-tags': { latest: '4.17.21' },
      versions: { '4.17.15': {}, '4.17.21': {} },
    }));
    global.fetch = mockFetch as unknown as typeof fetch;

    const deps = await resolveDependencies({ dependencies: { lodash: '^4.17.0' } }, null);
    expect(deps).toEqual([{ name: 'lodash', version: '4.17.21', resolvedFrom: 'manifest-range' }]);
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(mockFetch.mock.calls[0][0]).toBe('https://registry.npmjs.org/lodash');
  });

  it('drops a dependency whose version cannot be resolved instead of guessing', async () => {
    global.fetch = vi.fn().mockResolvedValue(jsonResponse({}, 404)) as unknown as typeof fetch;
    const deps = await resolveDependencies({ dependencies: { 'ghost-pkg': '^1.0.0' } }, null);
    expect(deps).toEqual([]);
  });

  it('returns an empty list for a package with no dependencies', async () => {
    expect(await resolveDependencies({}, null)).toEqual([]);
  });
});

describe('osv-scanner: queryOsvBatch', () => {
  it('chunks requests at 100 dependencies per call', async () => {
    const deps = Array.from({ length: 150 }, (_, i) => ({ name: `pkg${i}`, version: '1.0.0', resolvedFrom: 'lockfile' as const }));
    const mockFetch = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ results: Array.from({ length: 100 }, () => ({ vulns: [] })) }))
      .mockResolvedValueOnce(jsonResponse({ results: Array.from({ length: 50 }, () => ({ vulns: [] })) }));
    global.fetch = mockFetch as unknown as typeof fetch;

    await queryOsvBatch(deps);
    expect(mockFetch).toHaveBeenCalledTimes(2);
    const firstBody = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(firstBody.queries).toHaveLength(100);
    const secondBody = JSON.parse(mockFetch.mock.calls[1][1].body);
    expect(secondBody.queries).toHaveLength(50);
  });

  it('maps returned vuln ids back to the dependency at the same index', async () => {
    const deps = [{ name: 'lodash', version: '4.17.15', resolvedFrom: 'lockfile' as const }, { name: 'left-pad', version: '1.0.0', resolvedFrom: 'lockfile' as const }];
    global.fetch = vi.fn().mockResolvedValue(jsonResponse({
      results: [{ vulns: [{ id: 'GHSA-p6mc-m468-83gw' }] }, { vulns: [] }],
    })) as unknown as typeof fetch;

    const { vulnIdsByDep, failedDepNames } = await queryOsvBatch(deps);
    expect(vulnIdsByDep).toEqual([['GHSA-p6mc-m468-83gw'], []]);
    expect(failedDepNames).toEqual([]);
  });

  it('retries once on a 429 then succeeds', async () => {
    const mockFetch = vi.fn()
      .mockResolvedValueOnce(jsonResponse({}, 429))
      .mockResolvedValueOnce(jsonResponse({ results: [{ vulns: [] }] }));
    global.fetch = mockFetch as unknown as typeof fetch;

    const { vulnIdsByDep, failedDepNames } = await queryOsvBatch([{ name: 'lodash', version: '4.17.15', resolvedFrom: 'lockfile' }]);
    expect(mockFetch).toHaveBeenCalledTimes(2);
    expect(vulnIdsByDep).toEqual([[]]);
    expect(failedDepNames).toEqual([]);
  }, 10000);

  it('reports the chunk as failed, not clean, when it exhausts retries on 500s', async () => {
    global.fetch = vi.fn().mockResolvedValue(jsonResponse({}, 500)) as unknown as typeof fetch;
    const { vulnIdsByDep, failedDepNames } = await queryOsvBatch([{ name: 'lodash', version: '4.17.15', resolvedFrom: 'lockfile' }]);
    expect(vulnIdsByDep).toEqual([[]]);
    expect(failedDepNames).toEqual(['lodash']);
  }, 15000);

  it('marks a dependency as failed rather than clean when the response returns fewer results than queried', async () => {
    const deps = [{ name: 'lodash', version: '4.17.15', resolvedFrom: 'lockfile' as const }, { name: 'left-pad', version: '1.0.0', resolvedFrom: 'lockfile' as const }];
    global.fetch = vi.fn().mockResolvedValue(jsonResponse({ results: [{ vulns: [] }] })) as unknown as typeof fetch;

    const { vulnIdsByDep, failedDepNames } = await queryOsvBatch(deps);
    expect(vulnIdsByDep).toEqual([[], []]);
    expect(failedDepNames).toEqual(['left-pad']);
  });

  it('treats a malformed (non-JSON) 200 response as a failed chunk instead of throwing', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers(),
      json: vi.fn().mockRejectedValue(new Error('unexpected token')),
    }) as unknown as typeof fetch;

    const { vulnIdsByDep, failedDepNames } = await queryOsvBatch([{ name: 'lodash', version: '4.17.15', resolvedFrom: 'lockfile' }]);
    expect(vulnIdsByDep).toEqual([[]]);
    expect(failedDepNames).toEqual(['lodash']);
  });
});

describe('osv-scanner: fetchVulnDetails', () => {
  it('dedups repeated ids into a single request', async () => {
    const mockFetch = vi.fn().mockResolvedValue(jsonResponse(LODASH_VULN));
    global.fetch = mockFetch as unknown as typeof fetch;

    const { found, failedIds } = await fetchVulnDetails(['GHSA-p6mc-m468-83gw', 'GHSA-p6mc-m468-83gw']);
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(found.get('GHSA-p6mc-m468-83gw')?.summary).toBe('Prototype Pollution in lodash');
    expect(failedIds).toEqual([]);
  });

  it('reports an id whose fetch fails after retries as failed rather than silently dropping it', async () => {
    global.fetch = vi.fn().mockResolvedValue(jsonResponse({}, 404)) as unknown as typeof fetch;
    const { found, failedIds } = await fetchVulnDetails(['does-not-exist']);
    expect(found.size).toBe(0);
    expect(failedIds).toEqual(['does-not-exist']);
  });
});

describe('osv-scanner: scanDependencyCves end to end', () => {
  it('reports a confirmed dependency vulnerability with advisory metadata', async () => {
    const mockFetch = vi.fn()
      // resolveDependencies: no lockfile, registry lookup
      .mockResolvedValueOnce(jsonResponse({ 'dist-tags': { latest: '4.17.15' }, versions: { '4.17.15': {} } }))
      // queryOsvBatch
      .mockResolvedValueOnce(jsonResponse({ results: [{ vulns: [{ id: 'GHSA-p6mc-m468-83gw' }] }] }))
      // fetchVulnDetails
      .mockResolvedValueOnce(jsonResponse(LODASH_VULN));
    global.fetch = mockFetch as unknown as typeof fetch;

    const findings = await scanDependencyCves({ dependencies: { lodash: '^4.17.0' } }, null);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('dependency-known-vulnerability-medium');
    expect(findings[0].description).toContain('GHSA-p6mc-m468-83gw');
    expect(findings[0].description).toContain('fixed 4.17.21');
    expect(findings[0].description).toContain('https://github.com/advisories/GHSA-p6mc-m468-83gw');
    expect(findings[0].fixRecommendation).toContain('4.17.21');
    // No lockfile was shipped, so the version came from resolving the
    // manifest's semver range - the finding must say so, not imply proof.
    expect(findings[0].description).toContain('manifest-inferred');
    expect(findings[0].dependencyResolution).toBe('manifest-range');
  });

  it('marks a dependency vulnerability as lockfile-confirmed when a real lockfile resolved the version', async () => {
    const mockFetch = vi.fn()
      // queryOsvBatch (resolveDependencies needs no fetch: the lockfile has the version)
      .mockResolvedValueOnce(jsonResponse({ results: [{ vulns: [{ id: 'GHSA-p6mc-m468-83gw' }] }] }))
      // fetchVulnDetails
      .mockResolvedValueOnce(jsonResponse(LODASH_VULN));
    global.fetch = mockFetch as unknown as typeof fetch;

    const findings = await scanDependencyCves(
      { dependencies: { lodash: '^4.17.0' } },
      { packages: { 'node_modules/lodash': { version: '4.17.15' } } }
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].description).toContain('lockfile-confirmed');
    expect(findings[0].description).not.toContain('manifest-inferred');
    expect(findings[0].dependencyResolution).toBe('lockfile');
  });

  it('does not report a vulnerability whose fixed range excludes the resolved version', async () => {
    const mockFetch = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ 'dist-tags': { latest: '4.17.21' }, versions: { '4.17.21': {} } }))
      .mockResolvedValueOnce(jsonResponse({ results: [{ vulns: [{ id: 'GHSA-p6mc-m468-83gw' }] }] }))
      .mockResolvedValueOnce(jsonResponse(LODASH_VULN));
    global.fetch = mockFetch as unknown as typeof fetch;

    const findings = await scanDependencyCves({ dependencies: { lodash: '^4.17.0' } }, null);
    expect(findings).toEqual([]);
  });

  it('aggregates advisories with no matchable range into one low-severity unresolved finding', async () => {
    const unrangedVuln = { ...LODASH_VULN, affected: [{ package: { ecosystem: 'npm', name: 'lodash' } }] };
    const mockFetch = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ 'dist-tags': { latest: '4.17.15' }, versions: { '4.17.15': {} } }))
      .mockResolvedValueOnce(jsonResponse({ results: [{ vulns: [{ id: 'GHSA-p6mc-m468-83gw' }] }] }))
      .mockResolvedValueOnce(jsonResponse(unrangedVuln));
    global.fetch = mockFetch as unknown as typeof fetch;

    const findings = await scanDependencyCves({ dependencies: { lodash: '^4.17.0' } }, null);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('dependency-known-vulnerability-unresolved');
    expect(findings[0].severity).toBe('LOW');
  });

  it('returns no findings for a package with no dependencies', async () => {
    expect(await scanDependencyCves({}, null)).toEqual([]);
  });

  it('surfaces an incomplete-lookup finding when the batch query fails, instead of reading as clean', async () => {
    const mockFetch = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ 'dist-tags': { latest: '4.17.15' }, versions: { '4.17.15': {} } }))
      .mockResolvedValue(jsonResponse({}, 500));
    global.fetch = mockFetch as unknown as typeof fetch;

    const findings = await scanDependencyCves({ dependencies: { lodash: '^4.17.0' } }, null);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('dependency-osv-lookup-incomplete');
    expect(findings[0].severity).toBe('INFO');
    expect(findings[0].description).toContain('lodash');
  }, 15000);

  it('surfaces an incomplete-lookup finding when a matched advisory fails to hydrate', async () => {
    const mockFetch = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ 'dist-tags': { latest: '4.17.15' }, versions: { '4.17.15': {} } }))
      .mockResolvedValueOnce(jsonResponse({ results: [{ vulns: [{ id: 'GHSA-p6mc-m468-83gw' }] }] }))
      .mockResolvedValue(jsonResponse({}, 500));
    global.fetch = mockFetch as unknown as typeof fetch;

    const findings = await scanDependencyCves({ dependencies: { lodash: '^4.17.0' } }, null);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('dependency-osv-lookup-incomplete');
    expect(findings[0].description).toContain('GHSA-p6mc-m468-83gw');
  }, 15000);
});
