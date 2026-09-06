import { describe, it, expect } from 'vitest';
import { collectRankedFindings } from '../../scripts/findings-ranked.mjs';

function pkgResult(overrides = {}) {
  return {
    package: 'some-pkg',
    ecosystem: 'npm',
    weeklyDownloads: 1000,
    bounty: { vendor: 'Acme', program: 'HackerOne', payout: '$1000' },
    metadata: { version: '1.0.0' },
    findings: [],
    ...overrides,
  };
}

describe('findings-ranked: collectRankedFindings', () => {
  it('excludes a heuristic:true finding even if its severity is HIGH or CRITICAL', () => {
    const results = [pkgResult({
      findings: [{ id: 'tool-name-shadow', severity: 'CRITICAL', heuristic: true, description: 'heuristic hit' }],
    })];
    expect(collectRankedFindings(results)).toEqual([]);
  });

  it('keeps a non-heuristic HIGH/CRITICAL finding', () => {
    const results = [pkgResult({
      findings: [{ id: 'exposed-secret', severity: 'CRITICAL', description: 'real secret' }],
    })];
    const rows = collectRankedFindings(results);
    expect(rows).toHaveLength(1);
    expect(rows[0].severity).toBe('CRITICAL');
  });

  it('drops MEDIUM/LOW/INFO findings regardless of the heuristic flag', () => {
    const results = [pkgResult({
      findings: [
        { id: 'high-entropy-value', severity: 'MEDIUM', description: 'medium hit' },
        { id: 'network-egress-unknown', severity: 'INFO', heuristic: true, description: 'downgraded hit' },
      ],
    })];
    expect(collectRankedFindings(results)).toEqual([]);
  });

  it('surfaces dependencyResolution as its own column value, not buried in truncated text', () => {
    const longVersionDescription =
      "HIGH vulnerability in dependency 'undici@5.29.0' (manifest-inferred, verify the real installed " +
      "version before reporting): GHSA-2mjp-6q6p-2qxm (affected >=5.0.0 <5.29.1, fixed 5.29.1) - some summary.";
    const results = [pkgResult({
      findings: [{
        id: 'dependency-known-vulnerability-high',
        severity: 'HIGH',
        description: longVersionDescription,
        dependencyResolution: 'manifest-range',
      }],
    })];
    const rows = collectRankedFindings(results);
    expect(rows).toHaveLength(1);
    expect(rows[0].dependencyResolution).toBe('manifest-range');
    // The shared one-sentence truncation cuts at the first '.', which lands
    // inside the version number - proving the column can't be reconstructed
    // from the truncated description text alone.
    expect(rows[0].description).not.toContain('manifest-inferred');
  });

  it('reports "n/a" for dependencyResolution on findings that are not dependency-CVE hits', () => {
    const results = [pkgResult({
      findings: [{ id: 'exposed-secret', severity: 'CRITICAL', description: 'real secret' }],
    })];
    const rows = collectRankedFindings(results);
    expect(rows[0].dependencyResolution).toBe('n/a');
  });

  it('skips unsupported (PyPI) results entirely', () => {
    const results = [{ package: 'pypi-pkg', unsupported: true, findings: [{ id: 'x', severity: 'CRITICAL', description: 'x' }] }];
    expect(collectRankedFindings(results)).toEqual([]);
  });
});
