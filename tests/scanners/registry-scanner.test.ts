import { describe, it, expect, vi, beforeEach } from 'vitest';
import { scanRegistry } from '../../src/scanners/registry-scanner.js';

const mockFetch = vi.fn();
global.fetch = mockFetch;

const createMockFetchResponse = (ok: boolean, json: any) => ({
  ok,
  status: ok ? 200 : 404,
  json: vi.fn().mockResolvedValue(json),
});

vi.mock('../../src/utils/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), detail: vi.fn(), log: vi.fn(), brand: vi.fn(), isVerbose: false },
}));

describe('Registry Scanner', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it('should flag known malicious packages', async () => {
    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'postmark-mcp']
    }, true);
    expect(findings.some(f => f.id === 'known-malicious')).toBe(true);
  });

  it('should identify official servers', async () => {
    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-sqlite']
    }, true);
    expect(findings.some(f => f.id === 'official-server')).toBe(true);
  });

  it('should identify trusted community servers', async () => {
    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'slack-mcp']
    }, true);
    expect(findings.some(f => f.id === 'trusted-community-server')).toBe(true);
  });

  it('should flag unverified sources when offline (no network call)', async () => {
    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'offline-random-pkg']
    }, true);
    expect(mockFetch).not.toHaveBeenCalled();
    expect(findings.some(f => f.id === 'unverified-source' && f.severity === 'MEDIUM')).toBe(true);
  });

  it('should flag scoped unverified sources at LOW when offline', async () => {
    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', '@random-scope/offline-scoped-pkg']
    }, true);
    expect(findings.some(f => f.id === 'unverified-source' && f.severity === 'LOW')).toBe(true);
  });

  it('emits provenance-verified and skips unverified-source when the registry reports a provenance attestation', async () => {
    mockFetch.mockResolvedValueOnce(createMockFetchResponse(true, {
      version: '2.0.10',
      dist: {
        attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } },
        signatures: [{ keyid: 'SHA256:abc', sig: 'deadbeef' }],
      },
    }));

    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'has-provenance-pkg']
    }, false);

    expect(mockFetch).toHaveBeenCalledWith(
      'https://registry.npmjs.org/has-provenance-pkg/latest',
      expect.anything()
    );
    expect(findings.some(f => f.id === 'provenance-verified' && f.severity === 'INFO')).toBe(true);
    expect(findings.some(f => f.id === 'unverified-source')).toBe(false);
    expect(findings.find(f => f.id === 'provenance-verified')?.description).toContain('slsa.dev/provenance/v1');
  });

  it('resolves a pinned version instead of latest when the spec is pinned', async () => {
    mockFetch.mockResolvedValueOnce(createMockFetchResponse(true, {
      version: '1.2.3',
      dist: { attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } },
    }));

    await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'pinned-provenance-pkg@1.2.3']
    }, false);

    expect(mockFetch).toHaveBeenCalledWith(
      'https://registry.npmjs.org/pinned-provenance-pkg/1.2.3',
      expect.anything()
    );
  });

  it('falls back to unverified-source when no attestation is present', async () => {
    mockFetch.mockResolvedValueOnce(createMockFetchResponse(true, {
      version: '3.0.0',
      dist: {},
    }));

    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'no-provenance-pkg']
    }, false);

    expect(findings.some(f => f.id === 'unverified-source' && f.severity === 'MEDIUM')).toBe(true);
    expect(findings.some(f => f.id === 'provenance-verified')).toBe(false);
  });

  it('falls back to unverified-source when the registry lookup fails', async () => {
    mockFetch.mockRejectedValueOnce(new Error('network down'));

    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'lookup-fails-pkg']
    }, false);

    expect(findings.some(f => f.id === 'unverified-source' && f.severity === 'MEDIUM')).toBe(true);
  });

  it('falls back to unverified-source when the registry returns a non-ok response', async () => {
    mockFetch.mockResolvedValueOnce(createMockFetchResponse(false, {}));

    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'not-found-pkg']
    }, false);

    expect(findings.some(f => f.id === 'unverified-source' && f.severity === 'MEDIUM')).toBe(true);
  });

  it('mentions npm provenance as the publisher-side fix', async () => {
    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'fix-rec-pkg']
    }, true);
    const finding = findings.find(f => f.id === 'unverified-source');
    expect(finding?.fixRecommendation).toContain('--provenance');
  });

  it('does not fall through to latest provenance when a range spec resolves to an older, unattested version', async () => {
    mockFetch
      .mockResolvedValueOnce(createMockFetchResponse(true, {
        'dist-tags': { latest: '2.0.0' },
        versions: { '1.0.0': {}, '1.5.0': {}, '2.0.0': {} },
      }))
      .mockResolvedValueOnce(createMockFetchResponse(true, {
        version: '1.5.0',
        dist: {},
      }));

    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'range-spec-pkg@^1.0.0']
    }, false);

    expect(mockFetch).toHaveBeenNthCalledWith(1, 'https://registry.npmjs.org/range-spec-pkg', expect.anything());
    expect(mockFetch).toHaveBeenNthCalledWith(2, 'https://registry.npmjs.org/range-spec-pkg/1.5.0', expect.anything());
    expect(findings.some(f => f.id === 'provenance-verified')).toBe(false);
    expect(findings.some(f => f.id === 'unverified-source')).toBe(true);
  });

  it('resolves a dist-tag spec through dist-tags rather than defaulting to latest', async () => {
    mockFetch
      .mockResolvedValueOnce(createMockFetchResponse(true, {
        'dist-tags': { latest: '2.0.0', beta: '3.0.0-beta.1' },
        versions: { '2.0.0': {}, '3.0.0-beta.1': {} },
      }))
      .mockResolvedValueOnce(createMockFetchResponse(true, {
        version: '3.0.0-beta.1',
        dist: { attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } },
      }));

    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'tag-spec-pkg@beta']
    }, false);

    expect(mockFetch).toHaveBeenNthCalledWith(2, 'https://registry.npmjs.org/tag-spec-pkg/3.0.0-beta.1', expect.anything());
    expect(findings.some(f => f.id === 'provenance-verified')).toBe(true);
  });

  it('falls back to unverified-source when the version spec cannot be resolved at all', async () => {
    mockFetch.mockResolvedValueOnce(createMockFetchResponse(true, {
      'dist-tags': { latest: '2.0.0' },
      versions: { '2.0.0': {} },
    }));

    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'unresolvable-spec-pkg@nonexistent-tag']
    }, false);

    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(findings.some(f => f.id === 'unverified-source')).toBe(true);
    expect(findings.some(f => f.id === 'provenance-verified')).toBe(false);
  });

  it('treats a non-string predicateType (object) as no provenance', async () => {
    mockFetch.mockResolvedValueOnce(createMockFetchResponse(true, {
      version: '1.0.0',
      dist: { attestations: { provenance: { predicateType: {} } } },
    }));

    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'weird-predicate-object-pkg']
    }, false);

    expect(findings.some(f => f.id === 'provenance-verified')).toBe(false);
    expect(findings.some(f => f.id === 'unverified-source')).toBe(true);
  });

  it('treats a non-string predicateType (array) as no provenance', async () => {
    mockFetch.mockResolvedValueOnce(createMockFetchResponse(true, {
      version: '1.0.0',
      dist: { attestations: { provenance: { predicateType: [] } } },
    }));

    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'weird-predicate-array-pkg']
    }, false);

    expect(findings.some(f => f.id === 'provenance-verified')).toBe(false);
    expect(findings.some(f => f.id === 'unverified-source')).toBe(true);
  });

  it('retries after a rejected registry lookup instead of caching the failure', async () => {
    mockFetch
      .mockRejectedValueOnce(new Error('transient network blip'))
      .mockResolvedValueOnce(createMockFetchResponse(true, {
        version: '4.0.0',
        dist: { attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } },
      }));

    const server = {
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'cache-retry-pkg']
    };

    const first = await scanRegistry(server, false);
    expect(first.some(f => f.id === 'unverified-source')).toBe(true);

    const second = await scanRegistry(server, false);
    expect(second.some(f => f.id === 'provenance-verified')).toBe(true);
    expect(second.some(f => f.id === 'unverified-source')).toBe(false);
  });
});
