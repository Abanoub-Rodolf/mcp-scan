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
});
