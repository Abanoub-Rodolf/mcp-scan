import { describe, it, expect, vi, beforeEach } from 'vitest';
import { scanSupplyChain } from '../../src/scanners/supply-chain-scanner.js';
import { ResolvedServer } from '../../src/types/config.js';

// Mocking global fetch
const mockFetch = vi.fn();
global.fetch = mockFetch;

const createMockFetchResponse = (ok: boolean, json: any, status: number = ok ? 200 : 404) => ({
  ok,
  status,
  json: vi.fn().mockResolvedValue(json),
  text: vi.fn().mockResolvedValue(JSON.stringify(json)),
  headers: new Headers(),
  statusText: ok ? 'OK' : 'Not Found',
});

describe('Supply Chain Scanner', () => {
  const mockServer = (packageName: string, command: string = 'npx'): ResolvedServer => ({
    name: `${packageName}-server`,
    toolName: 'mock-tool',
    configPath: `/path/to/config.json`,
    command: command,
    args: [packageName],
    schema: {},
    description: '',
    env: {},
    disabled: false,
  });

  beforeEach(() => {
    mockFetch.mockClear();
    vi.clearAllMocks();
  });

  it('should give high trust score to popular and active repos', async () => {
    mockFetch.mockImplementation(async (url) => {
      if (url.includes('registry.npmjs.org')) {
        return createMockFetchResponse(true, {
          repository: { url: 'git+https://github.com/trusted/repo.git' }
        });
      }
      if (url.includes('api.github.com/repos/trusted/repo')) {
        return createMockFetchResponse(true, {
          stargazers_count: 5000,
          forks_count: 500,
          updated_at: new Date().toISOString(),
          pushed_at: new Date().toISOString(),
          owner: { login: 'trusted' }
        });
      }
      return createMockFetchResponse(false, {});
    });

    const server = mockServer('trusted-pkg');
    const result = await scanSupplyChain(server);

    expect(result.trustScore).toBeGreaterThanOrEqual(80);
    expect(result.findings).toHaveLength(0);
  });

  it('should detect low trust for inactive or unpopular repos', async () => {
    mockFetch.mockImplementation(async (url) => {
      if (url.includes('registry.npmjs.org')) {
        return createMockFetchResponse(true, {
          repository: { url: 'git+https://github.com/ghost/abandoned.git' }
        });
      }
      if (url.includes('api.github.com/repos/ghost/abandoned')) {
        const twoYearsAgo = new Date();
        twoYearsAgo.setFullYear(twoYearsAgo.getFullYear() - 2);
        return createMockFetchResponse(true, {
          stargazers_count: 0,
          forks_count: 0,
          updated_at: twoYearsAgo.toISOString(),
          pushed_at: twoYearsAgo.toISOString(),
          owner: { login: 'ghost' }
        });
      }
      return createMockFetchResponse(false, {});
    });

    const server = mockServer('abandoned-pkg');
    const result = await scanSupplyChain(server);

    expect(result.trustScore).toBeLessThan(40);
    expect(result.findings.some(f => f.id === 'supply-chain-low-trust')).toBe(true);
  });

  it('should flag packages with no repository URL', async () => {
    mockFetch.mockResolvedValue(createMockFetchResponse(true, { repository: null }));

    const server = mockServer('no-repo-pkg');
    const result = await scanSupplyChain(server);

    expect(result.trustScore).toBe(20);
    expect(result.findings.some(f => f.id === 'supply-chain-low-trust')).toBe(true);
    expect(result.findings[0].description).toContain('no public repository URL');
  });

  it('should handle registry fetch errors gracefully', async () => {
    mockFetch.mockResolvedValue(createMockFetchResponse(false, {}));

    const server = mockServer('error-pkg');
    const result = await scanSupplyChain(server);

    expect(result.trustScore).toBe(30);
    expect(result.findings).toHaveLength(0); // Error during fetch doesn't necessarily mean a finding
  });

  // Regression: a package with a real license on npm was reported as
  // "no license specified" (HIGH) whenever the registry fetch failed and
  // the code fell back to the small offline CVE snapshot, which doesn't
  // have this package. license-scanner now needs licenseVerified to tell
  // "we checked and it's unlicensed" apart from "we couldn't check".
  it('should mark license as verified on a successful live registry lookup', async () => {
    mockFetch.mockImplementation(async (url) => {
      if (url.includes('registry.npmjs.org')) {
        return createMockFetchResponse(true, { license: 'MIT', repository: null });
      }
      return createMockFetchResponse(false, {});
    });

    const server = mockServer('licensed-pkg');
    const result = await scanSupplyChain(server);

    expect(result.metadata?.license).toBe('MIT');
    expect(result.metadata?.licenseVerified).toBe(true);
  });

  it('should NOT mark license as verified when the registry fetch fails and it falls back offline', async () => {
    mockFetch.mockResolvedValue(createMockFetchResponse(false, {}));

    const server = mockServer('unreachable-pkg');
    const result = await scanSupplyChain(server);

    expect(result.metadata?.licenseVerified).toBeFalsy();
  });

  it('should NOT mark license as verified when run with offline: true', async () => {
    const server = mockServer('@modelcontextprotocol/server-github');
    const result = await scanSupplyChain(server, true);

    expect(mockFetch).not.toHaveBeenCalled();
    expect(result.metadata?.licenseVerified).toBeFalsy();
  });

  it('should return perfect score for local servers (no package name)', async () => {
    const server = { ...mockServer('local'), command: '/usr/local/bin/server' };
    server.args = []; // No package name arg
    const result = await scanSupplyChain(server);

    expect(result.trustScore).toBe(100);
    expect(result.findings).toHaveLength(0);
  });
});
