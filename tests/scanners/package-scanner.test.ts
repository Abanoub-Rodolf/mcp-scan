import { describe, it, expect, vi } from 'vitest';
import { scanPackageDeep, validatePackageName } from '../../src/scanners/package-scanner.js';
import { ResolvedServer } from '../../src/types/config.js';
import { FindingId } from '../../src/types/scan-result.js';
import { logger } from '../../src/utils/logger.js';

// Mocking global fetch for OSV.dev and npm registry tests
const mockFetch = vi.fn();
global.fetch = mockFetch;

// Helper to create mock fetch response
const createMockFetchResponse = (ok: boolean, json: any, status: number = ok ? 200 : 404) => ({
  ok,
  status,
  json: vi.fn().mockResolvedValue(json),
  text: vi.fn().mockResolvedValue(JSON.stringify(json)),
  headers: new Headers(),
  statusText: ok ? 'OK' : 'Not Found',
});

// Mock vuln-vects for CVSS parsing
vi.mock('vuln-vects', () => ({
  parseCvssVector: vi.fn((score: string) => {
    if (score === 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H') return { baseScore: 9.8 };
    if (score === 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L') return { baseScore: 7.5 };
    if (score === 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L') return { baseScore: 5.0 }; // Low severity example
    throw new Error('Invalid CVSS vector');
  }),
}));

// Mock logger to avoid console output during tests
vi.mock('../../src/utils/logger.js', () => ({
  logger: {
    warn: vi.fn(),
    info: vi.fn(),
    detail: vi.fn(),
    log: vi.fn(),
    brand: vi.fn(),
    isVerbose: true, // Set to true to allow detail logs
  },
}));

describe('Package Scanner - OSV.dev integration', () => {
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
    // Reset mocks for logger and other potential dependencies
    vi.clearAllMocks();
    // Ensure fetch is mocked for each test
    mockFetch.mockImplementation(async (url, options) => {
      if (url === 'https://api.osv.dev/v1/query') {
        const body = JSON.parse(options.body as string);
        const packageName = body.package.name;

        // affected[].ranges use OSV's real event shape: an "introduced"
        // opens the vulnerable interval, "fixed" closes it exclusively.
        // Everything below fixed is vulnerable; the fixed version and
        // above is patched.
        if (packageName === 'vulnerable-critical') {
          return createMockFetchResponse(true, {
            vulns: [{
              id: 'CVE-2023-1234',
              summary: 'A critical vulnerability',
              details: 'Details of the critical vulnerability.',
              severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
              affected: [{
                package: { ecosystem: 'npm', name: 'vulnerable-critical' },
                ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }],
              }],
            }],
          });
        } else if (packageName === 'vulnerable-high') {
          return createMockFetchResponse(true, {
            vulns: [{
              id: 'CVE-2023-5678',
              summary: 'A high vulnerability',
              details: 'Details of the high vulnerability.',
              severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L' }],
              affected: [{
                package: { ecosystem: 'npm', name: 'vulnerable-high' },
                ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.5.0' }] }],
              }],
            }],
          });
        } else if (packageName === 'mcp-remote-fixture') {
          // Mirrors the real mcp-remote case: an advisory exists, but only
          // for versions below the fix; latest resolves patched.
          return createMockFetchResponse(true, {
            vulns: [{
              id: 'GHSA-fake-remote',
              summary: 'Vulnerable before 0.8.0',
              severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
              affected: [{
                package: { ecosystem: 'npm', name: 'mcp-remote-fixture' },
                ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '0.8.0' }] }],
              }],
            }],
          });
        } else if (packageName === 'no-vulns') {
          return createMockFetchResponse(true, { vulns: [] });
        } else if (packageName === 'error-package') {
          return createMockFetchResponse(false, {}, 500);
        }
      } else if (url.startsWith('https://registry.npmjs.org/')) {
         // Mock npm registry response
         const packageName = url.split('/').pop();
         if (packageName === 'stale-package') {
            return createMockFetchResponse(true, { time: { modified: new Date(Date.now() - 7 * 30 * 24 * 60 * 60 * 1000).toISOString() } }); // Modified 7 months ago
         } else if (packageName === 'fresh-package') {
             return createMockFetchResponse(true, { time: { modified: new Date(Date.now() - 2 * 30 * 24 * 60 * 60 * 1000).toISOString() } }); // Modified 2 months ago
         } else if (packageName === 'npm-error') {
             return createMockFetchResponse(false, {}, 404);
         } else if (packageName === 'mcp-remote-fixture') {
             // Unpinned config resolves to the current patched latest.
             return createMockFetchResponse(true, { 'dist-tags': { latest: '0.8.2' }, versions: { '0.8.2': {} } });
         }
      }
      return createMockFetchResponse(false, {}, 404); // Default not found
    });
  });

  it('should return empty findings if package name cannot be extracted', async () => {
    const server = { ...mockServer('some-pkg'), command: 'some-other-command' }; // Command that doesn't extract package name
    const findings = await scanPackageDeep(server);
    expect(findings).toEqual([]);
  });

  describe('npm registry lookup', () => {
    it('should detect stale package if not updated in 6+ months', async () => {
      const server = mockServer('stale-package');
      const findings = await scanPackageDeep(server);
      expect(findings.some(f => f.id === 'stale-server')).toBe(true);
    });

    it('should not detect package as stale if updated recently', async () => {
      const server = mockServer('fresh-package');
      const findings = await scanPackageDeep(server);
      expect(findings.some(f => f.id === 'stale-server')).toBe(false);
    });

    it('should handle npm registry errors gracefully', async () => {
      const server = mockServer('npm-error');
      const findings = await scanPackageDeep(server);
      expect(findings.some(f => f.id === 'stale-server')).toBe(false); // Should not error out
    });
  });

  describe('OSV.dev integration', () => {
    it('pinned vulnerable version fires at full severity', async () => {
      // resolved version 1.0.0 falls inside the [0, 2.0.0) affected range
      const server = mockServer('vulnerable-critical@1.0.0');
      const findings = await scanPackageDeep(server);
      expect(findings.some(f => f.id === 'known-vulnerability-critical')).toBe(true);
      expect(findings.some(f => f.id === 'known-vulnerability-unresolved')).toBe(false);
    });

    it('pinned patched version does not fire', async () => {
      // resolved version 2.0.0 is at the fix boundary - patched
      const server = mockServer('vulnerable-critical@2.0.0');
      const findings = await scanPackageDeep(server);
      expect(findings.some(f => f.id === 'known-vulnerability-critical')).toBe(false);
      expect(findings.some(f => f.id === 'known-vulnerability-unresolved')).toBe(false);
    });

    it('pinned vulnerable version (high severity advisory) fires', async () => {
      const server = mockServer('vulnerable-high@1.0.0');
      const findings = await scanPackageDeep(server);
      expect(findings.some(f => f.id === 'known-vulnerability-high')).toBe(true);
    });

    it('pinned patched version (high severity advisory) does not fire', async () => {
      const server = mockServer('vulnerable-high@1.5.0');
      const findings = await scanPackageDeep(server);
      expect(findings.some(f => f.id === 'known-vulnerability-high')).toBe(false);
    });

    it('unpinned package resolving to a patched latest does not fire critical (mcp-remote case)', async () => {
      // npx <pkg> with no version pin: registry resolves dist-tags.latest
      // to 0.8.2, which is at/after the advisory's fix (0.8.0). Must not
      // fire - this is the exact false positive that was reported live.
      const server = mockServer('mcp-remote-fixture');
      const findings = await scanPackageDeep(server);
      expect(findings.some(f => f.id === 'known-vulnerability-critical')).toBe(false);
      expect(findings.some(f => f.id === 'known-vulnerability-high')).toBe(false);
    });

    it('resolution failure produces a lower-severity unresolved finding, not a critical', async () => {
      // npm registry has no entry for this name, so latestVersion can't be
      // resolved and the package is unpinned - version resolution fails.
      const server = mockServer('vulnerable-critical');
      const findings = await scanPackageDeep(server);
      expect(findings.some(f => f.id === 'known-vulnerability-critical')).toBe(false);
      expect(findings.some(f => f.id === 'known-vulnerability-high')).toBe(false);
      const unresolved = findings.find(f => f.id === 'known-vulnerability-unresolved');
      expect(unresolved).toBeDefined();
      expect(unresolved?.severity).toBe('LOW');
      expect(unresolved?.description).toContain('CVE-2023-1234');
    });

    it('should find high vulnerabilities from OSV.dev when the resolved version is affected', async () => {
      const server = mockServer('vulnerable-high@1.0.0');
      const findings = await scanPackageDeep(server);
      expect(findings.some(f => f.id === 'known-vulnerability-high')).toBe(true);
    });

    it('should handle OSV.dev API timeout gracefully', async () => {
      // The mock honors the abort signal the scanner wires up, so the
      // 5-second timeout fires under fake timers instead of sleeping for
      // real seconds. Proves the abort -> warn -> offline-fallback path.
      vi.useFakeTimers();
      try {
        mockFetch.mockImplementation(async (url: string | URL | Request, options: RequestInit = {}) => {
          if (url === 'https://api.osv.dev/v1/query') {
            return new Promise((_, reject) => {
              const signal = options.signal;
              if (!signal) {
                reject(new Error('mock fetch requires an AbortSignal'));
                return;
              }
              if (signal.aborted) {
                reject(new DOMException('The operation was aborted.', 'AbortError'));
                return;
              }
              signal.addEventListener('abort', () => reject(new DOMException('The operation was aborted.', 'AbortError')));
            });
          }
          return createMockFetchResponse(false, {}, 404);
        });

        const server = mockServer('timeout-package');
        const pending = scanPackageDeep(server);
        await vi.advanceTimersByTimeAsync(5001);
        const findings = await pending;

        expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining(`OSV.dev API request for ${'timeout-package'} failed or timed out`));
        expect(findings.some(f => f.id === 'known-vulnerability-critical' || f.id === 'known-vulnerability-high')).toBe(false);
      } finally {
        vi.useRealTimers();
      }
    });

    it('should handle OSV.dev API network errors gracefully', async () => {
      const server = mockServer('error-package');
      const findings = await scanPackageDeep(server);
      expect(findings.some(f => f.id === 'known-vulnerability-critical' || f.id === 'known-vulnerability-high')).toBe(false);
      expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('OSV.dev API request failed for error-package'));
    });

    it('should handle OSV.dev API non-ok response gracefully', async () => {
      const server = mockServer('non-ok-response'); // This will hit the default 404 in mockFetch
      const findings = await scanPackageDeep(server);
      expect(findings.some(f => f.id === 'known-vulnerability-critical' || f.id === 'known-vulnerability-high')).toBe(false);
      expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('OSV.dev API request failed for non-ok-response'));
    });

     it('should return no findings if OSV.dev returns no vulnerabilities', async () => {
      const server = mockServer('no-vulns');
      const findings = await scanPackageDeep(server);
      expect(findings.some(f => f.id === 'known-vulnerability-critical' || f.id === 'known-vulnerability-high')).toBe(false);
    });
  });
});

describe('validatePackageName', () => {
  it('accepts a plain lowercase name', () => {
    expect(validatePackageName('mcp-scan')).toEqual({ valid: true, name: 'mcp-scan' });
  });

  it('accepts a scoped name', () => {
    expect(validatePackageName('@modelcontextprotocol/server-filesystem')).toEqual({
      valid: true,
      name: '@modelcontextprotocol/server-filesystem',
    });
  });

  it('strips a pinned version before validating', () => {
    expect(validatePackageName('mcp-scan@2.0.10')).toEqual({ valid: true, name: 'mcp-scan' });
  });

  it('strips a version from a scoped spec', () => {
    expect(validatePackageName('@scope/name@1.2.3')).toEqual({ valid: true, name: '@scope/name' });
  });

  it('rejects uppercase letters', () => {
    const result = validatePackageName('MyPackage');
    expect(result.valid).toBe(false);
  });

  it('rejects a leading dot', () => {
    const result = validatePackageName('.hidden');
    expect(result.valid).toBe(false);
  });

  it('rejects spaces', () => {
    const result = validatePackageName('my package');
    expect(result.valid).toBe(false);
  });

  it('rejects a bare file path', () => {
    const result = validatePackageName('/usr/local/bin/server.js');
    expect(result.valid).toBe(false);
  });

  it('rejects a name over 214 characters', () => {
    const result = validatePackageName('a'.repeat(215));
    expect(result.valid).toBe(false);
  });

  it('rejects an empty string', () => {
    const result = validatePackageName('');
    expect(result.valid).toBe(false);
  });
});
