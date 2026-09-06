import { describe, it, expect, vi, afterEach } from 'vitest';
import { resolveNamedTargets } from '../../scripts/top-mcp-packages.mjs';

// Reproduces the run2 ecosystem-scan bug: named priority-vendor targets
// (Vercel, Cloudflare, etc.) were dropped whenever npm's downloads endpoint
// had nothing for them, because withDownloads() filters out any entry with
// `downloads === null`. resolveNamedTargets bypasses that filter and only
// drops a named target when the package genuinely doesn't exist.
const jsonResponse = (body: unknown, ok = true) => ({
  ok,
  json: vi.fn().mockResolvedValue(body),
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('top-mcp-packages: resolveNamedTargets', () => {
  it('keeps a named target with real download data', async () => {
    global.fetch = vi.fn().mockResolvedValue(jsonResponse({ downloads: 65139 })) as unknown as typeof fetch;
    const results = await resolveNamedTargets(['@vercel/mcp-adapter']);
    expect(results).toEqual([{ name: '@vercel/mcp-adapter', weeklyDownloads: 65139 }]);
  });

  it('keeps a named target with no download data as long as the package exists', async () => {
    const mockFetch = vi.fn()
      // downloads point lookup: nothing returned
      .mockResolvedValueOnce(jsonResponse(null, false))
      // registry metadata: package exists
      .mockResolvedValueOnce(jsonResponse({ name: '@azure/mcp', versions: {} }));
    global.fetch = mockFetch as unknown as typeof fetch;

    const results = await resolveNamedTargets(['@azure/mcp']);
    expect(results).toEqual([{ name: '@azure/mcp', weeklyDownloads: null }]);
  });

  it('records a skip reason only when the package does not exist on the registry either', async () => {
    const mockFetch = vi.fn()
      .mockResolvedValueOnce(jsonResponse(null, false))
      .mockResolvedValueOnce(jsonResponse(null, false));
    global.fetch = mockFetch as unknown as typeof fetch;

    const results = await resolveNamedTargets(['totally-made-up-package']);
    expect(results).toEqual([{
      name: 'totally-made-up-package',
      weeklyDownloads: null,
      skipped: 'package not found on npm registry',
    }]);
  });

  it('resolves each named target independently in one list', async () => {
    const mockFetch = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ downloads: 100 })) // pkg-a: has downloads
      .mockResolvedValueOnce(jsonResponse(null, false)) // pkg-b: no downloads...
      .mockResolvedValueOnce(jsonResponse({ name: 'pkg-b' })); // ...but exists
    global.fetch = mockFetch as unknown as typeof fetch;

    const results = await resolveNamedTargets(['pkg-a', 'pkg-b']);
    expect(results).toEqual([
      { name: 'pkg-a', weeklyDownloads: 100 },
      { name: 'pkg-b', weeklyDownloads: null },
    ]);
  });
});
