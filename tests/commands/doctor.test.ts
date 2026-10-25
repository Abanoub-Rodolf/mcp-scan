import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { runDoctor } from '../../src/commands/doctor.js';
import { fetchWithTimeout } from '../../src/utils/fetch-with-timeout.js';
import { logger } from '../../src/utils/logger.js';
import { detectTools } from '../../src/config/detector.js';
import fs from 'fs';
import os from 'os';
import path from 'path';

vi.mock('../../src/config/detector.js', () => ({ detectTools: vi.fn().mockResolvedValue([]) }));
vi.mock('../../src/utils/fetch-with-timeout.js', () => ({ fetchWithTimeout: vi.fn() }));

const res = (ok: boolean, status: number, statusText: string, body: object = {}) => ({
  ok, status, statusText, headers: new Headers(), json: async () => body,
});

describe('doctor update check', () => {
  // the real logger, not a mock: a non-verbose run must still print why a check failed
  let saved: typeof process.exitCode;
  let printed: () => string;
  beforeEach(() => {
    vi.clearAllMocks();
    saved = process.exitCode;
    logger.isSilent = false;
    logger.isVerbose = false;
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});
    printed = () => log.mock.calls.map(c => c.join(' ')).join('\n');
  });
  afterEach(() => { process.exitCode = saved; vi.restoreAllMocks(); });

  const fetchAs = (npm: () => unknown) => vi.mocked(fetchWithTimeout).mockImplementation((async (url: string) =>
    url.includes('npmjs.org') ? npm() : res(true, 200, 'OK')) as any);

  it('says why when the registry is unreachable', async () => {
    fetchAs(() => { throw new Error('getaddrinfo ENOTFOUND registry.npmjs.org'); });
    await runDoctor();
    expect(printed()).toContain('npm registry unreachable: getaddrinfo ENOTFOUND');
  });

  it('says why when the registry answers with an error status', async () => {
    fetchAs(() => res(false, 503, 'Service Unavailable'));
    await runDoctor();
    expect(printed()).toContain('npm registry returned 503: Service Unavailable');
  });

  it('prints no failure detail when the registry answers', async () => {
    fetchAs(() => res(true, 200, 'OK', { version: '9.9.9' }));
    await runDoctor();
    expect(printed()).not.toContain('npm registry');
  });

  // A bare launcher name is trusted to be on PATH; a path to one still has to exist.
  it.each([
    ['NPX.CMD', '✓ Server executables'],
    [path.join(os.tmpdir(), 'mcp-scan-missing', 'npm.cmd'), '1 servers reference executables'],
  ])('checks executables for %s', async (command, want) => {
    fetchAs(() => res(true, 200, 'OK', { version: '9.9.9' }));
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-doctor-'));
    const cfg = path.join(dir, 'mcp.json');
    fs.writeFileSync(cfg, JSON.stringify({ mcpServers: { s: { command, args: ['-y', 'pkg'] } } }));
    vi.mocked(detectTools).mockResolvedValueOnce([{ name: 'cursor', configPath: cfg, exists: true }] as any);
    try {
      await runDoctor();
      expect(printed()).toContain(want);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
