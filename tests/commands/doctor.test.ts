import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { runDoctor } from '../../src/commands/doctor.js';
import { fetchWithTimeout } from '../../src/utils/fetch-with-timeout.js';
import { logger } from '../../src/utils/logger.js';

vi.mock('../../src/config/detector.js', () => ({ detectTools: vi.fn().mockResolvedValue([]) }));
vi.mock('../../src/utils/fetch-with-timeout.js', () => ({ fetchWithTimeout: vi.fn() }));
vi.mock('../../src/utils/logger.js', () => ({
  logger: { brand: vi.fn(), divider: vi.fn(), log: vi.fn(), detail: vi.fn(), pass: vi.fn(), error: vi.fn() },
}));

const res = (ok: boolean, status: number, statusText: string, body: object = {}) => ({
  ok, status, statusText, headers: new Headers(), json: async () => body,
});

describe('doctor update check', () => {
  let saved: typeof process.exitCode;
  beforeEach(() => { vi.clearAllMocks(); saved = process.exitCode; });
  afterEach(() => { process.exitCode = saved; });

  const fetchAs = (npm: () => unknown) => vi.mocked(fetchWithTimeout).mockImplementation((async (url: string) =>
    url.includes('npmjs.org') ? npm() : res(true, 200, 'OK')) as any);

  it('says why when the registry is unreachable', async () => {
    fetchAs(() => { throw new Error('getaddrinfo ENOTFOUND registry.npmjs.org'); });
    await runDoctor();
    expect(logger.detail).toHaveBeenCalledWith(expect.stringContaining('npm registry unreachable: getaddrinfo ENOTFOUND'));
  });

  it('says why when the registry answers with an error status', async () => {
    fetchAs(() => res(false, 503, 'Service Unavailable'));
    await runDoctor();
    expect(logger.detail).toHaveBeenCalledWith(expect.stringContaining('npm registry returned 503: Service Unavailable'));
  });

  it('prints no failure detail when the registry answers', async () => {
    fetchAs(() => res(true, 200, 'OK', { version: '9.9.9' }));
    await runDoctor();
    expect(logger.detail).not.toHaveBeenCalledWith(expect.stringContaining('npm registry'));
  });
});
