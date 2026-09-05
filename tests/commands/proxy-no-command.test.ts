import { describe, it, expect, vi, afterEach } from 'vitest';
import { runProxy } from '../../src/commands/proxy.js';

// runProxy used to throw a plain Error for a missing --command, which
// escapes commander's bare program.parse() (no .parseAsync, no catch)
// as an uncaught stack trace instead of a clean error line + exit 1.
describe('runProxy without --command', () => {
  afterEach(() => {
    process.exitCode = undefined;
    vi.restoreAllMocks();
  });

  it('prints a clean error and exits 1 instead of throwing', async () => {
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await expect(runProxy({})).resolves.toBeUndefined();

    expect(errSpy).toHaveBeenCalledWith('No command specified for proxy. Use --command <cmd>.');
    expect(process.exitCode).toBe(1);
  });
});
