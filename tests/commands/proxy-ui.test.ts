import { describe, it, expect, vi, afterEach } from 'vitest';

// runProxy used to throw a plain Error here, which escapes commander's
// .action() with no handler (index.ts uses program.parse(), not
// parseAsync) and crashes with an unhandled-rejection stack trace instead
// of the same clean hint dashboard.ts prints for the identical failure.
vi.mock('../../src/utils/dashboard-ui.js', () => ({
  get createDashboard(): never {
    const err = new Error("Cannot find package 'blessed'") as Error & { code: string };
    err.code = 'ERR_MODULE_NOT_FOUND';
    throw err;
  }
}));

describe('runProxy --ui without blessed', () => {
  afterEach(() => {
    process.exitCode = undefined;
    vi.restoreAllMocks();
  });

  it('prints an install hint and exits 1 instead of throwing', async () => {
    const { runProxy } = await import('../../src/commands/proxy.js');
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await expect(runProxy({ command: 'node', args: '-v', ui: true })).resolves.toBeUndefined();

    expect(errSpy).toHaveBeenCalledWith(expect.stringContaining('npm i -g mcp-scan'));
    expect(process.exitCode).toBe(1);
  });
});
