import { describe, it, expect, vi, afterEach } from 'vitest';

// Simulate the module failing to import via a throwing getter rather than
// a throwing factory: this vitest version swallows a factory that throws
// synchronously and reports its own "module mocking" error instead of the
// one under test.
vi.mock('../../src/utils/dashboard-ui.js', () => ({
  get createDashboard(): never {
    const err = new Error("Cannot find package 'blessed' imported from src/utils/dashboard-ui.ts") as Error & { code: string };
    err.code = 'ERR_MODULE_NOT_FOUND';
    throw err;
  }
}));

describe('runDashboard', () => {
  afterEach(() => {
    process.exitCode = undefined;
    vi.restoreAllMocks();
  });

  it('prints an install hint and exits 1 when blessed is not installed', async () => {
    const { runDashboard } = await import('../../src/commands/dashboard.js');
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await runDashboard();

    expect(errSpy).toHaveBeenCalledWith(expect.stringContaining('npm i -g mcp-scan'));
    expect(process.exitCode).toBe(1);
  });
});
