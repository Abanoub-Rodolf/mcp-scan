import { describe, it, expect, vi, afterEach } from 'vitest';

// A missing 'blessed' module isn't the only way this dynamic import can
// fail. Anything else (a syntax error in dashboard-ui.ts, a broken
// transitive dep) must surface as-is, not get swallowed into the
// "go install blessed" hint.
vi.mock('../../src/utils/dashboard-ui.js', () => ({
  get createDashboard(): never {
    throw new Error('unexpected token in dashboard-ui.js');
  }
}));

describe('runDashboard with an unrelated import failure', () => {
  afterEach(() => {
    process.exitCode = undefined;
    vi.restoreAllMocks();
  });

  it('surfaces the real error instead of the blessed install hint', async () => {
    const { runDashboard } = await import('../../src/commands/dashboard.js');
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await runDashboard();

    expect(errSpy).toHaveBeenCalledWith('unexpected token in dashboard-ui.js');
    expect(errSpy).not.toHaveBeenCalledWith(expect.stringContaining('npm i -g mcp-scan'));
    expect(process.exitCode).toBe(1);
  });
});
