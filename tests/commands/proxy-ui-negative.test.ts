import { describe, it, expect, vi, afterEach } from 'vitest';

vi.mock('../../src/utils/dashboard-ui.js', () => ({
  get createDashboard(): never {
    throw new Error('unexpected token in dashboard-ui.js');
  }
}));

describe('runProxy --ui with an unrelated import failure', () => {
  afterEach(() => {
    process.exitCode = undefined;
    vi.restoreAllMocks();
  });

  it('surfaces the real error instead of the blessed install hint', async () => {
    const { runProxy } = await import('../../src/commands/proxy.js');
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await expect(runProxy({ command: 'node', args: '-v', ui: true })).resolves.toBeUndefined();

    expect(errSpy).toHaveBeenCalledWith('unexpected token in dashboard-ui.js');
    expect(errSpy).not.toHaveBeenCalledWith(expect.stringContaining('npm i -g mcp-scan'));
    expect(process.exitCode).toBe(1);
  });
});
